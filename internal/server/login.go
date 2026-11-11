package server

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"github.com/ReCasaOS/recasaos-relay/internal/devicecode"
	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/ratelimit"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

//go:embed login.html
var loginHTML string

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

const maxLoginBody = 1 << 10

type loginText struct{ Title, Label, Button, Prompt, Hint, Added, Invalid, Expired, Retry, Slow, Big string }

var loginTexts = map[string]loginText{
	"en": {"Add this device", "Code", "Add", "Enter the code shown in your box's dashboard.",
		"Only enter a code if you just started this login in the Tailscale app on this device.", "Device added: %s. You can close this page.",
		"The code is invalid or already used.", "This login request has expired. Restart the login in the Tailscale app, then generate a new code.",
		"Something went wrong. Generate a new code in your box's dashboard and try again.", "Too many attempts, try again later.", "Request too large."},
	"fr": {"Ajouter cet appareil", "Code", "Ajouter", "Saisis le code affiché dans le tableau de bord de ta box.",
		"Ne saisis un code que si tu viens de lancer cette connexion dans l'app Tailscale, sur cet appareil.", "Appareil ajouté : %s. Tu peux fermer cette page.",
		"Le code est invalide ou déjà utilisé.", "Cette demande de connexion a expiré. Relance la connexion dans l'application Tailscale, puis génère un nouveau code.",
		"Une erreur est survenue. Génère un nouveau code dans le tableau de bord de ta box et réessaie.", "Trop d'essais, réessaie plus tard.", "Requête trop volumineuse."},
}

type loginPageData struct {
	Lang, Title, Label, Button, Hint, Message string
	Form, IsError                             bool
	Marker                                    template.HTML // html/template drops comments; this one is a constant
	Host                                      string        // the relay's own name, under the logo: the person sees where they are
}

type loginHandler struct {
	cfg       Config
	deps      Deps
	limiter   *ratelimit.Limiter // per IP (IPv6: per /64)
	limiter48 *ratelimit.Limiter // per IPv6 /48, prefix48Factor times the rate
}

// render writes the page with the headers every login response carries.
func render(w http.ResponseWriter, r *http.Request, status int, form, isErr bool, msg func(loginText) string) {
	lang := "en"
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("Accept-Language"))), "fr") {
		lang = "fr"
	}
	t := loginTexts[lang]
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if err := loginTmpl.Execute(w, loginPageData{lang, t.Title, t.Label, t.Button, t.Hint, msg(t), form, isErr, "<!-- recasaos-device-login -->", r.Host}); err != nil {
		log.Printf("login page: %v", err)
	}
}

func (h *loginHandler) form(w http.ResponseWriter, r *http.Request) {
	if !headscale.ValidAuthID(r.PathValue("authID")) {
		http.NotFound(w, r)
		return
	}
	render(w, r, http.StatusOK, true, false, func(t loginText) string { return t.Prompt })
}

// approve handles POST /register/{authID}. The code is consumed before Headscale is called, so a
// double submit never registers twice; a failure after that costs the user a new code.
func (h *loginHandler) approve(w http.ResponseWriter, r *http.Request) {
	// The /64 limiter goes first, so a single /64 hammering past its own limit does not use up its /48's budget.
	for _, l := range []struct {
		lim  *ratelimit.Limiter
		bits int
	}{{h.limiter, 64}, {h.limiter48, 48}} {
		if ok, retry := l.lim.Allow(clientKey(r, h.cfg.TrustedProxyHeader, l.bits)); !ok {
			w.Header().Set("Retry-After", retryAfter(retry))
			render(w, r, http.StatusTooManyRequests, false, true, func(t loginText) string { return t.Slow })
			return
		}
	}
	id := r.PathValue("authID")
	if !headscale.ValidAuthID(id) {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBody)
	if err := r.ParseForm(); err != nil {
		var big *http.MaxBytesError
		if errors.As(err, &big) {
			render(w, r, http.StatusRequestEntityTooLarge, false, true, func(t loginText) string { return t.Big })
			return
		}
		h.bad(w, r)
		return
	}
	norm, ok := devicecode.Normalize(r.PostFormValue("code"))
	if !ok {
		h.bad(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()
	now := h.deps.Now()
	fleetID, err := h.deps.Store.TakeDeviceCode(ctx, devicecode.Hash(norm), now)
	if errors.Is(err, store.ErrNotFound) {
		h.bad(w, r)
		return
	} else if err != nil {
		log.Printf("login: take code: %v", err)
		h.fail(w, r)
		return
	}
	f, err := h.deps.Store.Fleet(ctx, fleetID)
	if err != nil {
		log.Printf("fleet %s: login: fleet: %v", fleetID, err)
		h.fail(w, r)
		return
	}
	node, err := h.deps.Headscale.RegisterNode(ctx, f.HeadscaleUser, id)
	if errors.Is(err, headscale.ErrAuthRequestNotFound) {
		render(w, r, http.StatusGone, false, true, func(t loginText) string { return t.Expired })
		return
	} else if err != nil {
		log.Printf("fleet %s: login: register: %v", fleetID, err)
		h.fail(w, r)
		return
	}
	if err := h.deps.Store.AddDevice(ctx, fleetID, node.ID, now); err != nil {
		log.Printf("fleet %s: node %s: record device: %v", fleetID, node.ID, err) // the node exists: not shown
	}
	if err := h.deps.Store.Touch(ctx, fleetID, now); err != nil {
		log.Printf("fleet %s: touch: %v", fleetID, err)
	}
	log.Printf("fleet %s: device approved, node %s", fleetID, node.ID)
	render(w, r, http.StatusOK, false, false, func(t loginText) string { return fmt.Sprintf(t.Added, node.Hostname) })
}

func (h *loginHandler) bad(w http.ResponseWriter, r *http.Request) {
	render(w, r, http.StatusBadRequest, true, true, func(t loginText) string { return t.Invalid })
}

func (h *loginHandler) fail(w http.ResponseWriter, r *http.Request) {
	render(w, r, http.StatusBadGateway, false, true, func(t loginText) string { return t.Retry })
}
