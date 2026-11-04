// Package admin is a small operator page under /admin: the fleets and nodes of this relay, and the
// two deletions an operator may need. It is mounted only when ADMIN_TOKEN is set.
package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/ratelimit"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// MinTokenLen: the token is the only protection of the page.
const MinTokenLen = 24

const opTimeout = 20 * time.Second

// requestsPerHour bounds the requests carrying credentials, per client address: a token guess costs one.
const requestsPerHour = 120

//go:embed page.html
var pageHTML string

var page = template.Must(template.New("page").Funcs(template.FuncMap{
	"ago": func(t, now time.Time) string {
		switch d := now.Sub(t); {
		case d < time.Minute:
			return "now"
		case d < time.Hour:
			return strconv.Itoa(int(d.Minutes())) + " min ago"
		case d < 48*time.Hour:
			return strconv.Itoa(int(d.Hours())) + " h ago"
		default:
			return strconv.Itoa(int(d.Hours()/24)) + " d ago"
		}
	},
}).Parse(pageHTML))

// Config is what the page shows next to the live numbers.
type Config struct {
	Token         string
	NodesPerFleet int
	MaxFleets     int
	// ClientHeader names the header in which `front` puts the client address (X-Client-IP); empty:
	// the TCP peer.
	ClientHeader string
}

// Deps are the same collaborators the enrolment handlers use.
type Deps struct {
	Store     store.Store
	Headscale headscale.API
	Remover   *fleets.Remover
	Now       func() time.Time // default time.Now
}

type handler struct {
	cfg       Config
	deps      Deps
	tokenSum  [32]byte
	csrf      string
	nodeFetch chan struct{} // bounds the Headscale calls of one page load
	limiter   *ratelimit.Limiter
}

// New returns the admin handler. The token must be at least MinTokenLen long.
func New(cfg Config, deps Deps) (http.Handler, error) {
	if len(cfg.Token) < MinTokenLen {
		return nil, errors.New("ADMIN_TOKEN must be at least 24 characters")
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	sum := sha256.Sum256([]byte("csrf:" + cfg.Token))
	h := &handler{cfg: cfg, deps: deps, tokenSum: sha256.Sum256([]byte(cfg.Token)),
		csrf: hex.EncodeToString(sum[:]), nodeFetch: make(chan struct{}, 8),
		limiter: ratelimit.New(requestsPerHour, deps.Now)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/{$}", h.index)
	mux.HandleFunc("POST /admin/fleets/{id}/delete", h.deleteFleet)
	mux.HandleFunc("POST /admin/fleets/{id}/nodes/{node}/remove", h.removeNode)
	return h.guard(mux), nil
}

// guard asks for the token (HTTP Basic: any user name, the token as password), and for the CSRF
// field on POSTs: the browser resends Basic credentials to any site that makes it post here.
func (h *handler) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		if ok, _ := h.limiter.Allow(h.client(r)); !ok {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		_, pass, ok := r.BasicAuth()
		got := sha256.Sum256([]byte(pass))
		if !ok || subtle.ConstantTimeCompare(got[:], h.tokenSum[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="relay admin", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(h.csrf)) != 1 {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// client is the address the rate limit counts: the one `front` set, else the TCP peer.
func (h *handler) client(r *http.Request) string {
	if v := r.Header.Get(h.cfg.ClientHeader); h.cfg.ClientHeader != "" && v != "" {
		return v
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type fleetView struct {
	ID                  string
	Created, LastOnline time.Time
	Nodes               []headscale.Node
	Online              int
	Err                 bool // its nodes could not be listed
}

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), opTimeout)
	defer cancel()
	all, err := h.deps.Store.ListFleets(ctx)
	if err != nil {
		log.Printf("admin: list fleets: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].LastOnline.After(all[j].LastOnline) })
	views := make([]fleetView, len(all))
	var wg sync.WaitGroup
	for i, f := range all {
		views[i] = fleetView{ID: f.ID, Created: f.CreatedAt, LastOnline: f.LastOnline}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.nodeFetch <- struct{}{}
			defer func() { <-h.nodeFetch }()
			ns, err := h.deps.Headscale.ListNodes(ctx, f.HeadscaleUser)
			if err != nil {
				log.Printf("admin: fleet %s: list nodes: %v", f.ID, err)
				views[i].Err = true
				return
			}
			views[i].Nodes = ns
			for _, n := range ns {
				if n.Online {
					views[i].Online++
				}
			}
		}()
	}
	wg.Wait()
	nodes, online := 0, 0
	for _, v := range views {
		nodes += len(v.Nodes)
		online += v.Online
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, map[string]any{
		"Fleets": views, "Nodes": nodes, "Online": online, "Now": h.deps.Now(),
		"MaxFleets": h.cfg.MaxFleets, "NodesPerFleet": h.cfg.NodesPerFleet, "CSRF": h.csrf,
	}); err != nil {
		log.Printf("admin: render: %v", err)
	}
}

func (h *handler) deleteFleet(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), fleets.RemoveTimeout)
	defer cancel()
	f, err := h.deps.Store.Fleet(ctx, r.PathValue("id"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		log.Printf("admin: get fleet: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if err == nil {
		if err := h.deps.Remover.Remove(ctx, f); err != nil {
			log.Printf("admin: fleet %s: delete: %v", f.ID, err)
			http.Error(w, "upstream error, retry", http.StatusBadGateway)
			return
		}
		log.Printf("admin: fleet %s deleted", f.ID)
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// removeNode only removes a node that belongs to the fleet named in the URL.
func (h *handler) removeNode(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()
	f, err := h.deps.Store.Fleet(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}
	if err != nil {
		log.Printf("admin: get fleet: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	ns, err := h.deps.Headscale.ListNodes(ctx, f.HeadscaleUser)
	if err != nil {
		log.Printf("admin: fleet %s: list nodes: %v", f.ID, err)
		http.Error(w, "upstream error, retry", http.StatusBadGateway)
		return
	}
	for _, n := range ns {
		if n.ID == r.PathValue("node") {
			if err := h.deps.Headscale.DeleteNodeByID(ctx, n.ID); err != nil {
				log.Printf("admin: fleet %s: remove node: %v", f.ID, err)
				http.Error(w, "upstream error, retry", http.StatusBadGateway)
				return
			}
			log.Printf("admin: fleet %s: node %s removed", f.ID, n.Hostname)
		}
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}
