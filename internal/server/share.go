package server

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/ReCasaOS/recasaos-relay/internal/auth"
	"github.com/ReCasaOS/recasaos-relay/internal/ratelimit"
	"github.com/ReCasaOS/recasaos-relay/internal/sharename"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// maxShareBody caps the JSON bodies of the share routes, as createFleet does.
const maxShareBody = 1 << 10

// shareHandler serves the box-signed /v1/share routes.
type shareHandler struct {
	cfg         Config
	deps        Deps
	authLimiter *ratelimit.Limiter // per client IP, before the signature is verified
	acmeLimiter *ratelimit.Limiter // ACME TXT writes, per node id, after verification
	beats       *heartbeats
}

// shareEnabled answers 503 on every share route while SHARE_DOMAIN is empty.
func (c Config) shareEnabled(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if c.ShareDomain == "" {
			writeError(w, http.StatusServiceUnavailable, "sharing not enabled")
			return
		}
		next(w, r)
	}
}

func opCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
}

// setBoxKey handles PUT /v1/fleets/{id}/nodes/{node}/box-key: the fleet owner links a box's
// signing key to one of the fleet's nodes.
func (h *fleetsHandler) setBoxKey(w http.ResponseWriter, r *http.Request) {
	f, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	var body struct {
		BoxKey string `json:"box_key"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if pub, err := base64.RawURLEncoding.Strict().DecodeString(body.BoxKey); err != nil || len(pub) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "invalid box key")
		return
	}
	ctx, cancel := opCtx(r)
	defer cancel()
	nodes, err := h.deps.Headscale.ListNodes(ctx, f.HeadscaleUser)
	if err != nil {
		log.Printf("fleet %s: box key: %v", f.ID, err)
		writeError(w, http.StatusBadGateway, "upstream error")
		return
	}
	node := r.PathValue("node")
	found := false
	for _, n := range nodes {
		found = found || n.ID == node
	}
	if !found {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	switch err := h.deps.Store.SetBoxKey(ctx, f.ID, node, body.BoxKey, h.deps.Now()); {
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, "box key already linked")
	case err != nil:
		log.Printf("fleet %s: set box key: %v", f.ID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// readJSON reads a body of at most maxShareBody bytes into v. It has answered the request when it
// returns false. An empty body leaves v untouched.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxShareBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return false
	}
	if len(b) > 0 && json.Unmarshal(b, v) != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return false
	}
	return true
}

// boxAuth runs the checks every box-signed route shares, in this order: IP throttle, body cap,
// signature, key link. body, when not nil, receives the decoded JSON. It has answered the request
// when ok is false.
func (h *shareHandler) boxAuth(w http.ResponseWriter, r *http.Request, body any) (ref store.BoxRef, ok bool) {
	if ok, retry := h.authLimiter.Allow(clientKey(r, h.cfg.TrustedProxyHeader, 64)); !ok {
		tooMany(w, retry)
		return ref, false
	}
	// Read (capped) before verifying, decode only once the caller is known.
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxShareBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return ref, false
	}
	if _, err := auth.VerifyBox(r, h.deps.Now()); err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return ref, false
	}
	ctx, cancel := opCtx(r)
	defer cancel()
	ref, err = h.deps.Store.BoxByKey(ctx, r.Header.Get("X-Box-Key"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusForbidden, "box key not linked")
		return ref, false
	case err != nil:
		log.Printf("share: box lookup: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return ref, false
	}
	if body != nil && len(raw) > 0 && json.Unmarshal(raw, body) != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return ref, false
	}
	return ref, true
}

func (h *shareHandler) shareBody(name string) map[string]string {
	return map[string]string{"name": name, "host": name + "." + h.cfg.ShareDomain, "domain": h.cfg.ShareDomain}
}

func internalError(w http.ResponseWriter, what string, err error) {
	log.Printf("share: %s: %v", what, err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// putName handles PUT /v1/share/name.
func (h *shareHandler) putName(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	ref, ok := h.boxAuth(w, r, &body)
	if !ok {
		return
	}
	switch err := sharename.Valid(body.Name); {
	case errors.Is(err, sharename.ErrReserved):
		writeError(w, http.StatusConflict, "name reserved")
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, "invalid name")
		return
	}
	if ref.Name == body.Name { // already ours
		writeJSON(w, http.StatusOK, h.shareBody(body.Name))
		return
	}
	ctx, cancel := opCtx(r)
	defer cancel()
	switch err := h.deps.Store.ClaimName(ctx, ref.NodeID, body.Name, h.deps.Now()); {
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, "name taken")
	case errors.Is(err, store.ErrBanned):
		writeError(w, http.StatusConflict, "name revoked")
	case errors.Is(err, store.ErrQuarantined):
		writeError(w, http.StatusConflict, "name in quarantine")
	case errors.Is(err, store.ErrNotFound): // the key was unlinked since boxAuth
		writeError(w, http.StatusForbidden, "box key not linked")
	case err != nil:
		internalError(w, "claim name", err)
	default:
		writeJSON(w, http.StatusCreated, h.shareBody(body.Name))
	}
}

// deleteName handles DELETE /v1/share/name.
func (h *shareHandler) deleteName(w http.ResponseWriter, r *http.Request) {
	ref, ok := h.boxAuth(w, r, nil)
	if !ok {
		return
	}
	ctx, cancel := opCtx(r)
	defer cancel()
	if err := h.deps.Store.ReleaseName(ctx, ref.NodeID, h.deps.Now().Add(store.Quarantine)); err != nil {
		internalError(w, "release name", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// status handles GET /v1/share.
func (h *shareHandler) status(w http.ResponseWriter, r *http.Request) {
	ref, ok := h.boxAuth(w, r, nil)
	if !ok {
		return
	}
	if ref.Name == "" {
		writeError(w, http.StatusNotFound, "no name")
		return
	}
	b := map[string]any{"tunnel_online": h.beats.online(ref.NodeID, h.deps.Now())}
	for k, v := range h.shareBody(ref.Name) {
		b[k] = v
	}
	writeJSON(w, http.StatusOK, b)
}

// acmeName is the key under which the TXT value of the box's DNS-01 challenge is stored: the full
// record name, so the DNS server can look a query up as it is.
func (h *shareHandler) acmeName(name string) string {
	return "_acme-challenge." + name + "." + h.cfg.ShareDomain
}

// putACME handles PUT /v1/share/acme.
func (h *shareHandler) putACME(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Value string `json:"value"`
	}
	ref, ok := h.boxAuth(w, r, &body)
	if !ok {
		return
	}
	if ref.Name == "" {
		writeError(w, http.StatusNotFound, "no name")
		return
	}
	if ok, retry := h.acmeLimiter.Allow(ref.NodeID); !ok {
		tooMany(w, retry)
		return
	}
	if n := len(body.Value); n == 0 || n > 255 { // one TXT character-string
		writeError(w, http.StatusBadRequest, "invalid value")
		return
	}
	ctx, cancel := opCtx(r)
	defer cancel()
	if err := h.deps.Store.SetACME(ctx, h.acmeName(ref.Name), body.Value, h.deps.Now().Add(h.cfg.ShareACMETTL)); err != nil {
		internalError(w, "set acme", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteACME handles DELETE /v1/share/acme.
func (h *shareHandler) deleteACME(w http.ResponseWriter, r *http.Request) {
	ref, ok := h.boxAuth(w, r, nil)
	if !ok {
		return
	}
	if ref.Name != "" {
		ctx, cancel := opCtx(r)
		defer cancel()
		if err := h.deps.Store.DeleteACME(ctx, h.acmeName(ref.Name)); err != nil {
			internalError(w, "delete acme", err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
