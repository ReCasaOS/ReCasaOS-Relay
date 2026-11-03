package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/auth"
	"github.com/ReCasaOS/recasaos-relay/internal/ratelimit"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// opTimeout bounds one create-fleet attempt, rollback included. The operations run detached from
// the request context so a client hanging up cannot leave a half-created fleet behind.
const opTimeout = 20 * time.Second

type fleetsHandler struct {
	cfg     Config
	deps    Deps
	limiter *ratelimit.Limiter
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// createFleet handles POST /v1/fleets. Errors are logged without request headers, the secret or
// signatures; response bodies never carry upstream error text.
func (h *fleetsHandler) createFleet(w http.ResponseWriter, r *http.Request) {
	// The limiter runs first and is keyed by client IP: box keys are free to mint.
	if ok, retry := h.limiter.Allow(clientKey(r, h.cfg.TrustedProxyHeader)); !ok {
		secs := int((retry + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	// No body is expected; refuse a large one without ever buffering it.
	if _, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 1<<10)); err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	if _, err := auth.VerifyBox(r, h.deps.Now()); err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized") // same answer whatever the reason
		return
	}

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()

	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		log.Printf("create fleet: random id: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	id := hex.EncodeToString(raw[:])
	user := "f-" + id
	secret, hash, err := auth.NewSecret()
	if err != nil {
		log.Printf("create fleet: random secret: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := h.deps.Headscale.CreateUser(ctx, user); err != nil {
		log.Printf("create fleet %s: headscale create user: %v", id, err)
		// The request may have reached Headscale even though we saw an error: clean up best effort.
		h.rollback(ctx, id, user, false)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	now := h.deps.Now()
	if err := h.deps.Store.CreateFleet(ctx, store.Fleet{ID: id, SecretHash: hash, HeadscaleUser: user, CreatedAt: now, LastOnline: now}); err != nil {
		log.Printf("create fleet %s: store: %v", id, err)
		h.rollback(ctx, id, user, false)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if h.deps.PolicyHook != nil {
		if err := h.deps.PolicyHook([]string{user}); err != nil {
			log.Printf("create fleet %s: policy: %v", id, err)
			h.rollback(ctx, id, user, true)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"fleet_id":             id,
		"secret":               secret,
		"login_server":         h.cfg.LoginServer,
		"expires_in_days_idle": int(h.cfg.IdleAfter / (24 * time.Hour)),
	})
}

// rollback undoes a partly created fleet; failures are logged, nothing more can be done here.
func (h *fleetsHandler) rollback(ctx context.Context, id, user string, storeRow bool) {
	// Fresh budget: the failed call may have used up (or timed out) ctx.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if storeRow {
		if err := h.deps.Store.DeleteFleet(ctx, id); err != nil {
			log.Printf("rollback fleet %s: store: %v", id, err)
		}
	}
	if err := h.deps.Headscale.DeleteUser(ctx, user); err != nil {
		log.Printf("rollback fleet %s: headscale delete user: %v", id, err)
	}
}

// clientKey returns the rate-limit key of a request: the client IP, or its /64 for IPv6 (a single
// subscriber typically owns a whole /64, so per-address keys would be free to mint).
//
// With header empty the TCP peer is used. Otherwise the LAST value of that header is used: it is
// the one appended by the trusted proxy in front of us, whereas earlier values are client-supplied.
// If the header is absent or unparsable the peer address is used (conservative: every client then
// shares the proxy's bucket).
func clientKey(r *http.Request, header string) string {
	addr, ok := netip.Addr{}, false
	if header != "" {
		addr, ok = lastHop(r.Header.Values(header))
	}
	if !ok {
		peer := r.RemoteAddr
		if ap, err := netip.ParseAddrPort(peer); err == nil {
			addr, ok = ap.Addr(), true
		} else if a, err := netip.ParseAddr(peer); err == nil {
			addr, ok = a, true
		}
	}
	if !ok {
		return "unknown"
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is6() {
		p, _ := addr.Prefix(64)
		return p.String()
	}
	return addr.String()
}

func lastHop(values []string) (netip.Addr, bool) {
	if len(values) == 0 {
		return netip.Addr{}, false
	}
	last := values[len(values)-1]
	last = strings.TrimSpace(last[strings.LastIndexByte(last, ',')+1:])
	if ap, err := netip.ParseAddrPort(last); err == nil {
		return ap.Addr(), true
	}
	a, err := netip.ParseAddr(strings.Trim(last, "[]"))
	return a, err == nil
}
