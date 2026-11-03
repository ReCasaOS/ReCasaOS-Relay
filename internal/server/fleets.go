package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/auth"
	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/ratelimit"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// opTimeout bounds one create-fleet attempt, rollback included. The operations run detached from
// the request context so a client hanging up cannot leave a half-created fleet behind.
const opTimeout = 20 * time.Second

type fleetsHandler struct {
	cfg         Config
	deps        Deps
	limiter     *ratelimit.Limiter // create-fleet, per IP
	authLimiter *ratelimit.Limiter // fleet requests, per IP, before the secret is checked
	keyLimiter  *ratelimit.Limiter // join keys, per fleet, after the secret is verified
	locks       *fleets.Locks      // serialises "count nodes and pending keys, then create a key" per fleet; shared with deletion
}

// checkSecret is a variable so tests can observe that every request pays one comparison.
var checkSecret = auth.CheckSecret

// dummyHash is compared against when the fleet is unknown, so that path costs what a wrong secret does.
const dummyHash = "0000000000000000000000000000000000000000000000000000000000000000"

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func tooMany(w http.ResponseWriter, retry time.Duration) {
	secs := int((retry + time.Second - 1) / time.Second)
	w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
	writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// createFleet handles POST /v1/fleets. Errors are logged without request headers, the secret or
// signatures; response bodies never carry upstream error text.
func (h *fleetsHandler) createFleet(w http.ResponseWriter, r *http.Request) {
	// The limiter runs first and is keyed by client IP: box keys are free to mint.
	if ok, retry := h.limiter.Allow(clientKey(r, h.cfg.TrustedProxyHeader)); !ok {
		tooMany(w, retry)
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

// authenticate throttles by client IP, then checks the fleet secret (Authorization: Bearer). It has
// answered the request and returns false unless the caller is the fleet's owner. The IP throttle runs
// first so the secret cannot be hammered and fleet ids chosen by the caller never become limiter keys.
func (h *fleetsHandler) authenticate(w http.ResponseWriter, r *http.Request) (store.Fleet, bool) {
	if ok, retry := h.authLimiter.Allow(clientKey(r, h.cfg.TrustedProxyHeader)); !ok {
		tooMany(w, retry)
		return store.Fleet{}, false
	}
	secret := ""
	if scheme, tok, found := strings.Cut(r.Header.Get("Authorization"), " "); found && strings.EqualFold(scheme, "Bearer") {
		secret = strings.TrimSpace(tok)
	}
	f, err := h.deps.Store.Fleet(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		checkSecret(secret, dummyHash) // same work as a wrong secret: nothing to time
		writeError(w, http.StatusNotFound, "fleet not found")
		return store.Fleet{}, false
	case err != nil:
		log.Printf("fleet lookup: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return store.Fleet{}, false
	}
	if !checkSecret(secret, f.SecretHash) {
		writeError(w, http.StatusUnauthorized, "unauthorized") // generic: says nothing about why
		return store.Fleet{}, false
	}
	return f, true
}

// quotaUsage returns the fleet's nodes and whether one more node would exceed the quota. Unused,
// unexpired join keys count as nodes-to-be: without that a fleet could stockpile keys (the key rate
// limit allows many per day) and enrol beyond the quota. Used keys are not counted: their node is.
func (h *fleetsHandler) quotaUsage(ctx context.Context, user string) (nodes []headscale.Node, full bool, err error) {
	// Keys first, nodes second: a box that registers between the two reads is then counted twice
	// (its key is still pending in the first read, its node shows in the second), which only errs on
	// the safe side. The other order would miss it entirely.
	keys, err := h.deps.Headscale.ListPreAuthKeys(ctx, user)
	if err != nil {
		return nil, false, err
	}
	if nodes, err = h.deps.Headscale.ListNodes(ctx, user); err != nil {
		return nil, false, err
	}
	now, pending := h.deps.Now(), 0
	for _, k := range keys {
		if !k.Used && (k.Expiration.IsZero() || k.Expiration.After(now)) {
			pending++
		}
	}
	return nodes, len(nodes)+pending >= h.cfg.NodesPerFleet, nil
}

// createKey handles POST /v1/fleets/{id}/keys: a single-use join key for one more box.
func (h *fleetsHandler) createKey(w http.ResponseWriter, r *http.Request) {
	f, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	// Keyed by fleet id, which is only now known to be real; the secret holder is who we limit.
	if ok, retry := h.keyLimiter.Allow(f.ID); !ok {
		tooMany(w, retry)
		return
	}
	// Detached like createFleet: a key created for a client that hung up would still use up quota.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()
	unlock, err := h.locks.Lock(ctx, f.ID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "busy, retry later")
		return
	}
	defer unlock()

	_, full, err := h.quotaUsage(ctx, f.HeadscaleUser)
	if err != nil {
		log.Printf("fleet %s: key quota: %v", f.ID, err)
		writeError(w, http.StatusBadGateway, "upstream error")
		return
	}
	if full {
		writeError(w, http.StatusConflict, "node quota reached")
		return
	}
	expires := h.deps.Now().Add(h.cfg.JoinKeyTTL).UTC()
	key, err := h.deps.Headscale.CreatePreAuthKey(ctx, f.HeadscaleUser, h.cfg.JoinKeyTTL)
	if err != nil {
		log.Printf("fleet %s: create key: %v", f.ID, err)
		writeError(w, http.StatusBadGateway, "upstream error")
		return
	}
	// Keep only a digest, never the key. Bookkeeping only: the quota reads Headscale, so a failure
	// here must not lose a key that exists.
	sum := sha256.Sum256([]byte(key))
	if err := h.deps.Store.RecordKey(ctx, f.ID, hex.EncodeToString(sum[:]), expires); err != nil {
		log.Printf("fleet %s: record key: %v", f.ID, err)
	}
	writeJSON(w, http.StatusCreated, map[string]string{"key": key, "expires_at": expires.Format(time.RFC3339)})
}

// fleetStatus handles GET /v1/fleets/{id}.
func (h *fleetsHandler) fleetStatus(w http.ResponseWriter, r *http.Request) {
	f, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), opTimeout)
	defer cancel()
	nodes, full, err := h.quotaUsage(ctx, f.HeadscaleUser)
	if err != nil {
		log.Printf("fleet %s: status: %v", f.ID, err)
		writeError(w, http.StatusBadGateway, "upstream error")
		return
	}
	type node struct {
		Hostname string `json:"hostname"`
		IP       string `json:"ip"`
		Online   bool   `json:"online"`
	}
	out := make([]node, 0, len(nodes)) // [] rather than null for an empty fleet
	for _, n := range nodes {
		out = append(out, node{n.Hostname, n.IP, n.Online})
	}
	state := "ok"
	if full {
		state = "quota"
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": out, "nodes_max": h.cfg.NodesPerFleet, "state": state})
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
