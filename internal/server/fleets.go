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
	"sync"
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
	limiter     *ratelimit.Limiter // create-fleet, per IP (IPv6: per /64)
	limiter48   *ratelimit.Limiter // create-fleet, per IP (IPv6: per /48), prefix48Factor times the rate
	authLimiter *ratelimit.Limiter // fleet requests, per IP, before the secret is checked
	keyLimiter  *ratelimit.Limiter // join keys, per fleet, after the secret is verified
	locks       *fleets.Locks      // serialises "count nodes and pending keys, then create a key" per fleet; shared with deletion

	capMu          sync.Mutex     // guards the "count fleets, reserve a slot" step of creation
	creating       int            // creations past that step and not yet finished
	creatingFrom   map[string]int // the same, by the network they come from (address or /64)
	creatingFrom48 map[string]int // and by its /48
}

// What reserveFleet found.
const (
	slotTaken   = iota // a place is reserved: call release when the creation is over
	relayFull          // the relay holds MaxFleets
	networkFull        // the network of the request holds its share
)

// reserveFleet takes one of the MaxFleets slots and one of those of the network the request
// comes from (origin: its address or /64; origin48: its /48), counting the creations still in
// flight, so that concurrent requests cannot all see the last free slot. Deletions running
// meanwhile can only make the counts err high (a refusal that a retry would not get).
func (h *fleetsHandler) reserveFleet(ctx context.Context, origin, origin48 string) (release func(), found int, err error) {
	h.capMu.Lock()
	defer h.capMu.Unlock()
	n, err := h.deps.Store.CountFleets(ctx)
	if err != nil {
		return nil, 0, err
	}
	if n+h.creating >= h.cfg.MaxFleets {
		return nil, relayFull, nil
	}
	here, wider, err := h.deps.Store.CountFleetsFrom(ctx, origin, origin48)
	if err != nil {
		return nil, 0, err
	}
	over := func(count, most int) bool { return most > 0 && count >= most }
	// origin48 is the address itself for IPv4: the limit of an address is then the only one
	if over(here+h.creatingFrom[origin], h.cfg.MaxFleetsPerOrigin) ||
		(origin48 != origin && over(wider+h.creatingFrom48[origin48], h.cfg.MaxFleetsPerPrefix48)) {
		return nil, networkFull, nil
	}
	if h.creatingFrom == nil {
		h.creatingFrom, h.creatingFrom48 = map[string]int{}, map[string]int{}
	}
	h.creating++
	h.creatingFrom[origin]++
	h.creatingFrom48[origin48]++
	return func() {
		h.capMu.Lock()
		defer h.capMu.Unlock()
		h.creating--
		// the maps hold the creations in flight, nothing more
		if h.creatingFrom[origin]--; h.creatingFrom[origin] <= 0 {
			delete(h.creatingFrom, origin)
		}
		if h.creatingFrom48[origin48]--; h.creatingFrom48[origin48] <= 0 {
			delete(h.creatingFrom48, origin48)
		}
	}, slotTaken, nil
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

func retryAfter(retry time.Duration) string {
	return strconv.Itoa(max(int((retry+time.Second-1)/time.Second), 1))
}

func tooMany(w http.ResponseWriter, retry time.Duration) {
	w.Header().Set("Retry-After", retryAfter(retry))
	writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// createFleet handles POST /v1/fleets. Errors are logged without request headers, the secret or
// signatures; response bodies never carry upstream error text.
func (h *fleetsHandler) createFleet(w http.ResponseWriter, r *http.Request) {
	// The limiters run first and are keyed by client IP: box keys are free to mint. The /64 one goes
	// first, so a single /64 hammering past its own limit does not use up its /48's budget.
	origin, origin48 := clientKey(r, h.cfg.TrustedProxyHeader, 64), clientKey(r, h.cfg.TrustedProxyHeader, 48)
	if ok, retry := h.limiter.Allow(origin); !ok {
		tooMany(w, retry)
		return
	}
	if ok, retry := h.limiter48.Allow(origin48); !ok {
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

	// Before any Headscale call: the policy and the key list Headscale returns grow with the fleets.
	release, found, err := h.reserveFleet(ctx, origin, origin48)
	if err != nil {
		log.Printf("create fleet: count fleets: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	switch found {
	case relayFull:
		writeError(w, http.StatusServiceUnavailable, "relay full, retry later")
		return
	case networkFull:
		// A place comes back when one of the network's fleets is deleted or idles out: no time to name.
		w.Header().Set("Retry-After", retryAfter(time.Hour))
		writeError(w, http.StatusTooManyRequests, "too many fleets from this network")
		return
	}
	defer release()

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
	if err := h.deps.Store.CreateFleet(ctx, store.Fleet{ID: id, SecretHash: hash, HeadscaleUser: user, CreatedAt: now, LastOnline: now, Origin: origin, Origin48: origin48}); err != nil {
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
	if ok, retry := h.authLimiter.Allow(clientKey(r, h.cfg.TrustedProxyHeader, 64)); !ok {
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

// quotaUsage returns the fleet's nodes, its pending join keys (unused, unexpired) and the ids of
// its spent ones (used or expired). Pending keys count as nodes-to-be against the node quota:
// without that a fleet could stockpile keys (the key rate limit allows many per day) and enrol
// beyond it. Used keys are not counted: their node is.
func (h *fleetsHandler) quotaUsage(ctx context.Context, fleetID, user string) (nodes []headscale.Node, pending int, spent []string, err error) {
	// Keys first, nodes second: a box that registers between the two reads is then counted twice
	// (its key is still pending in the first read, its node shows in the second), which only errs on
	// the safe side. The other order would miss it entirely.
	keys, err := h.deps.Headscale.ListPreAuthKeys(ctx, user)
	if err != nil {
		return nil, 0, nil, err
	}
	all, err := h.deps.Headscale.ListNodes(ctx, user)
	if err != nil {
		return nil, 0, nil, err
	}
	// Devices (phones, PCs) share the fleet's Headscale user but are not boxes: neither quota nor status counts them.
	devs, err := h.deps.Store.DeviceIDs(ctx, fleetID)
	if err != nil {
		return nil, 0, nil, err
	}
	for _, n := range all {
		if !devs[n.ID] {
			nodes = append(nodes, n)
		}
	}
	now := h.deps.Now()
	for _, k := range keys {
		if !k.Used && (k.Expiration.IsZero() || k.Expiration.After(now)) {
			pending++
		} else {
			spent = append(spent, k.ID)
		}
	}
	return nodes, pending, spent, nil
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

	nodes, pending, spent, err := h.quotaUsage(ctx, f.ID, f.HeadscaleUser)
	if err != nil {
		log.Printf("fleet %s: key quota: %v", f.ID, err)
		writeError(w, http.StatusBadGateway, "upstream error")
		return
	}
	// Not left to the janitor alone: with this, the fleet's share of Headscale's key list (listed
	// whole on every quota check) stays at most MaxPendingKeys between passes. A failure is retried
	// by the janitor.
	for _, id := range spent {
		if err := h.deps.Headscale.DeletePreAuthKey(ctx, id); err != nil {
			log.Printf("fleet %s: prune key %s: %v", f.ID, id, err)
		}
	}
	if len(nodes)+pending >= h.cfg.NodesPerFleet {
		writeError(w, http.StatusConflict, "node quota reached")
		return
	}
	if pending >= h.cfg.MaxPendingKeys {
		writeError(w, http.StatusConflict, "too many unused join keys, retry when one is used or expired")
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
	// The owner is active: a fleet asking for a key must not look idle to the janitor.
	if err := h.deps.Store.Touch(ctx, f.ID, h.deps.Now()); err != nil {
		log.Printf("fleet %s: touch: %v", f.ID, err)
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
	nodes, pending, _, err := h.quotaUsage(ctx, f.ID, f.HeadscaleUser)
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
	if len(nodes)+pending >= h.cfg.NodesPerFleet {
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

// clientKey returns the rate-limit key of a request: the client IP, or for IPv6 its prefix of the
// given length (a single subscriber typically owns a whole /64, often a /48 or /56, so per-address
// keys would be free to mint).
//
// With header empty the TCP peer is used. Otherwise the LAST value of that header is used: it is
// the one appended by the trusted proxy in front of us, whereas earlier values are client-supplied.
// If the header is absent or unparsable the peer address is used (conservative: every client then
// shares the proxy's bucket).
func clientKey(r *http.Request, header string, v6bits int) string {
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
		p, _ := addr.Prefix(v6bits)
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
