package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/auth"
	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// quotaHS is a headscale.API with nodes and pre-auth keys per user. Like the real server it keeps
// a created key as unused and unexpired until the test consumes it.
type quotaHS struct {
	headscale.API
	mu      sync.Mutex
	nodes   map[string][]headscale.Node
	keys    map[string][]headscale.PreAuthKey
	ttls    []time.Duration
	creates int
	listErr error
	now     func() time.Time
}

func newQuotaHS() *quotaHS {
	return &quotaHS{nodes: map[string][]headscale.Node{}, keys: map[string][]headscale.PreAuthKey{}, now: func() time.Time { return now0 }}
}

func (q *quotaHS) ListNodes(_ context.Context, user string) ([]headscale.Node, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.listErr != nil {
		return nil, q.listErr
	}
	return append([]headscale.Node(nil), q.nodes[user]...), nil
}

func (q *quotaHS) ListPreAuthKeys(_ context.Context, user string) ([]headscale.PreAuthKey, error) {
	q.mu.Lock()
	keys := append([]headscale.PreAuthKey(nil), q.keys[user]...)
	q.mu.Unlock()
	time.Sleep(2 * time.Millisecond) // widen the window between "count" and "create" for the race test
	return keys, nil
}

func (q *quotaHS) CreatePreAuthKey(_ context.Context, user string, ttl time.Duration) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.creates++
	q.ttls = append(q.ttls, ttl)
	q.keys[user] = append(q.keys[user], headscale.PreAuthKey{Expiration: q.now().Add(ttl)})
	return "hskey-auth-secret-" + strconv.Itoa(q.creates), nil
}

func (q *quotaHS) addNodes(user string, n int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := 0; i < n; i++ {
		q.nodes[user] = append(q.nodes[user], headscale.Node{Hostname: "box-" + strconv.Itoa(len(q.nodes[user])), IP: "100.64.0." + strconv.Itoa(len(q.nodes[user])+1), Online: i%2 == 0})
	}
}

func (q *quotaHS) addKey(user string, k headscale.PreAuthKey) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.keys[user] = append(q.keys[user], k)
}

type fleetEnv struct {
	env
	q      *quotaHS
	id     string
	secret string
	user   string
}

// setupKeys builds a handler with one fleet and a high default limit on everything but the quota.
func setupKeys(t *testing.T, mutate func(*Config, *Deps)) fleetEnv {
	t.Helper()
	q := newQuotaHS()
	e := setup(t, func(c *Config, d *Deps) {
		c.NodesPerFleet = 3
		c.KeyRatePerHour = 1000
		c.AuthRatePerHour = 1000
		c.JoinKeyTTL = 24 * time.Hour
		d.Headscale = q
		if mutate != nil {
			mutate(c, d)
		}
	})
	return fleetEnv{env: e, q: q, id: "fleet0001", secret: addFleet(t, e.st, "fleet0001"), user: "f-fleet0001"}
}

func addFleet(t *testing.T, st store.Store, id string) string {
	t.Helper()
	secret, hash, err := auth.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	f := store.Fleet{ID: id, SecretHash: hash, HeadscaleUser: "f-" + id, CreatedAt: now0, LastOnline: now0}
	if err := st.CreateFleet(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	return secret
}

func (e fleetEnv) call(method, path, secret, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = remote
	if secret != "" {
		r.Header.Set("Authorization", "Bearer "+secret)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func (e fleetEnv) key(secret, remote string) *httptest.ResponseRecorder {
	return e.call(http.MethodPost, "/v1/fleets/"+e.id+"/keys", secret, remote)
}

func (e fleetEnv) status(secret, remote string) *httptest.ResponseRecorder {
	return e.call(http.MethodGet, "/v1/fleets/"+e.id, secret, remote)
}

const ip1 = "192.0.2.1:4000"

func TestJoinKeyIsSingleUseAndExpires(t *testing.T) {
	e := setupKeys(t, func(c *Config, _ *Deps) { c.JoinKeyTTL = 6 * time.Hour })
	rec := e.key(e.secret, ip1)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	var body struct {
		Key       string `json:"key"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Key != "hskey-auth-secret-1" {
		t.Fatalf("key = %q", body.Key)
	}
	want := now0.Add(6 * time.Hour).UTC().Format(time.RFC3339)
	if body.ExpiresAt != want {
		t.Fatalf("expires_at = %q, want %q", body.ExpiresAt, want)
	}
	// The interface has no reusable flag: single use is what the client sends (reusable=false, see
	// headscale.TestCreatePreAuthKey) and Headscale enforces. Here: the TTL handed over is the config's.
	if len(e.q.ttls) != 1 || e.q.ttls[0] != 6*time.Hour {
		t.Fatalf("CreatePreAuthKey ttls = %v", e.q.ttls)
	}
	// Only a digest of the key is kept, never the key.
	sum := sha256.Sum256([]byte(body.Key))
	if err := e.st.RecordKey(context.Background(), e.id, hex.EncodeToString(sum[:]), now0); err != store.ErrExists {
		t.Fatalf("key digest not recorded (RecordKey again = %v)", err)
	}
}

func TestKeyRefusedAtNodeQuota(t *testing.T) {
	t.Run("nodes alone fill the quota", func(t *testing.T) {
		e := setupKeys(t, nil)
		e.q.addNodes(e.user, 3)
		if rec := e.key(e.secret, ip1); rec.Code != http.StatusConflict {
			t.Fatalf("status %d, want 409", rec.Code)
		}
		if e.q.creates != 0 {
			t.Fatal("a key was created beyond the quota")
		}
	})
	t.Run("nodes plus pending keys", func(t *testing.T) {
		e := setupKeys(t, nil)
		e.q.addNodes(e.user, 2)
		if rec := e.key(e.secret, ip1); rec.Code != http.StatusCreated { // 2 nodes + 0 pending < 3
			t.Fatalf("status %d", rec.Code)
		}
		if rec := e.key(e.secret, ip1); rec.Code != http.StatusConflict { // 2 nodes + 1 pending
			t.Fatalf("status %d, want 409", rec.Code)
		}
	})
	t.Run("pending keys alone fill the quota", func(t *testing.T) {
		e := setupKeys(t, nil)
		for i := 0; i < 3; i++ {
			if rec := e.key(e.secret, ip1); rec.Code != http.StatusCreated {
				t.Fatalf("key %d: %d", i+1, rec.Code)
			}
		}
		rec := e.key(e.secret, ip1)
		if rec.Code != http.StatusConflict {
			t.Fatalf("4th key = %d, want 409", rec.Code)
		}
		if strings.Contains(rec.Body.String(), "hskey") {
			t.Fatal("body leaks a key")
		}
	})
	t.Run("consumed and expired keys are not counted", func(t *testing.T) {
		e := setupKeys(t, nil)
		e.q.addNodes(e.user, 2) // the 2 nodes enrolled with 2 keys, now used
		e.q.addKey(e.user, headscale.PreAuthKey{Used: true, Expiration: now0.Add(time.Hour)})
		e.q.addKey(e.user, headscale.PreAuthKey{Used: true, Expiration: now0.Add(time.Hour)})
		e.q.addKey(e.user, headscale.PreAuthKey{Expiration: now0.Add(-time.Second)}) // never used, expired
		if rec := e.key(e.secret, ip1); rec.Code != http.StatusCreated {
			t.Fatalf("status %d, want 201 (2 nodes + 0 pending < 3)", rec.Code)
		}
	})
	t.Run("a key without expiration counts while unused", func(t *testing.T) {
		e := setupKeys(t, nil)
		e.q.addNodes(e.user, 2)
		e.q.addKey(e.user, headscale.PreAuthKey{})
		if rec := e.key(e.secret, ip1); rec.Code != http.StatusConflict {
			t.Fatalf("status %d, want 409", rec.Code)
		}
	})
	t.Run("another fleet's nodes do not count", func(t *testing.T) {
		e := setupKeys(t, nil)
		e.q.addNodes("f-other", 10)
		if rec := e.key(e.secret, ip1); rec.Code != http.StatusCreated {
			t.Fatalf("status %d", rec.Code)
		}
	})
}

func TestKeyRequestsNeedTheSecret(t *testing.T) {
	var mu sync.Mutex
	var hashes []string
	orig := checkSecret
	checkSecret = func(secret, hash string) bool {
		mu.Lock()
		hashes = append(hashes, hash)
		mu.Unlock()
		return orig(secret, hash)
	}
	t.Cleanup(func() { checkSecret = orig })

	e := setupKeys(t, nil)
	stored, _ := e.st.Fleet(context.Background(), e.id)
	cases := []struct {
		name, path, secret string
		code               int
		hash               string
	}{
		{"wrong secret", "/v1/fleets/" + e.id + "/keys", "not-the-secret", 401, stored.SecretHash},
		{"no header", "/v1/fleets/" + e.id + "/keys", "", 401, stored.SecretHash},
		{"unknown fleet", "/v1/fleets/ghost/keys", e.secret, 404, dummyHash},
		{"unknown fleet, no header", "/v1/fleets/ghost/keys", "", 404, dummyHash},
	}
	for _, c := range cases {
		hashes = nil
		rec := e.call(http.MethodPost, c.path, c.secret, ip1)
		if rec.Code != c.code {
			t.Fatalf("%s: status %d, want %d", c.name, rec.Code, c.code)
		}
		// Every outcome runs exactly one comparison, against the real hash only for a known fleet.
		if len(hashes) != 1 || hashes[0] != c.hash {
			t.Fatalf("%s: comparisons against %v, want exactly [%s]", c.name, hashes, c.hash)
		}
		if strings.Contains(rec.Body.String(), stored.SecretHash) || strings.Contains(rec.Body.String(), e.secret) {
			t.Fatalf("%s: body leaks secret material: %s", c.name, rec.Body)
		}
	}
	if e.q.creates != 0 {
		t.Fatal("a key was created for an unauthenticated caller")
	}
	// A non-Bearer scheme is no credential.
	r := httptest.NewRequest(http.MethodPost, "/v1/fleets/"+e.id+"/keys", nil)
	r.Header.Set("Authorization", "Basic "+e.secret)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Basic scheme = %d, want 401", rec.Code)
	}
	if rec := e.key(e.secret, ip1); rec.Code != http.StatusCreated {
		t.Fatalf("right secret = %d", rec.Code)
	}
}

func TestKeyRequestRateLimited(t *testing.T) {
	e := setupKeys(t, func(c *Config, _ *Deps) { c.KeyRatePerHour = 30; c.NodesPerFleet = 1000 })
	other := "fleet0002"
	otherSecret := addFleet(t, e.st, other)

	// Unauthenticated callers (many IPs, so the IP throttle is not what stops them) never touch the fleet's budget.
	for i := 0; i < 40; i++ {
		if rec := e.key("wrong", "198.51.100."+strconv.Itoa(i+1)+":1"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong secret = %d", rec.Code)
		}
	}
	for i := 0; i < 30; i++ {
		if rec := e.key(e.secret, ip1); rec.Code != http.StatusCreated {
			t.Fatalf("request %d = %d: %s", i+1, rec.Code, rec.Body)
		}
	}
	before := e.q.creates
	rec := e.key(e.secret, ip1)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("31st request = %d, want 429", rec.Code)
	}
	if ra, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || ra < 1 || ra > 3600 {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	if e.q.creates != before {
		t.Fatal("a rate-limited request created a key")
	}
	// Another fleet is unaffected, even from the same IP.
	r := httptest.NewRequest(http.MethodPost, "/v1/fleets/"+other+"/keys", nil)
	r.RemoteAddr = ip1
	r.Header.Set("Authorization", "Bearer "+otherSecret)
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, r)
	if rr.Code != http.StatusCreated {
		t.Fatalf("other fleet = %d, want 201", rr.Code)
	}
	// The status endpoint is not subject to the key budget.
	if rec := e.status(e.secret, ip1); rec.Code != http.StatusOK {
		t.Fatalf("status endpoint during key throttle = %d", rec.Code)
	}
}

func TestAuthIsThrottledPerIPBeforeAnyCheck(t *testing.T) {
	var compared atomic.Int32
	orig := checkSecret
	checkSecret = func(s, h string) bool { compared.Add(1); return orig(s, h) }
	t.Cleanup(func() { checkSecret = orig })

	e := setupKeys(t, func(c *Config, _ *Deps) { c.AuthRatePerHour = 3 })
	// Three attempts with three different bogus fleet ids use up the IP's budget...
	for i := 0; i < 3; i++ {
		rec := e.call(http.MethodPost, "/v1/fleets/bogus"+strconv.Itoa(i)+"/keys", e.secret, ip1)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("attempt %d = %d", i+1, rec.Code)
		}
	}
	compared.Store(0)
	// ...so even the right secret is refused, without comparing anything.
	rec := e.key(e.secret, "192.0.2.1:9999") // same IP, other port
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th attempt = %d, want 429", rec.Code)
	}
	if ra, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || ra < 1 {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	if compared.Load() != 0 {
		t.Fatal("secret compared for a throttled IP")
	}
	if rec := e.status(e.secret, ip1); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("GET status from the throttled IP = %d, want 429", rec.Code)
	}
	if e.q.creates != 0 {
		t.Fatal("throttled request created a key")
	}
	// Another IP is unaffected.
	if rec := e.key(e.secret, "192.0.2.2:1"); rec.Code != http.StatusCreated {
		t.Fatalf("other IP = %d", rec.Code)
	}
}

func TestConcurrentKeyRequestsRespectQuota(t *testing.T) {
	e := setupKeys(t, func(c *Config, _ *Deps) { c.NodesPerFleet = 5 })
	e.q.addNodes(e.user, 4) // quota - 1
	const n = 20
	var wg sync.WaitGroup
	var created, conflict atomic.Int32
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			switch rec := e.key(e.secret, ip1); rec.Code {
			case http.StatusCreated:
				created.Add(1)
			case http.StatusConflict:
				conflict.Add(1)
			default:
				t.Errorf("unexpected status %d: %s", rec.Code, rec.Body)
			}
		}()
	}
	close(start)
	wg.Wait()
	if created.Load() != 1 || conflict.Load() != n-1 || e.q.creates != 1 {
		t.Fatalf("created=%d conflict=%d creates=%d, want 1/%d/1", created.Load(), conflict.Load(), e.q.creates, n-1)
	}
}

func TestKeyUpstreamErrorsAreGeneric(t *testing.T) {
	e := setupKeys(t, nil)
	e.q.listErr = &headscale.APIError{Method: "GET", Path: "/api/v1/node", Status: 500, Message: "db password is hunter2"}
	rec := e.key(e.secret, ip1)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("upstream text leaked: %s", rec.Body)
	}
	if rec := e.status(e.secret, ip1); rec.Code != http.StatusBadGateway {
		t.Fatalf("GET status %d, want 502", rec.Code)
	}
}

func TestFleetStatus(t *testing.T) {
	e := setupKeys(t, nil)
	e.q.addNodes(e.user, 2)
	rec := e.status(e.secret, ip1)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	var body struct {
		Nodes []struct {
			Hostname string `json:"hostname"`
			IP       string `json:"ip"`
			Online   bool   `json:"online"`
		} `json:"nodes"`
		NodesMax int    `json:"nodes_max"`
		State    string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Nodes) != 2 || body.Nodes[0].Hostname != "box-0" || body.Nodes[0].IP != "100.64.0.1" || !body.Nodes[0].Online || body.Nodes[1].Online {
		t.Fatalf("nodes = %+v", body.Nodes)
	}
	if body.NodesMax != 3 || body.State != "ok" {
		t.Fatalf("nodes_max=%d state=%q", body.NodesMax, body.State)
	}

	// A pending key fills the quota: the same rule that refuses a key request.
	e.q.addKey(e.user, headscale.PreAuthKey{Expiration: now0.Add(time.Hour)})
	rec = e.status(e.secret, ip1)
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.State != "quota" {
		t.Fatalf("state = %q, %v", body.State, err)
	}
	if rec := e.key(e.secret, ip1); rec.Code != http.StatusConflict {
		t.Fatalf("key request when state is quota = %d", rec.Code)
	}
}

func TestFleetStatusEmptyFleetListsNoNull(t *testing.T) {
	e := setupKeys(t, nil)
	rec := e.status(e.secret, ip1)
	if !strings.Contains(rec.Body.String(), `"nodes":[]`) {
		t.Fatalf("body = %s", rec.Body)
	}
}

func TestFleetStatusNeedsTheSecret(t *testing.T) {
	e := setupKeys(t, nil)
	if rec := e.status("wrong", ip1); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret = %d", rec.Code)
	}
	if rec := e.call(http.MethodGet, "/v1/fleets/ghost", e.secret, ip1); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown fleet = %d", rec.Code)
	}
}
