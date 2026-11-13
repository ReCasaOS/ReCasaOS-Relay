package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/fakes"
	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
)

type delEnv struct {
	env
	hs     *fakes.HS
	log    *fakes.Log
	sy     *fakes.Syncer
	fst    *fakes.Store
	id     string
	secret string
	user   string
}

// setupDel builds a handler over fakes that share one call log, with one fleet "fleet0001".
func setupDel(t *testing.T, mutate func(*Config)) delEnv { return setupDelDeps(t, mutate, nil) }

// setupDelDeps is setupDel with a hook on the Deps once the fakes are in.
func setupDelDeps(t *testing.T, mutate func(*Config), deps func(*Deps)) delEnv {
	t.Helper()
	log := &fakes.Log{}
	hs := fakes.NewHS(log, func() time.Time { return now0 })
	sy := &fakes.Syncer{Log: log}
	var fst *fakes.Store
	e := setup(t, func(c *Config, d *Deps) {
		c.NodesPerFleet = 3
		c.KeyRatePerHour = 1000
		c.AuthRatePerHour = 1000
		c.JoinKeyTTL = time.Hour
		if mutate != nil {
			mutate(c)
		}
		fst = &fakes.Store{Store: d.Store, Log: log}
		d.Store, d.Headscale = fst, hs
		d.Remover = &fleets.Remover{Store: fst, Headscale: hs, Policy: sy}
		if deps != nil {
			deps(d)
		}
	})
	d := delEnv{env: e, hs: hs, log: log, sy: sy, fst: fst, id: "fleet0001", user: "f-fleet0001"}
	d.secret = addFleet(t, e.st, d.id)
	hs.AddUser(d.user)
	return d
}

func (d delEnv) do(method, path, secret, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = remote
	if secret != "" {
		r.Header.Set("Authorization", "Bearer "+secret)
	}
	rec := httptest.NewRecorder()
	d.h.ServeHTTP(rec, r)
	return rec
}

func (d delEnv) deleteFleet(secret string) *httptest.ResponseRecorder {
	return d.do(http.MethodDelete, "/v1/fleets/"+d.id, secret, ip1)
}

func (d delEnv) removeNode(secret, host string) *httptest.ResponseRecorder {
	return d.do(http.MethodDelete, "/v1/fleets/"+d.id+"/nodes/"+host, secret, ip1)
}

func (d delEnv) fleetExists(t *testing.T) bool {
	t.Helper()
	_, err := d.st.Fleet(context.Background(), d.id)
	return err == nil
}

func TestDeleteFleetIsIdempotent(t *testing.T) {
	t.Run("deletes in order and a repeat is 404", func(t *testing.T) {
		d := setupDel(t, nil)
		d.hs.AddNode(d.user, "box-a", true)
		d.hs.AddNode(d.user, "box-b", false)
		d.hs.AddKey(d.user, true, now0.Add(time.Hour))
		d.hs.AddKey("f-other", false, now0.Add(time.Hour)) // another fleet's key must survive
		d.log.Reset()

		rec := d.deleteFleet(d.secret)
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Fatalf("status %d, body %q", rec.Code, rec.Body)
		}
		// Nodes, then the user, then the leftover keys, then the store row, then the policy.
		if got, want := d.log.String(), "nodes,node:1,node:2,user,keys,row,sync"; got != want {
			t.Fatalf("calls = %s, want %s", got, want)
		}
		if d.fleetExists(t) || d.hs.HasUser(d.user) || d.hs.NodeCount(d.user) != 0 {
			t.Fatal("fleet not fully deleted")
		}
		if keys := d.hs.Keys(); len(keys) != 1 || keys[0].User != "f-other" {
			t.Fatalf("keys left = %+v", keys)
		}
		// After a COMPLETE deletion there is no row to authenticate against.
		if rec := d.deleteFleet(d.secret); rec.Code != http.StatusNotFound {
			t.Fatalf("second delete = %d, want 404", rec.Code)
		}
	})
	t.Run("a fleet that never had a node", func(t *testing.T) {
		d := setupDel(t, nil)
		if rec := d.deleteFleet(d.secret); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
		if d.fleetExists(t) {
			t.Fatal("row left")
		}
	})
	t.Run("the Headscale user is already gone", func(t *testing.T) {
		d := setupDel(t, nil)
		d.hs.DeleteUser(context.Background(), d.user)
		if rec := d.deleteFleet(d.secret); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
	})
	t.Run("keys Headscale kept are deleted by id", func(t *testing.T) {
		d := setupDel(t, nil)
		d.hs.KeepKeysOnUserDelete = true
		id := d.hs.AddKey(d.user, false, now0.Add(time.Hour))
		d.log.Reset()
		if rec := d.deleteFleet(d.secret); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
		if got, want := d.log.String(), "nodes,user,keys,key:"+id+",row,sync"; got != want {
			t.Fatalf("calls = %s, want %s", got, want)
		}
		if len(d.hs.Keys()) != 0 {
			t.Fatal("key left")
		}
	})
}

func TestDeleteFleetPartialFailureIsRetryable(t *testing.T) {
	boom := &headscale.APIError{Method: "DELETE", Path: "/api/v1/user/1", Status: 500, Message: "db password is hunter2"}
	for _, step := range []string{"nodes", "node", "user", "keys"} {
		t.Run("fails at "+step, func(t *testing.T) {
			d := setupDel(t, nil)
			d.hs.AddNode(d.user, "box-a", true)
			d.hs.Fail(step, boom)
			rec := d.deleteFleet(d.secret)
			if rec.Code != http.StatusBadGateway {
				t.Fatalf("status %d, want 502", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "hunter2") {
				t.Fatalf("upstream text leaked: %s", rec.Body)
			}
			if !d.fleetExists(t) {
				t.Fatal("row deleted although a step failed: the client could not retry")
			}
			if strings.Contains(d.log.String(), "row") || strings.Contains(d.log.String(), "sync") {
				t.Fatalf("row or policy touched after a failure: %s", d.log)
			}
			// Same call, same secret, once Headscale is back.
			d.hs.Heal(step)
			if rec := d.deleteFleet(d.secret); rec.Code != http.StatusNoContent {
				t.Fatalf("retry = %d, want 204", rec.Code)
			}
			if d.fleetExists(t) || d.hs.HasUser(d.user) {
				t.Fatal("retry left something behind")
			}
		})
	}
	t.Run("store row", func(t *testing.T) {
		d := setupDel(t, nil)
		d.fst.FailDelete(errors.New("disk full"))
		if rec := d.deleteFleet(d.secret); rec.Code != http.StatusBadGateway {
			t.Fatalf("status %d", rec.Code)
		}
		if !d.fleetExists(t) {
			t.Fatal("row gone")
		}
		d.fst.FailDelete(nil)
		if rec := d.deleteFleet(d.secret); rec.Code != http.StatusNoContent {
			t.Fatalf("retry = %d", rec.Code)
		}
	})
	t.Run("policy sync failure after the row is gone is not a failure", func(t *testing.T) {
		d := setupDel(t, nil)
		d.sy.Fail(errors.New("headscale down"))
		if rec := d.deleteFleet(d.secret); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
		if d.fleetExists(t) {
			t.Fatal("row left")
		}
	})
}

func TestRemoveNodeUnknownIs204(t *testing.T) {
	d := setupDel(t, nil)
	d.hs.AddNode(d.user, "box-a", true)
	d.hs.AddNode(d.user, "box-b", true)
	if rec := d.removeNode(d.secret, "box-a"); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("status %d, body %q", rec.Code, rec.Body)
	}
	if d.hs.NodeCount(d.user) != 1 {
		t.Fatal("node not removed")
	}
	// The same node again, and one that never existed: both already "gone".
	for _, host := range []string{"box-a", "never-existed"} {
		if rec := d.removeNode(d.secret, host); rec.Code != http.StatusNoContent {
			t.Fatalf("%s: status %d, want 204", host, rec.Code)
		}
	}
	if d.hs.NodeCount(d.user) != 1 {
		t.Fatal("an unknown hostname removed something")
	}
	if !d.fleetExists(t) {
		t.Fatal("removing a node deleted the fleet")
	}
}

func TestRemoveNodeHostnameValidation(t *testing.T) {
	d := setupDel(t, nil)
	for _, c := range []struct {
		host string
		code int
	}{
		{"box-1", 204},
		{"BOX-1", 204},
		{"a", 204},
		{strings.Repeat("a", 63), 204},
		{strings.Repeat("a", 64), 400},
		{"box_1", 400},
		{"box.local", 400},
		{"box%2e1", 400}, // decoded to "box.1"
		{"box%201", 400},
		{"%00", 400},
		{"b%C3%A9", 400},
	} {
		d.log.Reset()
		rec := d.removeNode(d.secret, c.host)
		if rec.Code != c.code {
			t.Errorf("hostname %q = %d, want %d", c.host, rec.Code, c.code)
		}
		if c.code == 400 && d.log.String() != "" {
			t.Errorf("hostname %q reached Headscale: %s", c.host, d.log)
		}
	}
	// An empty hostname does not match the route at all.
	if rec := d.do(http.MethodDelete, "/v1/fleets/"+d.id+"/nodes/", d.secret, ip1); rec.Code == http.StatusNoContent {
		t.Errorf("empty hostname = %d", rec.Code)
	}
	if !validHostname("x") || validHostname("") {
		t.Error("validHostname")
	}
}

func TestRemoveNodeUpstreamErrorIsGeneric(t *testing.T) {
	d := setupDel(t, nil)
	d.hs.AddNode(d.user, "box-a", true)
	d.hs.Fail("nodes", &headscale.APIError{Status: 500, Message: "db password is hunter2"})
	rec := d.removeNode(d.secret, "box-a")
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
}

func TestDeleteEndpointsNeedTheSecret(t *testing.T) {
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

	d := setupDel(t, nil)
	d.hs.AddNode(d.user, "box-a", true)
	stored, _ := d.st.Fleet(context.Background(), d.id)
	for _, ep := range []struct{ name, path string }{
		{"node", "/nodes/box-a"},
		{"fleet", ""},
	} {
		for _, c := range []struct {
			name, id, secret string
			code             int
			hash             string
		}{
			{"wrong secret", d.id, "not-the-secret", 401, stored.SecretHash},
			{"no header", d.id, "", 401, stored.SecretHash},
			{"unknown fleet", "ghost", d.secret, 404, dummyHash},
			{"unknown fleet, no header", "ghost", "", 404, dummyHash},
		} {
			hashes = nil
			rec := d.do(http.MethodDelete, "/v1/fleets/"+c.id+ep.path, c.secret, ip1)
			if rec.Code != c.code {
				t.Fatalf("%s/%s: status %d, want %d", ep.name, c.name, rec.Code, c.code)
			}
			// One comparison per request, against the real hash only for a known fleet.
			if len(hashes) != 1 || hashes[0] != c.hash {
				t.Fatalf("%s/%s: comparisons against %v, want exactly [%s]", ep.name, c.name, hashes, c.hash)
			}
		}
	}
	if !d.fleetExists(t) || d.hs.NodeCount(d.user) != 1 || d.log.String() != "" {
		t.Fatalf("an unauthenticated caller changed something: %s", d.log)
	}
	// A non-Bearer scheme is no credential.
	r := httptest.NewRequest(http.MethodDelete, "/v1/fleets/"+d.id, nil)
	r.Header.Set("Authorization", "Basic "+d.secret)
	rec := httptest.NewRecorder()
	d.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Basic scheme = %d", rec.Code)
	}
}

func TestDeleteEndpointsAreThrottledPerIPBeforeAnyCheck(t *testing.T) {
	var compared atomic.Int32
	orig := checkSecret
	checkSecret = func(s, h string) bool { compared.Add(1); return orig(s, h) }
	t.Cleanup(func() { checkSecret = orig })

	d := setupDel(t, func(c *Config) { c.AuthRatePerHour = 3 })
	for i := 0; i < 3; i++ {
		if rec := d.do(http.MethodDelete, "/v1/fleets/bogus"+strconv.Itoa(i), d.secret, ip1); rec.Code != http.StatusNotFound {
			t.Fatalf("attempt %d = %d", i+1, rec.Code)
		}
	}
	compared.Store(0)
	for _, rec := range []*httptest.ResponseRecorder{
		d.deleteFleet(d.secret),
		d.removeNode(d.secret, "box-a"),
	} {
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("throttled request = %d, want 429", rec.Code)
		}
		if ra, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || ra < 1 {
			t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
		}
	}
	if compared.Load() != 0 || !d.fleetExists(t) || d.log.String() != "" {
		t.Fatalf("a throttled request did work: compared=%d calls=%s", compared.Load(), d.log)
	}
	// Another IP is unaffected.
	if rec := d.do(http.MethodDelete, "/v1/fleets/"+d.id, d.secret, "192.0.2.2:1"); rec.Code != http.StatusNoContent {
		t.Fatalf("other IP = %d", rec.Code)
	}
}

// A delete and a key request for the same fleet must not interleave: the key request waits for the
// delete, so it cannot create a key (or count nodes) for a fleet that is being torn down.
func TestDeleteTakesThePerFleetLock(t *testing.T) {
	d := setupDel(t, nil)
	d.hs.AddNode(d.user, "box-a", true)
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	d.hs.Hook = func(op string) {
		if op == "nodes" {
			once.Do(func() { close(reached); <-release })
		}
	}
	var wg sync.WaitGroup
	var delCode int
	wg.Add(1)
	go func() { defer wg.Done(); delCode = d.deleteFleet(d.secret).Code }()
	<-reached // the delete holds the lock and is inside Headscale

	wg.Add(1)
	go func() {
		defer wg.Done()
		d.do(http.MethodPost, "/v1/fleets/"+d.id+"/keys", d.secret, ip1)
	}()
	time.Sleep(150 * time.Millisecond)
	if got := d.log.String(); got != "" { // the hook runs before the op is logged, so the blocked delete has logged nothing

		t.Fatalf("the key request ran while the delete held the lock: %s", got)
	}
	close(release)
	wg.Wait()
	if delCode != http.StatusNoContent {
		t.Fatalf("delete = %d", delCode)
	}
	// Everything the delete did comes before anything the key request did.
	calls := d.log.Calls()
	syncAt := -1
	for i, c := range calls {
		if c == "sync" {
			syncAt = i
		}
	}
	if syncAt < 0 {
		t.Fatalf("calls = %v", calls)
	}
	for i, c := range calls {
		if c == "create-key" && i < syncAt {
			t.Fatalf("a key was created in the middle of the delete: %v", calls)
		}
	}
}

// raceHS lets a box register between the two reads of the quota: whichever read comes first, the
// pending key is consumed (and its node appears) right after it.
type raceHS struct {
	*quotaHS
	user string
	once sync.Once
}

func (r *raceHS) register() {
	r.once.Do(func() {
		r.quotaHS.mu.Lock()
		defer r.quotaHS.mu.Unlock()
		r.quotaHS.keys[r.user][0].Used = true
		r.quotaHS.nodes[r.user] = append(r.quotaHS.nodes[r.user], headscale.Node{Hostname: "new-box"})
	})
}

func (r *raceHS) ListPreAuthKeys(ctx context.Context, user string) ([]headscale.PreAuthKey, error) {
	keys, err := r.quotaHS.ListPreAuthKeys(ctx, user)
	r.register()
	return keys, err
}

func (r *raceHS) ListNodes(ctx context.Context, user string) ([]headscale.Node, error) {
	nodes, err := r.quotaHS.ListNodes(ctx, user)
	r.register()
	return nodes, err
}

// With quota 2, one node and one pending key the fleet is full. If the pending key registers while
// the quota is being read, reading nodes first would see 1 node and then a used key: 1 < 2, a key
// beyond the quota. Reading keys first sees the pending key and then both nodes: still full.
func TestQuotaReadsKeysBeforeNodes(t *testing.T) {
	q := newQuotaHS()
	race := &raceHS{quotaHS: q, user: "f-fleet0001"}
	e := setupKeys(t, func(c *Config, d *Deps) { c.NodesPerFleet = 2; d.Headscale = race })
	q.addNodes(e.user, 1)
	q.addKey(e.user, headscale.PreAuthKey{Expiration: now0.Add(time.Hour)})
	if rec := e.key(e.secret, ip1); rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409 (a box registered between the reads)", rec.Code)
	}
	if q.creates != 0 {
		t.Fatal("a key was created beyond the quota")
	}
}

// Headscale lets two nodes of one user share a hostname (live: both listed as "name":"dup").
func TestDuplicateHostnames(t *testing.T) {
	t.Run("deleting the fleet removes both, by id", func(t *testing.T) {
		d := setupDel(t, nil)
		a := d.hs.AddNode(d.user, "dup", true)
		b := d.hs.AddNode(d.user, "dup", false)
		d.log.Reset()
		if rec := d.deleteFleet(d.secret); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
		if got, want := d.log.String(), "nodes,node:"+a+",node:"+b+",user,keys,row,sync"; got != want {
			t.Fatalf("calls = %s, want %s", got, want)
		}
		if d.fleetExists(t) || d.hs.HasUser(d.user) {
			t.Fatal("fleet not deleted")
		}
	})
	t.Run("the node endpoint removes every node of that name", func(t *testing.T) {
		d := setupDel(t, nil)
		d.hs.AddNode(d.user, "dup", true)
		d.hs.AddNode(d.user, "dup", true)
		d.hs.AddNode(d.user, "keep", true)
		if rec := d.removeNode(d.secret, "dup"); rec.Code != http.StatusNoContent {
			t.Fatalf("status %d", rec.Code)
		}
		if d.hs.NodeCount(d.user) != 1 {
			t.Fatalf("%d nodes left, want only \"keep\"", d.hs.NodeCount(d.user))
		}
	})
}

func TestKeyCreationTouchesTheFleet(t *testing.T) {
	e := setupKeys(t, nil)
	old := now0.Add(-100 * 24 * time.Hour)
	if err := e.st.Touch(context.Background(), e.id, old); err != nil {
		t.Fatal(err)
	}
	if rec := e.key("wrong", ip1); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	if f, _ := e.st.Fleet(context.Background(), e.id); !f.LastOnline.Equal(old) {
		t.Fatalf("a refused request touched the fleet: %v", f.LastOnline)
	}
	if rec := e.key(e.secret, ip1); rec.Code != http.StatusCreated {
		t.Fatalf("status %d", rec.Code)
	}
	if f, _ := e.st.Fleet(context.Background(), e.id); !f.LastOnline.Equal(now0) {
		t.Fatalf("last online = %v, want %v", f.LastOnline, now0)
	}
}

func TestRemoveNodeSparesDevices(t *testing.T) {
	d := setupDel(t, nil)
	box := d.hs.AddNode(d.user, "b-x", true)
	dev := d.hs.AddNode(d.user, "b-x", true)
	if err := d.st.AddDevice(t.Context(), d.id, dev, now0); err != nil {
		t.Fatal(err)
	}
	d.log.Reset()
	if rec := d.removeNode(d.secret, "b-x"); rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	if got := d.log.String(); !strings.Contains(got, "node:"+box) || strings.Contains(got, "node:"+dev) || strings.Contains(got, "nodes-named") {
		t.Fatalf("log %q", got)
	}
	if d.hs.NodeCount(d.user) != 1 {
		t.Fatalf("nodes left %d", d.hs.NodeCount(d.user))
	}
}
