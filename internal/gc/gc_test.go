package gc

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/fakes"
	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

var (
	t0        = time.Unix(1_800_000_000, 0).UTC()
	idleAfter = 30 * 24 * time.Hour
	bg        = context.Background()
)

type rig struct {
	d   Deps
	hs  *fakes.HS
	st  store.Store
	log *fakes.Log
	sy  *fakes.Syncer
	now time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r := &rig{st: st, log: &fakes.Log{}, now: t0}
	now := func() time.Time { return r.now }
	r.hs = fakes.NewHS(r.log, now)
	r.sy = &fakes.Syncer{Log: r.log}
	fst := &fakes.Store{Store: st, Log: r.log}
	r.d = Deps{
		Remover:   &fleets.Remover{Store: fst, Headscale: r.hs, Policy: r.sy, Locks: &fleets.Locks{}},
		IdleAfter: idleAfter,
		Now:       now,
	}
	return r
}

// fleet adds a fleet last seen `ago` before t0; its Headscale user is f-<id>.
func (r *rig) fleet(t *testing.T, id string, ago time.Duration) string {
	t.Helper()
	user := "f-" + id
	err := r.st.CreateFleet(bg, store.Fleet{ID: id, SecretHash: "h", HeadscaleUser: user, CreatedAt: t0.Add(-ago), LastOnline: t0.Add(-ago)})
	if err != nil {
		t.Fatal(err)
	}
	r.hs.AddUser(user)
	return user
}

func (r *rig) lastOnline(t *testing.T, id string) time.Time {
	t.Helper()
	f, err := r.st.Fleet(bg, id)
	if err != nil {
		t.Fatal(err)
	}
	return f.LastOnline
}

func (r *rig) exists(id string) bool {
	_, err := r.st.Fleet(bg, id)
	return err == nil
}

func TestGCDeletesOnlyIdleFleets(t *testing.T) {
	r := newRig(t)
	online := r.fleet(t, "a-online", 60*24*time.Hour) // stale row, but a box is connected
	r.hs.AddNode(online, "box-on", true)
	r.hs.AddNode(online, "box-off", false)
	under := r.fleet(t, "b-under", idleAfter-time.Second)
	r.hs.AddNode(under, "box-u", false)
	r.fleet(t, "c-edge", idleAfter) // exactly at the threshold: not longer than it
	over := r.fleet(t, "d-over", idleAfter+time.Second)
	r.hs.AddNode(over, "box-o", false)
	r.hs.AddKey(over, false, t0.Add(time.Hour))
	r.fleet(t, "e-empty", 90*24*time.Hour) // never had a node

	Tick(bg, r.d)

	if got := r.lastOnline(t, "a-online"); !got.Equal(t0) {
		t.Fatalf("online fleet not touched: last online %v", got)
	}
	for _, id := range []string{"a-online", "b-under", "c-edge"} {
		if !r.exists(id) {
			t.Errorf("fleet %s was deleted", id)
		}
	}
	for _, id := range []string{"d-over", "e-empty"} {
		if r.exists(id) {
			t.Errorf("fleet %s was kept", id)
		}
	}
	if !r.hs.HasUser(online) || !r.hs.HasUser(under) || r.hs.HasUser(over) {
		t.Error("Headscale users do not match the store")
	}
	if r.hs.NodeCount(online) != 2 || r.hs.NodeCount(under) != 1 {
		t.Error("nodes of a kept fleet were removed")
	}
	// A touch refreshes only fleets with an online node: the idle one keeps its age, so it still
	// counts down towards deletion on later ticks.
	if got := r.lastOnline(t, "b-under"); !got.Equal(t0.Add(-(idleAfter - time.Second))) {
		t.Fatalf("an offline fleet was touched: %v", got)
	}

	// One read of the nodes per fleet, then for each deleted fleet: nodes, user, keys, row, sync;
	// then the key sweep and a last sync.
	want := "nodes,nodes,nodes,nodes,nodes," + // the five fleets, a to e
		"nodes,node:4,user,keys,row,sync," + // d-over, in order
		"nodes,user,keys,row,sync," + // e-empty
		"allkeys,sync"
	if got := r.log.String(); got != want {
		t.Fatalf("calls:\n%s\nwant:\n%s", got, want)
	}
}

func TestGCNeverDeletesAFleetItCouldNotReadNodesOf(t *testing.T) {
	r := newRig(t)
	r.fleet(t, "idle", idleAfter+time.Hour)
	// Only the pass's own read fails; the deletion's read would succeed. The guard must hold alone.
	r.hs.FailTimes("nodes", errors.New("headscale down"), 1)
	Tick(bg, r.d)
	if !r.exists("idle") {
		t.Fatal("a fleet was deleted although Headscale could not say whether it has an online node")
	}
	if strings.Contains(r.log.String(), "user") || strings.Contains(r.log.String(), "row") {
		t.Fatalf("calls: %s", r.log)
	}
	Tick(bg, r.d)
	if r.exists("idle") {
		t.Fatal("not deleted once Headscale answers")
	}
}

func TestGCPartialFailureLeavesTheRowAndRetryCompletes(t *testing.T) {
	r := newRig(t)
	for _, id := range []string{"one", "two"} {
		u := r.fleet(t, id, idleAfter+time.Hour)
		r.hs.AddNode(u, "box", false)
	}
	r.hs.Fail("user", errors.New("boom"))
	Tick(bg, r.d)
	// An error on the first fleet does not stop the second from being attempted.
	if n := strings.Count(r.log.String(), "user"); n != 2 {
		t.Fatalf("user deletions attempted = %d, want 2 (%s)", n, r.log)
	}
	if !r.exists("one") || !r.exists("two") {
		t.Fatal("a row was deleted although its Headscale user was not")
	}
	if strings.Contains(r.log.String(), "row") {
		t.Fatalf("store rows touched: %s", r.log)
	}
	if !strings.HasSuffix(r.log.String(), "allkeys,sync") {
		t.Fatalf("the pass did not finish with the key sweep and the sync: %s", r.log)
	}
	r.hs.Heal("user")
	Tick(bg, r.d)
	if r.exists("one") || r.exists("two") {
		t.Fatal("retry did not complete")
	}
}

func TestGCPrunesUsedAndExpiredKeysOfEveryFleet(t *testing.T) {
	r := newRig(t)
	a := r.fleet(t, "a", time.Hour)
	b := r.fleet(t, "b", time.Hour)
	future, past := t0.Add(time.Hour), t0.Add(-time.Second)
	gone := map[string]string{
		"a used":           r.hs.AddKey(a, true, future),
		"a expired":        r.hs.AddKey(a, false, past),
		"b used":           r.hs.AddKey(b, true, past),
		"b expired":        r.hs.AddKey(b, false, t0), // expires exactly now: expired
		"a used, no limit": r.hs.AddKey(a, true, time.Time{}),
	}
	kept := map[string]string{
		"a pending":        r.hs.AddKey(a, false, future),
		"b pending":        r.hs.AddKey(b, false, future),
		"b no expiration":  r.hs.AddKey(b, false, time.Time{}),
		"operator's, used": r.hs.AddKey("someone-else", true, past), // not a fleet's user: not ours
	}

	Tick(bg, r.d)

	left := map[string]bool{}
	for _, k := range r.hs.Keys() {
		left[k.ID] = true
	}
	for name, id := range gone {
		if left[id] {
			t.Errorf("key %q (%s) was not pruned", name, id)
		}
	}
	for name, id := range kept {
		if !left[id] {
			t.Errorf("key %q (%s) was pruned", name, id)
		}
	}
}

func TestGCKeyPruningFailureDoesNotStopThePass(t *testing.T) {
	r := newRig(t)
	a := r.fleet(t, "a", time.Hour)
	r.hs.AddKey(a, true, t0.Add(time.Hour))
	r.hs.AddKey(a, true, t0.Add(time.Hour))
	r.hs.Fail("key", errors.New("boom"))
	Tick(bg, r.d)
	if got := r.log.String(); got != "nodes,allkeys,key:1,key:2,sync" {
		t.Fatalf("calls = %s", got)
	}
	// And a failing key listing still ends in the policy sync.
	r.log.Reset()
	r.hs.Fail("allkeys", errors.New("boom"))
	Tick(bg, r.d)
	if got := r.log.String(); got != "nodes,allkeys,sync" {
		t.Fatalf("calls = %s", got)
	}
}

func TestGCSyncsThePolicyEveryTickEvenWithNoFleets(t *testing.T) {
	r := newRig(t)
	r.sy.Fail(errors.New("down")) // logged, not fatal
	Tick(bg, r.d)
	Tick(bg, r.d)
	if got := r.log.String(); got != "allkeys,sync,allkeys,sync" {
		t.Fatalf("calls = %s", got)
	}
}

// The janitor takes the same per-fleet lock as the HTTP handlers.
func TestGCDeletionWaitsForThePerFleetLock(t *testing.T) {
	r := newRig(t)
	r.fleet(t, "idle", idleAfter+time.Hour)
	unlock, err := r.d.Remover.Locks.Lock(bg, "idle") // a key request in progress
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { Tick(bg, r.d); close(done) }()
	select {
	case <-done:
		t.Fatal("the tick deleted a fleet whose lock was held")
	case <-time.After(150 * time.Millisecond):
	}
	if !r.exists("idle") {
		t.Fatal("row deleted under the lock")
	}
	unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tick did not finish after the lock was released")
	}
	if r.exists("idle") {
		t.Fatal("fleet not deleted")
	}
}

func TestRunTicksAndShutdownWaitsForTheTickInFlight(t *testing.T) {
	r := newRig(t)
	r.fleet(t, "a", time.Hour)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.hs.Hook = func(op string) {
		if op == "nodes" {
			once.Do(func() { close(entered); <-release }) // ignores ctx, like a stuck Headscale call
		}
	}
	ctx, cancel := context.WithCancel(bg)
	returned := make(chan struct{})
	go func() { Run(ctx, r.d, 5*time.Millisecond); close(returned) }()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no tick")
	}
	cancel()
	select {
	case <-returned:
		t.Fatal("Run returned while a tick was in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the tick finished")
	}
	n := strings.Count(r.log.String(), "sync")
	time.Sleep(50 * time.Millisecond)
	if strings.Count(r.log.String(), "sync") != n {
		t.Fatal("ticks continued after Run returned")
	}
}

// A box is online but the stale row cannot be refreshed: the fleet is still not idle.
func TestGCFailedTouchDoesNotMakeAnOnlineFleetIdle(t *testing.T) {
	r := newRig(t)
	u := r.fleet(t, "live", idleAfter+time.Hour)
	r.hs.AddNode(u, "box", true)
	r.d.Remover.Store.(*fakes.Store).FailTouch(errors.New("disk full"))
	Tick(bg, r.d)
	if !r.exists("live") || !r.hs.HasUser(u) || r.hs.NodeCount(u) != 1 {
		t.Fatalf("a fleet with an online box was deleted: %s", r.log)
	}
	if strings.Contains(r.log.String(), "user") {
		t.Fatalf("calls: %s", r.log)
	}
}

// The pass read the fleet as idle; before the deletion gets the lock a box comes online.
func TestGCRechecksNodesUnderTheLock(t *testing.T) {
	r := newRig(t)
	u := r.fleet(t, "idle", idleAfter+time.Hour)
	r.hs.AddNode(u, "box", false)
	var calls int
	r.hs.Hook = func(op string) {
		if op == "nodes" {
			if calls++; calls == 2 { // the first read is the pass's, the second is the deletion's
				r.hs.SetOnline(u, "box", true)
			}
		}
	}
	Tick(bg, r.d)
	if !r.exists("idle") || r.hs.NodeCount(u) != 1 || !r.hs.HasUser(u) {
		t.Fatalf("a fleet whose box came online was deleted: %s", r.log)
	}
	if strings.Contains(r.log.String(), "user") || strings.Contains(r.log.String(), "row") {
		t.Fatalf("calls: %s", r.log)
	}
}

// The pass read the fleet as idle; before the deletion gets the lock the owner asks for a join key
// (which touches the row).
func TestGCRechecksTheRowUnderTheLock(t *testing.T) {
	r := newRig(t)
	r.fleet(t, "idle", idleAfter+time.Hour)
	fst := r.d.Remover.Store.(*fakes.Store)
	var once sync.Once
	fst.OnFleet = func(id string) {
		// Runs after the janitor's own lookup of the row, before RemoveIfIdle re-reads it.
		once.Do(func() {
			if err := r.st.Touch(bg, id, t0); err != nil {
				t.Error(err)
			}
		})
	}
	Tick(bg, r.d)
	if !r.exists("idle") {
		t.Fatalf("a fleet touched after the pass read it was deleted: %s", r.log)
	}
	if strings.Contains(r.log.String(), "row") {
		t.Fatalf("calls: %s", r.log)
	}
}

func TestGCDeletesAFleetWithDuplicateHostnames(t *testing.T) {
	r := newRig(t)
	u := r.fleet(t, "dup", idleAfter+time.Hour)
	r.hs.AddNode(u, "same", false)
	r.hs.AddNode(u, "same", false)
	Tick(bg, r.d)
	if r.exists("dup") || r.hs.HasUser(u) {
		t.Fatalf("not deleted: %s", r.log)
	}
}
