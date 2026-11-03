package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

func user(i int) string { return fmt.Sprintf("f-%032x", i) }

type parsed struct {
	Groups map[string][]string `json:"groups"`
	ACLs   []struct {
		Action string   `json:"action"`
		Src    []string `json:"src"`
		Dst    []string `json:"dst"`
	} `json:"acls"`
}

func parse(t *testing.T, b []byte) parsed {
	t.Helper()
	var p parsed
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // nothing but groups and acls may ever appear
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("policy is not the expected JSON: %v\n%s", err, b)
	}
	return p
}

func TestPolicyHasNoCrossFleetRule(t *testing.T) {
	users := []string{user(3), user(1), user(2)}
	b, err := Build(users)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "*:") || strings.Contains(string(b), `"*"`) || strings.Contains(string(b), "autogroup") {
		t.Fatalf("wildcard or autogroup in policy: %s", b)
	}
	p := parse(t, b)
	if len(p.Groups) != 3 || len(p.ACLs) != 3 {
		t.Fatalf("want 3 groups and 3 rules, got %d and %d", len(p.Groups), len(p.ACLs))
	}
	for _, u := range users {
		g := "group:" + u
		if m := p.Groups[g]; len(m) != 1 || m[0] != u+"@" {
			t.Fatalf("%s members = %v, want exactly [%s@]", g, m, u)
		}
	}
	for _, r := range p.ACLs {
		if r.Action != "accept" || len(r.Src) != 1 || len(r.Dst) != 1 {
			t.Fatalf("unexpected rule %+v", r)
		}
		g := r.Src[0]
		if p.Groups[g] == nil || r.Dst[0] != g+":*" {
			t.Fatalf("rule %+v does not stay inside one group", r)
		}
	}
}

func TestZeroUsersIsDenyAll(t *testing.T) {
	for _, in := range [][]string{nil, {}} {
		b, err := Build(in)
		if err != nil {
			t.Fatal(err)
		}
		// An absent "acls" would mean allow-all in Headscale: it must be an explicit empty list.
		if !strings.Contains(string(b), `"acls":[]`) {
			t.Fatalf("zero users must give an explicit empty acls list, got %s", b)
		}
		p := parse(t, b)
		if len(p.ACLs) != 0 || len(p.Groups) != 0 {
			t.Fatalf("not deny-all: %s", b)
		}
	}
}

func TestBuildIsDeterministicAndDedupes(t *testing.T) {
	a, err := Build([]string{user(2), user(1), user(3), user(1)})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build([]string{user(3), user(1), user(2)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("order or duplicates changed the output:\n%s\n%s", a, b)
	}
}

func TestBuildRejectsInvalidUserNames(t *testing.T) {
	for _, bad := range []string{
		"", "f-", "alice", "f-" + strings.Repeat("a", 31), "f-" + strings.Repeat("a", 33),
		"F-" + strings.Repeat("a", 32), "f-" + strings.Repeat("A", 32), "f-" + strings.Repeat("g", 32),
		user(1) + "\n", user(1) + "@", " " + user(1), "f-" + strings.Repeat("a", 31) + `"`,
		"f-" + strings.Repeat("a", 30) + `",`, user(1) + `","*"`, "*",
	} {
		if b, err := Build([]string{user(0), bad}); err == nil {
			t.Errorf("Build accepted %q: %s", bad, b)
		}
	}
}

// fakes -------------------------------------------------------------------------------------------

type fakeStore struct {
	store.Store
	mu     sync.Mutex
	fleets []store.Fleet
	err    error
}

func (s *fakeStore) add(u string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fleets = append(s.fleets, store.Fleet{ID: strings.TrimPrefix(u, "f-"), HeadscaleUser: u})
}

func (s *fakeStore) ListFleets(context.Context) ([]store.Fleet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.Fleet(nil), s.fleets...), s.err
}

type fakeHS struct {
	headscale.API
	mu       sync.Mutex
	policies [][]byte
	failures int // SetPolicy fails this many times first
	inFlight int
	overlap  bool
}

func (h *fakeHS) SetPolicy(_ context.Context, p []byte) error {
	h.mu.Lock()
	h.inFlight++
	if h.inFlight > 1 {
		h.overlap = true
	}
	h.mu.Unlock()
	time.Sleep(time.Millisecond) // widen the window in which an unserialised writer would overlap
	h.mu.Lock()
	defer h.mu.Unlock()
	h.inFlight--
	if h.failures > 0 {
		h.failures--
		return errors.New("headscale not ready")
	}
	h.policies = append(h.policies, p)
	return nil
}

// tests -------------------------------------------------------------------------------------------

func TestWriterSerialisesConcurrentCreates(t *testing.T) {
	const n = 40
	st, hs := &fakeStore{}, &fakeHS{}
	w := NewWriter(st, hs)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := user(i)
			st.add(u) // the handler inserts the row before calling the hook
			if err := w.Hook([]string{u}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if hs.overlap {
		t.Fatal("two SetPolicy calls ran at the same time")
	}
	if len(hs.policies) != n {
		t.Fatalf("%d SetPolicy calls, want %d", len(hs.policies), n)
	}
	prev := map[string]bool{}
	for i, raw := range hs.policies {
		cur := map[string]bool{}
		for g := range parse(t, raw).Groups {
			cur[g] = true
		}
		for g := range prev {
			if !cur[g] {
				t.Fatalf("call %d dropped %s that call %d had: the policy must grow monotonically", i, g, i-1)
			}
		}
		prev = cur
	}
	if len(prev) != n {
		t.Fatalf("last policy has %d groups, want %d", len(prev), n)
	}
}

func TestSyncCoversEveryFleetNotJustTheNewOne(t *testing.T) {
	st, hs := &fakeStore{}, &fakeHS{}
	st.add(user(1))
	st.add(user(2))
	if err := NewWriter(st, hs).Hook([]string{user(2)}); err != nil {
		t.Fatal(err)
	}
	if g := parse(t, hs.policies[0]).Groups; len(g) != 2 {
		t.Fatalf("policy covers %d groups, want both fleets: %v", len(g), g)
	}
}

func TestSyncFailsClosedOnBadStoreOrBadUser(t *testing.T) {
	hs := &fakeHS{}
	st := &fakeStore{err: errors.New("disk")}
	if err := NewWriter(st, hs).Sync(context.Background()); err == nil || len(hs.policies) != 0 {
		t.Fatalf("store error must not push a policy (err=%v, pushed=%d)", err, len(hs.policies))
	}
	st = &fakeStore{}
	st.add("not-a-fleet-user")
	if err := NewWriter(st, hs).Sync(context.Background()); err == nil || len(hs.policies) != 0 {
		t.Fatalf("invalid user must not push a policy (err=%v, pushed=%d)", err, len(hs.policies))
	}
}

func TestSyncWithRetry(t *testing.T) {
	st, hs := &fakeStore{}, &fakeHS{failures: 2}
	w := NewWriter(st, hs)
	if err := w.SyncWithRetry(context.Background(), 5, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if len(hs.policies) != 1 || !strings.Contains(string(hs.policies[0]), `"acls":[]`) {
		t.Fatalf("expected one deny-all policy after two failures, got %q", hs.policies)
	}

	hs = &fakeHS{failures: 100}
	if err := NewWriter(st, hs).SyncWithRetry(context.Background(), 3, time.Millisecond); err == nil {
		t.Fatal("keeps failing: SyncWithRetry must return an error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	hs = &fakeHS{failures: 100}
	if err := NewWriter(st, hs).SyncWithRetry(ctx, 1000, time.Hour); err == nil {
		t.Fatal("cancelled context must stop the retries")
	}
}
