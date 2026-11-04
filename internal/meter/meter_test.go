package meter

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/fakes"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

const (
	k1 = "nodekey:1111111111111111111111111111111111111111111111111111111111111111"
	k2 = "nodekey:2222222222222222222222222222222222222222222222222222222222222222"
	kx = "nodekey:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

type fakeSource struct {
	mu    sync.Mutex
	conns []Conn
	err   error
	panic bool
}

func (f *fakeSource) Clients(context.Context) ([]Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panic {
		panic("boom")
	}
	return append([]Conn(nil), f.conns...), f.err
}

func (f *fakeSource) set(c ...Conn) { f.mu.Lock(); f.conns = c; f.mu.Unlock() }

type rig struct {
	t    *testing.T
	src  *fakeSource
	log  *fakes.Log
	hs   *fakes.HS
	st   store.Store
	now  time.Time
	node string // node id of k1, user f-fleet1
}

var connected = time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)

func newRig(t *testing.T) *rig {
	r := &rig{t: t, src: &fakeSource{}, log: &fakes.Log{}, now: time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)}
	r.hs = fakes.NewHS(r.log, func() time.Time { return r.now })
	st, err := store.Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r.st = st
	r.node = r.hs.AddNode("f-fleet1", "box", true)
	r.hs.SetNodeKey("f-fleet1", "box", k1)
	return r
}

func (r *rig) meter() *Meter {
	return &Meter{Source: r.src, Nodes: r.hs, Store: r.st, Now: func() time.Time { return r.now }}
}

func (r *rig) tick(m *Meter, c ...Conn) {
	r.t.Helper()
	r.src.set(c...)
	if err := m.Tick(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) totals() []store.UsageTotal {
	r.t.Helper()
	tot, err := r.st.UsageTotals(context.Background(), time.Unix(0, 0))
	if err != nil {
		r.t.Fatal(err)
	}
	return tot
}

// rx is the node's total received bytes, failing unless it is the only row.
func (r *rig) rx(node string) int64 {
	r.t.Helper()
	tot := r.totals()
	if len(tot) != 1 || tot[0].NodeID != node || tot[0].FleetID != "fleet1" {
		r.t.Fatalf("totals = %+v, want one row for fleet1/%s", tot, node)
	}
	return tot[0].Rx
}

func TestTickFirstSeenCountsFullValue(t *testing.T) {
	r := newRig(t)
	r.tick(r.meter(), Conn{Key: k1, ConnNum: 1, ConnectedAt: connected, Rx: 5000, Tx: 70})
	if got := r.rx(r.node); got != 5000 || r.totals()[0].Tx != 70 {
		t.Fatalf("totals = %+v", r.totals())
	}
}

func TestTickCountsDeltas(t *testing.T) {
	r := newRig(t)
	m := r.meter()
	r.tick(m, Conn{Key: k1, ConnNum: 1, ConnectedAt: connected, Rx: 5000, Tx: 100})
	r.now = r.now.Add(15 * time.Second)
	r.tick(m, Conn{Key: k1, ConnNum: 1, ConnectedAt: connected, Rx: 8000, Tx: 1600})
	if got := r.rx(r.node); got != 8000 {
		t.Fatalf("rx = %d, want 8000", got)
	}
	live := m.Live()
	if !live.OK || !live.At.Equal(r.now) || live.Nodes[r.node] != (Rate{Up: 200, Down: 100}) {
		t.Fatalf("live = %+v", live)
	}
}

func TestTickAfterRestartDoesNotDoubleCount(t *testing.T) {
	r := newRig(t)
	r.tick(r.meter(), Conn{Key: k1, ConnNum: 1, ConnectedAt: connected, Rx: 5000})
	r.now = r.now.Add(15 * time.Second)
	m := r.meter() // enrolment restarted: same store, new Meter
	r.tick(m, Conn{Key: k1, ConnNum: 1, ConnectedAt: connected, Rx: 6000})
	if got := r.rx(r.node); got != 6000 {
		t.Fatalf("rx = %d, want 6000", got)
	}
	if live := m.Live(); !live.OK {
		t.Fatalf("live = %+v", live)
	} else if rate, ok := live.Nodes[r.node]; ok {
		t.Fatalf("rate on a new Meter's first tick: %+v", rate)
	}
}

func TestTickDerperRestart(t *testing.T) {
	r := newRig(t)
	m := r.meter()
	r.tick(m, Conn{Key: k1, ConnNum: 7, ConnectedAt: connected, Rx: 9000})
	r.now = r.now.Add(15 * time.Second)
	r.tick(m, Conn{Key: k1, ConnNum: 1, ConnectedAt: r.now.Add(-5 * time.Second), Rx: 100})
	if got := r.rx(r.node); got != 9100 {
		t.Fatalf("rx = %d, want 9100", got)
	}
}

func TestTickDecreasingCounterIsNewConnection(t *testing.T) {
	r := newRig(t)
	m := r.meter()
	r.tick(m, Conn{Key: k1, ConnNum: 7, ConnectedAt: connected, Rx: 9000})
	r.now = r.now.Add(15 * time.Second)
	r.tick(m, Conn{Key: k1, ConnNum: 7, ConnectedAt: connected, Rx: 100})
	if got := r.rx(r.node); got != 9100 {
		t.Fatalf("rx = %d, want 9100", got)
	}
}

func TestTickKeyRotationSameNode(t *testing.T) {
	r := newRig(t)
	r.hs.AddNode("f-fleet1", "other", true)
	id := r.hs.AddNode("f-fleet1", "rotating", true)
	if id != "3" {
		t.Fatalf("node id = %s, want 3", id)
	}
	r.hs.SetNodeKey("f-fleet1", "rotating", k2)
	m := r.meter()
	r.tick(m, Conn{Key: k2, ConnNum: 1, ConnectedAt: connected, Rx: 5000})
	r.hs.SetNodeKey("f-fleet1", "rotating", kx)
	r.now = r.now.Add(60 * time.Second)
	// The old connection lingers a little while the new key connects.
	r.tick(m, Conn{Key: k2, ConnNum: 1, ConnectedAt: connected, Rx: 5500}, Conn{Key: kx, ConnNum: 2, ConnectedAt: r.now, Rx: 1000})
	if got := r.rx("3"); got != 6500 {
		t.Fatalf("rx = %d, want 6500", got)
	}
}

func TestTickUnknownKeyRefreshIsRateLimited(t *testing.T) {
	r := newRig(t)
	m := r.meter()
	for i := 0; i < 10; i++ {
		r.tick(m, Conn{Key: k1, ConnNum: 1, ConnectedAt: connected, Rx: 100}, Conn{Key: kx, ConnNum: 2, ConnectedAt: connected, Rx: int64(777 * (i + 1))})
		r.now = r.now.Add(6 * time.Second)
	}
	if n := strings.Count(r.log.String(), "nodes-all"); n < 1 || n > 2 {
		t.Fatalf("ListAllNodes called %d times: %s", n, r.log)
	}
	if got := r.rx(r.node); got != 100 {
		t.Fatalf("rx = %d, want 100", got)
	}
}

func TestTickUnknownKeyCountedOnceResolved(t *testing.T) {
	r := newRig(t)
	m := r.meter()
	late := Conn{Key: k2, ConnNum: 5, ConnectedAt: connected, Rx: 1000, Tx: 10}
	r.tick(m, late)
	r.now = r.now.Add(15 * time.Second)
	late.Rx, late.Tx = 3000, 30
	r.tick(m, late)
	id := r.hs.AddNode("f-fleet1", "late", true)
	r.hs.SetNodeKey("f-fleet1", "late", k2)
	r.now = r.now.Add(45 * time.Second) // 60 s after the first resolve
	late.Rx, late.Tx = 4000, 40
	r.tick(m, late)
	if got := r.rx(id); got != 4000 || r.totals()[0].Tx != 40 {
		t.Fatalf("totals = %+v, want the full counters 4000/40", r.totals())
	}
	if rate, ok := m.Live().Nodes[id]; ok {
		t.Fatalf("rate without a previous cursor: %+v", rate)
	}
}

func TestTickSourceErrorMarksLiveNotOK(t *testing.T) {
	r := newRig(t)
	m := r.meter()
	r.tick(m, Conn{Key: k1, ConnNum: 1, ConnectedAt: connected, Rx: 5000})
	before, _ := r.st.Cursors(context.Background())
	failed := errors.New("derper down")
	r.src.err = failed
	r.now = r.now.Add(15 * time.Second)
	if err := m.Tick(context.Background()); !errors.Is(err, failed) {
		t.Fatalf("err = %v", err)
	}
	if m.Live().OK {
		t.Fatalf("live = %+v", m.Live())
	}
	after, _ := r.st.Cursors(context.Background())
	if r.rx(r.node) != 5000 || len(after) != 1 || len(before) != 1 {
		t.Fatalf("store changed: %+v -> %+v, totals %+v", before, after, r.totals())
	}
	for k, c := range before {
		if after[k] != c {
			t.Fatalf("cursor %+v -> %+v", c, after[k])
		}
	}
}

func TestRunPrunesAndSurvivesPanics(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if err := r.st.ApplyUsage(ctx, time.Now().Add(-40*24*time.Hour), []store.UsageSample{{FleetID: "fleet1", NodeID: r.node, Rx: 1}}, nil); err != nil {
		t.Fatal(err)
	}
	r.src.panic = true
	m := r.meter()
	m.Now = time.Now // Run reads the clock from another goroutine
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { m.Run(ctx, time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(r.totals()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("old usage was never pruned")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}
