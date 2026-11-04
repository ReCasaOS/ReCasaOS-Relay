package meter

import (
	"context"
	"fmt"
	"log"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// refreshEvery bounds how often an unknown key makes the meter re-list Headscale's nodes.
const refreshEvery = 60 * time.Second

// Source lists derper's connections; *Derper is the real one.
type Source interface {
	Clients(ctx context.Context) ([]Conn, error)
}

// Rate is in bytes per second. Up is what the node sent through the relay (derper's Rx).
type Rate struct{ Up, Down float64 }

// Live is the latest reading. OK is false when the last tick failed; Nodes is keyed by Headscale
// node ID and holds only nodes with a connection seen on this Meter's previous tick too.
type Live struct {
	OK    bool
	At    time.Time
	Nodes map[string]Rate
}

// Meter attributes derper's byte counters to Headscale nodes and fleets. Tick is not safe for
// concurrent use (Run calls it from one goroutine); Live is.
type Meter struct {
	Source Source
	Nodes  headscale.API
	Store  store.Store
	Now    func() time.Time // default time.Now

	mu   sync.Mutex
	live Live

	owners       map[string]owner // node key -> owner; nil until the first resolve
	refreshed    time.Time
	prev         map[string]bool // connection identities seen on the previous successful tick
	prevAt       time.Time
	unattributed int64 // bytes of known keys outside any fleet, since the last hourly log
	conns        int   // connections on the last successful tick
}

// owner is a node and its fleet; fleet is "" for a node outside any fleet (not attributed).
type owner struct{ node, fleet string }

func (m *Meter) now() time.Time {
	if m.Now == nil {
		return time.Now()
	}
	return m.Now()
}

// Live returns a copy of the latest reading.
func (m *Meter) Live() Live {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.live
	l.Nodes = maps.Clone(l.Nodes)
	return l
}

// fail marks Live not OK and returns err (already prefixed by its package).
func (m *Meter) fail(at time.Time, err error) error {
	m.mu.Lock()
	m.live = Live{At: at}
	m.mu.Unlock()
	return err
}

// Tick reads derper once, stores the bytes moved since the stored cursors and updates Live. On
// error nothing is stored, so the next tick counts those bytes.
//
// The cursor table is replaced by the connections whose key Headscale knows. A key it does not
// know yet gets no cursor, so once it resolves its connection counts in full: each byte counts
// once, late rather than never. A key known but outside any fleet keeps its cursor and only its
// deltas count as unattributed.
func (m *Meter) Tick(ctx context.Context) error {
	now := m.now()
	conns, err := m.Source.Clients(ctx)
	if err != nil {
		return m.fail(now, err)
	}
	cursors, err := m.Store.Cursors(ctx)
	if err != nil {
		return m.fail(now, err)
	}
	if err := m.resolve(ctx, now, conns); err != nil {
		return m.fail(now, err)
	}

	type delta struct {
		o      owner
		rx, tx int64
		rated  bool // same connection as on this Meter's previous tick, counters not reset
	}
	seen := make(map[string]bool, len(conns))
	next := make([]store.Cursor, 0, len(conns))
	deltas := make([]delta, 0, len(conns))
	for _, c := range conns {
		id := fmt.Sprintf("%s|%d|%d", c.Key, c.ConnNum, c.ConnectedAt.UnixNano())
		if seen[id] {
			continue
		}
		seen[id] = true
		o, known := m.owners[c.Key]
		if !known {
			continue // no cursor: counted in full once the key resolves
		}
		next = append(next, store.Cursor{Conn: id, Rx: c.Rx, Tx: c.Tx})
		d := delta{o: o, rx: c.Rx, tx: c.Tx}
		if p, ok := cursors[id]; ok && c.Rx >= p.Rx && c.Tx >= p.Tx {
			d.rx, d.tx, d.rated = c.Rx-p.Rx, c.Tx-p.Tx, m.prev[id]
		}
		deltas = append(deltas, d)
	}

	sums := map[owner]*store.UsageSample{}
	var samples []store.UsageSample
	var unattributed int64
	for _, d := range deltas {
		if d.o.fleet == "" {
			unattributed += d.rx + d.tx
			continue
		}
		if s := sums[d.o]; s != nil {
			s.Rx, s.Tx = s.Rx+d.rx, s.Tx+d.tx
		} else {
			sums[d.o] = &store.UsageSample{FleetID: d.o.fleet, NodeID: d.o.node, Rx: d.rx, Tx: d.tx}
		}
	}
	for _, s := range sums {
		if s.Rx != 0 || s.Tx != 0 {
			samples = append(samples, *s)
		}
	}
	if err := m.Store.ApplyUsage(ctx, now, samples, next); err != nil {
		return m.fail(now, err)
	}

	rates := map[string]Rate{}
	if secs := now.Sub(m.prevAt).Seconds(); secs > 0 {
		for _, d := range deltas {
			if d.rated && d.o.fleet != "" {
				r := rates[d.o.node]
				r.Up += float64(d.rx) / secs
				r.Down += float64(d.tx) / secs
				rates[d.o.node] = r
			}
		}
	}
	m.prev, m.prevAt = seen, now
	m.unattributed += unattributed
	m.conns = len(seen)
	m.mu.Lock()
	m.live = Live{OK: true, At: now, Nodes: rates}
	m.mu.Unlock()
	return nil
}

// resolve (re)builds the key -> owner map: at the first tick, then when a key is unknown and the
// last refresh is at least refreshEvery old. A rotated-out key still connected keeps its owner.
func (m *Meter) resolve(ctx context.Context, now time.Time, conns []Conn) error {
	need := m.owners == nil
	present := make(map[string]bool, len(conns))
	for _, c := range conns {
		present[c.Key] = true
		if _, ok := m.owners[c.Key]; !ok && now.Sub(m.refreshed) >= refreshEvery {
			need = true
		}
	}
	if !need {
		return nil
	}
	m.refreshed = now // also on failure: an unreachable Headscale is not asked every tick
	nodes, err := m.Nodes.ListAllNodes(ctx)
	if err != nil {
		if m.owners != nil {
			log.Printf("meter: list nodes: %v (keeping the previous key map)", err)
			return nil
		}
		return err
	}
	owners := make(map[string]owner, len(nodes))
	for _, n := range nodes {
		fleet, ok := strings.CutPrefix(n.User, "f-")
		if !ok {
			fleet = ""
		}
		owners[n.NodeKey] = owner{node: n.ID, fleet: fleet}
	}
	for k, o := range m.owners {
		if _, ok := owners[k]; !ok && present[k] {
			owners[k] = o
		}
	}
	m.owners = owners
	return nil
}

// Run ticks every `every` until ctx is done, prunes old usage once an hour, and returns only once
// the tick in flight has returned. A panicking tick is logged; the next one retries.
func (m *Meter) Run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	var pruned time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ctx.Err() != nil {
				continue
			}
			m.safeTick(ctx)
			if now := m.now(); now.Sub(pruned) >= time.Hour {
				pruned = now
				if err := m.Store.PruneUsage(ctx, now.Add(-25*time.Hour), now.Add(-35*24*time.Hour)); err != nil {
					log.Printf("meter: prune usage: %v", err)
				}
				log.Printf("meter: %d derper connections, %d unattributed bytes in the last hour", m.conns, m.unattributed)
				m.unattributed = 0
			}
		}
	}
}

func (m *Meter) safeTick(ctx context.Context) {
	defer func() {
		if p := recover(); p != nil {
			m.fail(m.now(), nil)
			log.Printf("meter: tick panicked (the next tick retries): %v", p)
		}
	}()
	if err := m.Tick(ctx); err != nil {
		log.Print(err) // never holds a key or an address: see Derper.Clients
	}
}
