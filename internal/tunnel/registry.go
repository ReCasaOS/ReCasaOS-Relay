// Package tunnel carries visitor connections to shared boxes: a box opens a WebSocket to the relay, the
// relay runs a yamux client over it and opens one stream per visitor connection.
package tunnel

import (
	"context"
	"errors"
	"log"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// Close codes the relay sends to a box (see the API contract).
const (
	StatusUnauthorized websocket.StatusCode = 4401
	StatusRevoked      websocket.StatusCode = 4403
	StatusReplaced     websocket.StatusCode = 4409
)

// Limits on a tunnel's visitor streams.
const (
	MaxStreams  = 256              // concurrent streams per tunnel (yamux blocks beyond 256 un-ACKed opens)
	OpenTimeout = 10 * time.Second // to open one stream
)

// ErrFull: the tunnel already carries MaxStreams streams.
var ErrFull = errors.New("tunnel: too many open streams")

// Tunnel is one box's live connection. Key is the box key as X-Box-Key spells it (never log it).
type Tunnel struct {
	Name, NodeID, FleetID string
	Key                   string

	ws   *websocket.Conn
	sess *yamux.Session
	sem  chan struct{} // one slot per open stream

	rx, tx           atomic.Int64 // rx: bytes the box sent; tx: bytes sent to the box
	takenRx, takenTx atomic.Int64
	fullLogged       atomic.Int64 // unix time of the last "full" log line
}

func newTunnel(box Box, key string, ws *websocket.Conn, sess *yamux.Session) *Tunnel {
	return &Tunnel{Name: box.Name, NodeID: box.NodeID, FleetID: box.FleetID, Key: key, ws: ws, sess: sess,
		sem: make(chan struct{}, MaxStreams)}
}

// Open opens a stream to the box, within ctx and OpenTimeout. It fails at once with ErrFull when the
// tunnel already carries MaxStreams streams; a timeout leaves the session up.
func (t *Tunnel) Open(ctx context.Context) (net.Conn, error) {
	select {
	case t.sem <- struct{}{}:
	default:
		if last, now := t.fullLogged.Load(), time.Now().Unix(); now-last >= 60 && t.fullLogged.CompareAndSwap(last, now) {
			log.Printf("tunnel: %q full (%d streams)", t.Name, MaxStreams)
		}
		return nil, ErrFull
	}
	ctx, cancel := context.WithTimeout(ctx, OpenTimeout)
	defer cancel()
	type result struct {
		s   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() { s, err := t.sess.Open(); ch <- result{s, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			<-t.sem
			return nil, r.err
		}
		return &counted{Conn: r.s, t: t}, nil
	case <-ctx.Done():
		go func() { // a stream opened too late is closed, and only then is its slot freed
			if r := <-ch; r.err == nil {
				r.s.Close()
			}
			<-t.sem
		}()
		return nil, ctx.Err()
	}
}

// Close sends code to the box and closes the session and every open stream.
func (t *Tunnel) Close(code websocket.StatusCode, reason string) {
	// The WebSocket first: closing the yamux session would close it with 1000 instead of code.
	_ = t.ws.Close(code, reason)
	_ = t.sess.Close()
}

// Bytes returns the bytes the box sent (rx) and the bytes sent to it (tx) since the tunnel opened.
func (t *Tunnel) Bytes() (rx, tx int64) { return t.rx.Load(), t.tx.Load() }

// Take returns the bytes moved since the previous Take.
func (t *Tunnel) Take() (rx, tx int64) {
	r, w := t.rx.Load(), t.tx.Load()
	return r - t.takenRx.Swap(r), w - t.takenTx.Swap(w)
}

// counted adds what crosses a stream to its tunnel's counters as it goes, and frees its slot on Close.
type counted struct {
	net.Conn
	t    *Tunnel
	once sync.Once
}

func (c *counted) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.t.sem })
	return err
}

func (c *counted) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.t.rx.Add(int64(n))
	return n, err
}

func (c *counted) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.t.tx.Add(int64(n))
	return n, err
}

// MaxRetired bounds the closed tunnels waiting for TakeRetired.
const MaxRetired = 10000

// Registry maps a share name to its live tunnel, and keeps the tunnels that closed since the last
// TakeRetired so their final bytes are still reported.
type Registry struct {
	mu      sync.Mutex
	m       map[string]*Tunnel
	retired []*Tunnel
}

func (r *Registry) retire(t *Tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.retired) >= MaxRetired {
		log.Printf("tunnel: retired backlog full, dropping %q's last bytes", t.Name)
		return
	}
	r.retired = append(r.retired, t)
}

// TakeRetired returns the tunnels closed since the previous call, and forgets them.
func (r *Registry) TakeRetired() []*Tunnel {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.retired
	r.retired = nil
	return t
}

func NewRegistry() *Registry { return &Registry{m: map[string]*Tunnel{}} }

// Put registers t under name and returns the tunnel it replaced, if any (the caller closes it).
func (r *Registry) Put(name string, t *Tunnel) (replaced *Tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	replaced = r.m[name]
	r.m[name] = t
	return replaced
}

func (r *Registry) Get(name string) (*Tunnel, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.m[name]
	return t, ok
}

// Names returns the registered names, sorted.
func (r *Registry) Names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.m))
	for n := range r.m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Remove unregisters name only while t is still the tunnel registered under it.
func (r *Registry) Remove(name string, t *Tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.m[name] == t {
		delete(r.m, name)
	}
}

// Revalidate asks resolve about every tunnel's key and closes, with 4403, the tunnels whose box lost its
// name (ErrNotFound) or now holds another one. A transport error leaves the tunnel alone: enrolment
// restarting must not drop every share.
func Revalidate(ctx context.Context, reg *Registry, resolve Resolver) {
	for _, name := range reg.Names() {
		t, ok := reg.Get(name)
		if !ok {
			continue
		}
		box, err := resolve(ctx, t.Key)
		switch {
		case errors.Is(err, ErrNotFound) || (err == nil && box.Name != t.Name):
			log.Printf("tunnel: %q revoked", name)
			go t.Close(StatusRevoked, "name revoked")
		case err != nil:
			log.Printf("tunnel: revalidate %q: %v", name, err)
		}
	}
}
