package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/proxyproto"
	"github.com/ReCasaOS/recasaos-relay/internal/ratelimit"
	"github.com/ReCasaOS/recasaos-relay/internal/tunnel"
)

// fakeEnrolment serves the two internal routes: one known key, and a usage endpoint that fails while
// failUsage is set.
type fakeEnrolment struct {
	key       string
	mu        sync.Mutex
	failUsage bool
	tooLarge  bool // answer usage posts 413
	posts     [][]sample
}

func (f *fakeEnrolment) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/internal/share/boxes/"+f.key:
		json.NewEncoder(w).Encode(map[string]string{"name": "alpha", "node_id": "7", "fleet_id": "f1"})
	case strings.HasPrefix(r.URL.Path, "/internal/share/boxes/"):
		http.NotFound(w, r)
	case r.URL.Path == "/internal/share/usage":
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.failUsage {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		if f.tooLarge {
			http.Error(w, "too large", http.StatusRequestEntityTooLarge)
			return
		}
		var s []sample
		json.NewDecoder(r.Body).Decode(&s)
		f.posts = append(f.posts, s)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unexpected", http.StatusTeapot)
	}
}

// rig runs a fake enrolment and the tunnel handler, and dials a box tunnel named alpha.
func rig(t *testing.T) (*fakeEnrolment, string, *tunnel.Registry, *tunnel.Session) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := &fakeEnrolment{key: base64.RawURLEncoding.EncodeToString(pub)}
	enr := httptest.NewServer(f)
	t.Cleanup(enr.Close)
	reg := tunnel.NewRegistry()
	relay := httptest.NewServer(tunnel.Handler(reg, resolver(enr.URL), ratelimit.New(1000, time.Now), time.Now))
	t.Cleanup(relay.Close)
	box, err := tunnel.Dial(context.Background(), relay.URL, priv, tunnel.DialOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { box.Close() })
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, ok := reg.Get("alpha"); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no tunnel")
		}
	}
	return f, enr.URL, reg, box
}

func TestResolver(t *testing.T) {
	f := &fakeEnrolment{key: "known"}
	enr := httptest.NewServer(f)
	resolve := resolver(enr.URL)
	if b, err := resolve(context.Background(), "known"); err != nil || b != (tunnel.Box{Name: "alpha", NodeID: "7", FleetID: "f1"}) {
		t.Fatalf("known key: %+v, %v", b, err)
	}
	if _, err := resolve(context.Background(), "other"); !errors.Is(err, tunnel.ErrNotFound) {
		t.Fatalf("unknown key: %v, want ErrNotFound", err)
	}
	enr.Close()
	_, err := resolve(context.Background(), "secretkey")
	if err == nil || errors.Is(err, tunnel.ErrNotFound) || strings.Contains(err.Error(), "secretkey") {
		t.Fatalf("enrolment down: %v; want a transport error without the key", err)
	}
}

func TestVisitorGoesThroughTunnel(t *testing.T) {
	_, _, reg, box := rig(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		toTunnel(reg, newConnCap(tunnel.MaxStreams, "test"), "alpha", c, c)
	}()
	defer func() { <-done }()
	visitor, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer visitor.Close()
	visitor.Write([]byte("ping"))

	in, err := box.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	src, _, rest, err := proxyproto.ReadProxyV2(in)
	if err != nil || src.String() != visitor.LocalAddr().String() {
		t.Fatalf("PROXY header: %v, %v", src, err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(rest, got); err != nil || string(got) != "ping" {
		t.Fatalf("box read %q, %v", got, err)
	}
	in.Write([]byte("pong"))
	if _, err := io.ReadFull(visitor, got); err != nil || string(got) != "pong" {
		t.Fatalf("visitor read %q, %v", got, err)
	}
}

func TestUsageKeepsBytesUntilPosted(t *testing.T) {
	f, enrURL, reg, box := rig(t)
	u := newUsage(reg, enrURL)
	ctx := context.Background()

	u.tick(ctx) // heartbeat with zero bytes
	tun, _ := reg.Get("alpha")
	s, err := tun.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Write([]byte("12345"))
	in, err := box.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	io.ReadFull(in, make([]byte, 5))

	f.mu.Lock()
	f.failUsage = true
	f.mu.Unlock()
	u.tick(ctx) // lost post: the 5 bytes stay pending
	f.mu.Lock()
	f.failUsage = false
	f.mu.Unlock()
	u.tick(ctx)

	f.mu.Lock()
	defer f.mu.Unlock()
	want := [][]sample{{{FleetID: "f1", NodeID: "7"}}, {{FleetID: "f1", NodeID: "7", TX: 5}}}
	if len(f.posts) != 2 || f.posts[0][0] != want[0][0] || len(f.posts[1]) != 1 || f.posts[1][0] != want[1][0] {
		t.Fatalf("posts = %+v, want %+v", f.posts, want)
	}
}

// enrolment caps the usage body at 64 KiB: a large backlog goes in chunks, and a refused chunk is
// dropped instead of failing every later post.
func TestUsagePostsAreChunked(t *testing.T) {
	f, enrURL, reg, _ := rig(t)
	u := newUsage(reg, enrURL)
	for i := range 999 { // plus alpha's heartbeat: 1 000
		k := [2]string{"f1", strconv.Itoa(1000 + i)}
		u.pending[k] = sample{FleetID: k[0], NodeID: k[1], RX: 1}
	}
	u.tick(context.Background())
	f.mu.Lock()
	n := 0
	for _, p := range f.posts {
		n += len(p)
	}
	if len(f.posts) != 3 || n != 1000 || len(u.pending) != 0 {
		f.mu.Unlock()
		t.Fatalf("%d posts, %d samples, %d pending; want 3, 1000, 0", len(f.posts), n, len(u.pending))
	}
	f.tooLarge = true
	f.mu.Unlock()
	u.pending[[2]string{"f1", "9"}] = sample{FleetID: "f1", NodeID: "9", RX: 1}
	u.tick(context.Background())
	if len(u.pending) != 0 {
		t.Fatalf("a refused chunk stayed pending: %+v", u.pending)
	}
}

// acceptAll makes the box accept (and hold) every stream until the test ends.
func acceptAll(t *testing.T, box *tunnel.Session) {
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := box.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
}

func TestTunnelStreamCap(t *testing.T) {
	_, _, reg, box := rig(t)
	acceptAll(t, box)
	tun, _ := reg.Get("alpha")
	var streams []net.Conn
	defer func() {
		for _, s := range streams {
			s.Close()
		}
	}()
	for range tunnel.MaxStreams {
		s, err := tun.Open(context.Background())
		if err != nil {
			t.Fatalf("stream %d: %v", len(streams)+1, err)
		}
		streams = append(streams, s)
	}

	visitor, c := tcpPair(t)
	defer visitor.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer c.Close()
		toTunnel(reg, newConnCap(tunnel.MaxStreams, "test"), "alpha", c, c)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the visitor past the cap was not turned away at once")
	}
	if _, err := tun.Open(context.Background()); !errors.Is(err, tunnel.ErrFull) {
		t.Fatalf("Open past the cap: %v, want ErrFull", err)
	}

	streams[0].Close() // frees a slot
	s, err := tun.Open(context.Background())
	if err != nil {
		t.Fatalf("Open after a stream closed: %v", err)
	}
	streams[0] = s
}

func TestIdleVisitorIsClosed(t *testing.T) {
	old := idleTimeout
	idleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { idleTimeout = old })
	_, _, reg, box := rig(t)

	visitor, c := tcpPair(t)
	defer visitor.Close()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		defer c.Close()
		toTunnel(reg, newConnCap(tunnel.MaxStreams, "test"), "alpha", c, c)
	}()
	in, err := box.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("idle visitor still connected")
	}
	if d := time.Since(start); d < idleTimeout {
		t.Fatalf("visitor closed after %v, before the idle timeout", d)
	}
	in.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadAll(in); err != nil { // EOF: the relay closed its end of the stream
		t.Fatalf("box stream after the idle timeout: %v", err)
	}
}

func TestClosedTunnelIsReported(t *testing.T) {
	f, enrURL, reg, box := rig(t)
	tun, _ := reg.Get("alpha")
	s, err := tun.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.Write([]byte("12345"))
	in, err := box.Accept()
	if err != nil {
		t.Fatal(err)
	}
	io.ReadFull(in, make([]byte, 5))
	box.Close() // the tunnel goes away before any usage tick
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, ok := reg.Get("alpha"); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("tunnel still registered")
		}
	}

	newUsage(reg, enrURL).tick(context.Background())
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.posts) != 1 || len(f.posts[0]) != 1 || f.posts[0][0] != (sample{FleetID: "f1", NodeID: "7", TX: 5}) {
		t.Fatalf("posts = %+v, want one sample with tx 5", f.posts)
	}
}

// tcpPair returns both ends of a loopback TCP connection (toTunnel needs TCP addresses).
func tcpPair(t *testing.T) (client, server net.Conn) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err = l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}
