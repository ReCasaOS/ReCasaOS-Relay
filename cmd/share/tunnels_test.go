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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/proxyproto"
	"github.com/ReCasaOS/recasaos-relay/internal/tunnel"
)

// fakeEnrolment serves the two internal routes: one known key, and a usage endpoint that fails while
// failUsage is set.
type fakeEnrolment struct {
	key       string
	mu        sync.Mutex
	failUsage bool
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
	relay := httptest.NewServer(tunnel.Handler(reg, resolver(enr.URL), time.Now))
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
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		toTunnel(reg, "alpha", c, c)
	}()
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
