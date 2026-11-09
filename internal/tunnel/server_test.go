package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/proxyproto"
)

// fakeEnrolment answers resolve for the keys it knows; err, when set, is returned for every key.
type fakeEnrolment struct {
	mu    sync.Mutex
	boxes map[string]Box
	err   error
}

func (f *fakeEnrolment) resolve(_ context.Context, key string) (Box, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return Box{}, f.err
	}
	b, ok := f.boxes[key]
	if !ok {
		return Box{}, ErrNotFound
	}
	return b, nil
}

func (f *fakeEnrolment) set(key string, b *Box, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b == nil {
		delete(f.boxes, key)
	} else {
		f.boxes[key] = *b
	}
	f.err = err
}

func newBox(t *testing.T, f *fakeEnrolment, name string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if name != "" {
		f.set(base64.RawURLEncoding.EncodeToString(pub), &Box{Name: name, NodeID: "7", FleetID: "f1"}, nil)
	}
	return priv
}

// newRelay serves Handler on an httptest server. Sessions must be closed before the test ends (the
// handler lives as long as its tunnel, and the server's Close waits for it).
func newRelay(t *testing.T) (*Registry, *fakeEnrolment, string) {
	t.Helper()
	reg, f := NewRegistry(), &fakeEnrolment{boxes: map[string]Box{}}
	srv := httptest.NewServer(Handler(reg, f.resolve, time.Now))
	t.Cleanup(srv.Close)
	return reg, f, srv.URL
}

func dial(t *testing.T, url string, key ed25519.PrivateKey, opts DialOptions) *Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := Dial(ctx, url, key, opts)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// waitTunnel waits until name is registered with a tunnel other than not.
func waitTunnel(t *testing.T, reg *Registry, name string, not *Tunnel) *Tunnel {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if tun, ok := reg.Get(name); ok && tun != not {
			return tun
		}
	}
	t.Fatalf("no tunnel for %q", name)
	return nil
}

// accept returns the next stream the box receives, or fails after 5 s.
func accept(t *testing.T, s *Session) net.Conn {
	t.Helper()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() { c, err := s.Accept(); ch <- res{c, err} }()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("Accept: %v", r.err)
		}
		return r.c
	case <-time.After(5 * time.Second):
		t.Fatal("Accept: timeout")
		return nil
	}
}

// waitClosed waits for the box session to end and returns the close code the relay sent.
func waitClosed(t *testing.T, s *Session) int {
	t.Helper()
	ch := make(chan error, 1)
	go func() {
		for {
			c, err := s.Accept()
			if err != nil {
				ch <- err
				return
			}
			c.Close()
		}
	}()
	select {
	case <-ch:
		return int(s.CloseStatus())
	case <-time.After(15 * time.Second):
		t.Fatal("box session still open")
		return 0
	}
}

func TestTunnelRoundTrip(t *testing.T) {
	reg, f, url := newRelay(t)
	box := dial(t, url, newBox(t, f, "alpha"), DialOptions{})
	tun := waitTunnel(t, reg, "alpha", nil)
	if tun.NodeID != "7" || tun.FleetID != "f1" || tun.Name != "alpha" {
		t.Fatalf("tunnel = %+v", tun)
	}

	stream, err := tun.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	visitor := &net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 51000}
	local := &net.TCPAddr{IP: net.IPv4(198, 51, 100, 1), Port: 443}
	if err := proxyproto.WriteV2(stream, visitor, local); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("hello box")); err != nil {
		t.Fatal(err)
	}

	in := accept(t, box)
	defer in.Close()
	src, dst, rest, err := proxyproto.ReadProxyV2(in)
	if err != nil {
		t.Fatal(err)
	}
	if src.String() != visitor.String() || dst.String() != local.String() {
		t.Fatalf("PROXY header: %v -> %v", src, dst)
	}
	got := make([]byte, len("hello box"))
	if _, err := io.ReadFull(rest, got); err != nil || string(got) != "hello box" {
		t.Fatalf("read %q, %v", got, err)
	}
}

func TestUnknownKeyIsClosed4403(t *testing.T) {
	reg, _, url := newRelay(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	_, err := Dial(context.Background(), url, priv, DialOptions{})
	var de *DialError
	if !errors.As(err, &de) || de.StatusCode != http.StatusForbidden {
		t.Fatalf("Dial with an unknown key: %v, want 403", err)
	}
	if n := len(reg.Names()); n != 0 {
		t.Fatalf("%d tunnels registered", n)
	}
}

// Refused before the upgrade, a bad signature is a plain 401: the 4401 close code is for a failure
// detected once the WebSocket is up, which this handler never has.
func TestBadSignatureIs4401(t *testing.T) {
	_, f, url := newRelay(t)
	key := newBox(t, f, "alpha")
	pub := key.Public().(ed25519.PublicKey)
	req, _ := http.NewRequest("GET", url+Path, nil)
	_, other, _ := ed25519.GenerateKey(nil)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("X-Box-Key", base64.RawURLEncoding.EncodeToString(pub))
	req.Header.Set("X-Box-Time", ts)
	req.Header.Set("X-Box-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(other, []byte("GET "+Path+"\n"+ts))))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
}

func TestNewerTunnelReplacesOlder(t *testing.T) {
	reg, f, url := newRelay(t)
	key := newBox(t, f, "alpha")
	// Two dials within one second would sign the same message: the replay check would refuse the second.
	first := dial(t, url, key, DialOptions{Now: func() time.Time { return time.Now().Add(-2 * time.Second) }})
	old := waitTunnel(t, reg, "alpha", nil)
	second := dial(t, url, key, DialOptions{})
	waitTunnel(t, reg, "alpha", old)

	if code := waitClosed(t, first); code != int(StatusReplaced) {
		t.Fatalf("older session closed with %d, want 4409", code)
	}
	if second.CloseStatus() != -1 {
		t.Fatalf("newer session closed with %d", second.CloseStatus())
	}
}

func TestRevokedNameClosesTunnel(t *testing.T) {
	reg, f, url := newRelay(t)
	key := newBox(t, f, "alpha")
	box := dial(t, url, key, DialOptions{})
	tun := waitTunnel(t, reg, "alpha", nil)
	stream, err := tun.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	stream.Write([]byte("x"))
	in := accept(t, box)
	defer in.Close()

	// Enrolment down: the tunnel stays.
	f.set(tun.Key, &Box{Name: "alpha", NodeID: "7", FleetID: "f1"}, errors.New("connection refused"))
	Revalidate(context.Background(), reg, f.resolve)
	time.Sleep(50 * time.Millisecond)
	if _, ok := reg.Get("alpha"); !ok || box.CloseStatus() != -1 {
		t.Fatal("a transport error closed the tunnel")
	}

	f.set(tun.Key, nil, nil) // the name was revoked: resolve answers 404
	Revalidate(context.Background(), reg, f.resolve)
	if code := waitClosed(t, box); code != int(StatusRevoked) {
		t.Fatalf("box session closed with %d, want 4403", code)
	}
	buf := make([]byte, 8)
	in.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(in, buf); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("box stream still open: %v", err)
	}
	stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Read(buf); err == nil {
		t.Fatal("relay stream still open")
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, ok := reg.Get("alpha"); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked tunnel still registered")
		}
	}
}

func TestBytesAreCounted(t *testing.T) {
	reg, f, url := newRelay(t)
	box := dial(t, url, newBox(t, f, "alpha"), DialOptions{})
	tun := waitTunnel(t, reg, "alpha", nil)
	stream, err := tun.Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("0123456789")); err != nil { // 10 bytes to the box
		t.Fatal(err)
	}
	in := accept(t, box)
	defer in.Close()
	if _, err := io.ReadFull(in, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := in.Write([]byte("abcdefg")); err != nil { // 7 bytes from the box
		t.Fatal(err)
	}
	if _, err := io.ReadFull(stream, make([]byte, 7)); err != nil {
		t.Fatal(err)
	}
	if rx, tx := tun.Bytes(); rx != 7 || tx != 10 {
		t.Fatalf("Bytes = %d, %d; want 7, 10", rx, tx)
	}
	if rx, tx := tun.Take(); rx != 7 || tx != 10 {
		t.Fatalf("Take = %d, %d; want 7, 10", rx, tx)
	}
	if rx, tx := tun.Take(); rx != 0 || tx != 0 {
		t.Fatalf("second Take = %d, %d; want 0, 0", rx, tx)
	}
}
