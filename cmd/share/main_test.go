package main

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/ReCasaOS/recasaos-relay/internal/proxyproto"
)

type flakyListener struct {
	net.Listener
	calls int
	conn  net.Conn
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.calls++
	switch l.calls {
	case 1:
		return nil, errors.New("accept: too many open files")
	case 2:
		return l.conn, nil
	}
	return nil, net.ErrClosed
}

func TestAcceptSurvivesTemporaryError(t *testing.T) {
	c, peer := net.Pipe()
	defer peer.Close()
	served := make(chan struct{})
	var wg sync.WaitGroup
	accept(&flakyListener{conn: c}, &wg, newConnCap(1, "test"), nil, nil, func(net.Conn) { close(served) })
	wg.Wait()
	select {
	case <-served:
	default:
		t.Fatal("connection after a temporary Accept error was not served")
	}
}

// front listens like Caddy would and sends back what it received first: the header, then the payload.
func fakeFront(t *testing.T) (addr string, got chan []byte) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got = make(chan []byte, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		got <- b
	}()
	return l.Addr().String(), got
}

func forwardOnce(t *testing.T, front string, proxy bool, payload []byte) (client, server *net.TCPAddr) {
	t.Helper()
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
		toFront(c, front, proxy)
	}()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, server = c.LocalAddr().(*net.TCPAddr), l.Addr().(*net.TCPAddr)
	c.Write(payload)
	c.(*net.TCPConn).CloseWrite()
	io.Copy(io.Discard, c) // front closes after reading everything
	<-done
	return client, server
}

func TestForwardToFrontSendsProxyHeader(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: relay.test\r\n\r\n")
	front, got := fakeFront(t)
	client, server := forwardOnce(t, front, true, payload)
	b := <-got
	want := new(bytes.Buffer)
	if err := proxyproto.WriteV2(want, client, server); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, append(want.Bytes(), payload...)) {
		t.Fatalf("front received %q, want header for %v->%v then the payload", b, client, server)
	}
	src, dst, rest, err := proxyproto.ReadProxyV2(bytes.NewReader(b))
	if err != nil || src.String() != client.String() || dst.String() != server.String() {
		t.Fatalf("header parses to %v -> %v, %v; want %v -> %v", src, dst, err, client, server)
	}
	if p, _ := io.ReadAll(rest); !bytes.Equal(p, payload) {
		t.Fatalf("payload after header = %q", p)
	}

	front, got = fakeFront(t)
	forwardOnce(t, front, false, payload)
	if b := <-got; !bytes.Equal(b, payload) {
		t.Fatalf("without the flag the front received %q, want the client's own bytes", b)
	}
}

func TestProxyFlagDefaultsToTrue(t *testing.T) {
	t.Setenv("RELAY_HOST", "relay.test")
	t.Setenv("SHARE_DOMAIN", "box.relay.test")
	t.Setenv("FRONT_PROXY_PROTOCOL", "")
	if c, err := ConfigFromEnv(); err != nil || !c.FrontProxyProtocol {
		t.Fatalf("default: %+v, %v", c, err)
	}
	t.Setenv("FRONT_PROXY_PROTOCOL", "false")
	if c, err := ConfigFromEnv(); err != nil || c.FrontProxyProtocol {
		t.Fatalf("false: %+v, %v", c, err)
	}
	t.Setenv("FRONT_PROXY_PROTOCOL", "maybe")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("garbage accepted")
	}
}
