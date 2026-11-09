package sni

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// chunkConn writes in 2-byte pieces and remembers everything it wrote.
type chunkConn struct {
	net.Conn
	mu  sync.Mutex
	got []byte
}

func (c *chunkConn) Write(p []byte) (int, error) {
	for i := 0; i < len(p); i += 2 {
		j := min(i+2, len(p))
		if _, err := c.Conn.Write(p[i:j]); err != nil {
			return i, err
		}
		c.mu.Lock()
		c.got = append(c.got, p[i:j]...)
		c.mu.Unlock()
	}
	return len(p), nil
}

func TestPeekServerNameAcrossWritesAndTimeout(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	cc := &chunkConn{Conn: cli}
	go tls.Client(cc, &tls.Config{ServerName: "app.boxa.box.relay.test", InsecureSkipVerify: true}).Handshake()

	name, replay, err := PeekServerName(srv, 2*time.Second)
	if err != nil || name != "app.boxa.box.relay.test" {
		t.Fatalf("name=%q err=%v", name, err)
	}
	cc.mu.Lock()
	want := append([]byte(nil), cc.got...)
	cc.mu.Unlock()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(replay, got); err != nil || string(got) != string(want) {
		t.Fatalf("replay differs (err=%v)", err)
	}

	// A silent peer: the whole peek is bounded by the timeout.
	silent, other := net.Pipe()
	defer silent.Close()
	defer other.Close()
	start := time.Now()
	if _, _, err := PeekServerName(silent, 100*time.Millisecond); err == nil {
		t.Fatal("no error on a silent conn")
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("took %v", d)
	}
}

func TestNonTLSGoesToFront(t *testing.T) {
	cli, srv := net.Pipe()
	defer cli.Close()
	defer srv.Close()
	const req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
	go cli.Write([]byte(req))
	_, replay, err := PeekServerName(srv, time.Second)
	if !errors.Is(err, ErrNotTLS) {
		t.Fatalf("err=%v", err)
	}
	got := make([]byte, len(req))
	if _, err := io.ReadFull(replay, got); err != nil || string(got) != req {
		t.Fatalf("replay %q err=%v", got, err)
	}
}
