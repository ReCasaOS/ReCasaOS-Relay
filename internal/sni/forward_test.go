package sni

import (
	"io"
	"net"
	"testing"
)

func TestForwardCopiesBothWays(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	type res struct{ ab, ba int64 }
	done := make(chan res)
	go func() { ab, ba := Forward(a2, b1); done <- res{ab, ba} }()

	go a1.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(b2, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("a->b %q %v", buf, err)
	}
	go b2.Write([]byte("pong!"))
	buf = make([]byte, 5)
	if _, err := io.ReadFull(a1, buf); err != nil || string(buf) != "pong!" {
		t.Fatalf("b->a %q %v", buf, err)
	}
	a1.Close()
	b2.Close()
	if r := <-done; r.ab != 4 || r.ba != 5 {
		t.Fatalf("counts %+v", r)
	}
}
