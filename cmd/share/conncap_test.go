package main

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestConnCapCountsPerKey(t *testing.T) {
	c := newConnCap(2, "test")
	if !c.acquire("a") || !c.acquire("a") {
		t.Fatal("refused under the cap")
	}
	if c.acquire("a") {
		t.Fatal("third connection of a was let through")
	}
	if !c.acquire("b") {
		t.Fatal("a's count refused b")
	}
	c.release("a")
	if !c.acquire("a") {
		t.Fatal("released slot not given back")
	}
	c.release("a")
	c.release("a")
	c.release("b")
	if len(c.open) != 0 {
		t.Fatalf("keys left with no open connection: %v", c.open)
	}
}

func TestIPKey(t *testing.T) {
	for _, tc := range []struct{ ip, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"::ffff:203.0.113.7", "203.0.113.7"},
		{"2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"},
		{"2001:db8:1:2:bbbb::9", "2001:db8:1:2::/64"},
		{"127.0.0.1", ""}, // uncapped: loopback, private, link-local (Docker's proxy, the relay's LAN)
		{"10.1.2.3", ""},
		{"172.17.0.1", ""},
		{"192.168.1.20", ""},
		{"fd00::1", ""},
		{"fe80::1", ""},
		{"::1", ""},
	} {
		if got := ipKey(&net.TCPAddr{IP: net.ParseIP(tc.ip), Port: 1234}); got != tc.want {
			t.Errorf("ipKey(%s) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

// listOf hands out conns, then reports itself closed.
type listOf struct {
	net.Listener
	conns []net.Conn
}

func (l *listOf) Accept() (net.Conn, error) {
	if len(l.conns) == 0 {
		return nil, net.ErrClosed
	}
	c := l.conns[0]
	l.conns = l.conns[1:]
	return c, nil
}

func TestAcceptRefusesPastPerIPCap(t *testing.T) {
	c1, p1 := net.Pipe() // pipes all share the address "pipe": one client
	c2, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	hold, handled := make(chan struct{}), make(chan net.Conn, 2)
	var wg sync.WaitGroup
	accept(&listOf{conns: []net.Conn{c1, c2}}, &wg, newConnCap(1, "test"), nil, func(c net.Conn) { handled <- c; <-hold })
	p2.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := p2.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("second connection of the same client: %v, want it closed", err)
	}
	close(hold)
	wg.Wait()
	if len(handled) != 1 || <-handled != c1 {
		t.Fatal("want only the first connection served")
	}
}

// fromAddr is a conn whose client address is ra: tcpPair's 127.0.0.1 is not capped.
type fromAddr struct {
	net.Conn
	ra net.Addr
}

func (c fromAddr) RemoteAddr() net.Addr { return c.ra }

func TestVisitorPastPerBoxCapIsTurnedAway(t *testing.T) {
	_, _, reg, box := rig(t)
	perBox := newConnCap(1, "test")
	visitor := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 40000}
	via := func(c net.Conn, done chan struct{}) {
		defer close(done)
		defer c.Close()
		toTunnel(reg, perBox, nil, nil, "alpha", fromAddr{c, visitor}, c)
	}

	v1, c1 := tcpPair(t)
	defer v1.Close()
	first := make(chan struct{})
	go via(c1, first)
	in, err := box.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	v2, c2 := tcpPair(t)
	defer v2.Close()
	second := make(chan struct{})
	go via(c2, second)
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("second stream of the same address into the box was not turned away at once")
	}

	v1.Close()
	in.Close()
	<-first
	v3, c3 := tcpPair(t)
	third := make(chan struct{})
	go via(c3, third)
	in3, err := box.Accept()
	if err != nil {
		t.Fatalf("slot not given back after the first visitor left: %v", err)
	}
	in3.Close()
	v3.Close()
	<-third // not left running into a later test that changes idleTimeout
}
