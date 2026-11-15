package main

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

func noBoxConn(t *testing.T) net.Conn {
	t.Helper()
	c, p := net.Pipe()
	t.Cleanup(func() { c.Close(); p.Close() })
	return fromAddr{c, testVisitor}
}

func TestNoBoxCutsLongLabel(t *testing.T) {
	e := newEvents()
	noBox(nil, e, nil, strings.Repeat("a", 300)+".box.relay.test", strings.Repeat("a", 300), noBoxConn(t))
	if len(e.unkQ) != 1 || len(e.unkQ[0].Name) > 64 {
		t.Fatalf("unknown = %+v, want one name of at most 64 bytes", e.unkQ)
	}
}

func TestNoBoxSkipsABannedAddress(t *testing.T) {
	var s snapshot
	s.Version = "v1"
	s.Manual.Address = []string{"203.0.113.7/32"}
	e := newEvents()
	noBox(holderWith(snap(t, s)), e, nil, "x.box.relay.test", "x", noBoxConn(t))
	if len(e.unkQ) != 0 {
		t.Fatalf("unknown = %+v, want none for a banned address", e.unkQ)
	}
	var a snapshot // an automatic ban refuses every share name too: nothing to report either
	a.Version = "v2"
	a.Auto.Address = []string{"203.0.113.7/32"}
	noBox(holderWith(snap(t, a)), e, nil, "x.box.relay.test", "x", noBoxConn(t))
	if len(e.unkQ) != 0 {
		t.Fatalf("unknown = %+v, want none for an automatically banned address", e.unkQ)
	}
	noBox(&filterHolder{}, e, nil, "x.box.relay.test", "x", noBoxConn(t)) // no filter yet: reported
	noBox(nil, e, nil, "y.box.relay.test", "y", noBoxConn(t))             // nil holder: no panic
	if len(e.unkQ) != 2 {
		t.Fatalf("unknown = %+v, want 2", e.unkQ)
	}
}

func TestTrimEvictsUnknownBeforeSeen(t *testing.T) {
	e := newEvents()
	for i := range maxEvents {
		e.unknown("203.0.113.7/32", "n"+strconv.Itoa(i))
	}
	e.seen("203.0.113.8/32", "0")
	e.box("203.0.113.9/32")
	if len(e.seenQ) != 1 || len(e.boxQ) != 1 || len(e.unkQ) != maxEvents-2 || e.unkQ[0].Name != "n2" {
		t.Fatalf("seen %d, boxes %d, unknown %d (first %+v)", len(e.seenQ), len(e.boxQ), len(e.unkQ), e.unkQ[0])
	}
}
