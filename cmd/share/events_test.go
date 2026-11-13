package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 13, 10, 20, 0, 0, time.UTC)

func clockedEvents(now *time.Time) *events {
	e := newEvents()
	e.now = func() time.Time { return *now }
	return e
}

func flushed(t *testing.T, e *events) []eventsBody {
	t.Helper()
	f := &fakeEnrolment{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	e.flush(context.Background(), srv.URL+"/internal/share/events")
	return f.eventPosts
}

func TestSeenOncePerTenMinutes(t *testing.T) {
	now := t0
	e := clockedEvents(&now)
	e.seen("203.0.113.7/32", "7")
	e.seen("203.0.113.7/32", "7")
	e.seen("", "7")
	e.seen("203.0.113.7/32", "8") // another box: its own entry
	now = now.Add(9 * time.Minute)
	e.seen("203.0.113.7/32", "7")
	if p := flushed(t, e); len(p) != 1 || len(p[0].Seen) != 2 {
		t.Fatalf("posts = %+v, want one post with 2 seen", p)
	}
	now = now.Add(2 * time.Minute) // 11 minutes after the first
	e.seen("203.0.113.7/32", "7")
	if p := flushed(t, e); len(p) != 1 || len(p[0].Seen) != 1 || p[0].Seen[0] != (seenItem{"203.0.113.7/32", "7"}) {
		t.Fatalf("posts = %+v, want the pair again after 10 minutes", p)
	}
	if len(e.seenAt) != 1 { // the 8 pair, older than 10 minutes, was pruned by the flush
		t.Fatalf("seenAt = %v, want pruned", e.seenAt)
	}
}

func TestRefusalsCountedPerHour(t *testing.T) {
	now := t0
	e := clockedEvents(&now)
	for range 3 {
		e.refused("mybox", "203.0.113.7/32", "external", "FireHOL level 1")
	}
	e.refused("", "", "cap", "ip") // no key (private source): not recorded
	now = now.Add(time.Hour)
	e.refused("mybox", "203.0.113.7/32", "external", "FireHOL level 1")
	p := flushed(t, e)
	if len(p) != 1 || len(p[0].Refusals) != 2 {
		t.Fatalf("posts = %+v, want one post with 2 rows", p)
	}
	r := p[0].Refusals
	if r[0] != (refItem{"2026-11-13T10:00:00Z", "mybox", "203.0.113.7/32", "external", "FireHOL level 1", 3}) ||
		r[1].Hour != "2026-11-13T11:00:00Z" || r[1].Count != 1 {
		t.Fatalf("rows = %+v", r)
	}
}

func TestFlushRetriesThenDropsOldest(t *testing.T) {
	now := t0
	e := clockedEvents(&now)
	f := &fakeEnrolment{eventsStatus: http.StatusBadGateway}
	srv := httptest.NewServer(f)
	defer srv.Close()
	url := srv.URL + "/internal/share/events"
	for i := range maxEvents + 5 {
		e.seen("203.0.113.7/32", strconv.Itoa(i))
	}
	e.flush(context.Background(), url) // fails: everything is kept, bounded
	e.refused("mybox", "203.0.113.7/32", "cap", "ip-box")
	f.mu.Lock()
	f.eventsStatus = 0
	f.mu.Unlock()
	e.flush(context.Background(), url)
	f.mu.Lock()
	defer f.mu.Unlock()
	var seen, refs int
	nodes := map[string]bool{}
	for _, b := range f.eventPosts {
		if n := len(b.Seen) + len(b.Refusals); n > eventsPerPost {
			t.Fatalf("a post held %d items", n)
		}
		seen, refs = seen+len(b.Seen), refs+len(b.Refusals)
		for _, s := range b.Seen {
			nodes[s.NodeID] = true
		}
	}
	if seen+refs != maxEvents || refs != 1 {
		t.Fatalf("delivered %d seen + %d refusals, want %d items with the refusal kept", seen, refs, maxEvents)
	}
	if nodes["0"] || !nodes[strconv.Itoa(maxEvents+4)] {
		t.Fatal("want the oldest seen dropped and the newest kept")
	}
}

func TestFlushDropsABatchAnswered4xx(t *testing.T) {
	now := t0
	e := clockedEvents(&now)
	f := &fakeEnrolment{eventsStatus: http.StatusBadRequest}
	srv := httptest.NewServer(f)
	defer srv.Close()
	e.seen("203.0.113.7/32", "7")
	e.flush(context.Background(), srv.URL+"/internal/share/events")
	f.mu.Lock()
	f.eventsStatus = 0
	f.mu.Unlock()
	e.flush(context.Background(), srv.URL+"/internal/share/events")
	if len(f.eventPosts) != 0 {
		t.Fatalf("posts = %+v, want the refused batch dropped, not resent", f.eventPosts)
	}
}

func TestEventKey(t *testing.T) {
	for _, c := range []struct{ ip, want string }{
		{"203.0.113.7", "203.0.113.7/32"},
		{"::ffff:203.0.113.7", "203.0.113.7/32"},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"10.0.0.1", ""}, {"127.0.0.1", ""}, {"::1", ""}, {"fe80::1", ""}, {"0.0.0.0", ""},
		{"100.64.0.1", ""}, {"224.0.0.1", ""}, {"fd00::1", ""},
	} {
		if got := connKey(fromAddr{ra: &net.TCPAddr{IP: net.ParseIP(c.ip)}}); got != c.want {
			t.Errorf("connKey(%s) = %q, want %q", c.ip, got, c.want)
		}
	}
}

func TestEventsConcurrent(t *testing.T) {
	e := newEvents()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				e.seen("203.0.113.7/32", strconv.Itoa(i))
				e.refused("b", "203.0.113.7/32", "cap", "ip")
			}
		}()
	}
	wg.Wait()
}

func TestCapRefusalCounted(t *testing.T) {
	c1, p1 := net.Pipe()
	c2, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	visitor := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 40000}
	hold := make(chan struct{})
	var wg sync.WaitGroup
	e := newEvents()
	accept(&listOf{conns: []net.Conn{fromAddr{c1, visitor}, fromAddr{c2, visitor}}}, &wg, newConnCap(1, "test"), e,
		func(net.Conn) { <-hold })
	close(hold)
	wg.Wait()
	p := flushed(t, e)
	if len(p) != 1 || len(p[0].Refusals) != 1 || p[0].Refusals[0].Name != "" || p[0].Refusals[0].Key != "203.0.113.7/32" ||
		p[0].Refusals[0].Reason != "cap" || p[0].Refusals[0].Source != "ip" || p[0].Refusals[0].Count != 1 {
		t.Fatalf("posts = %+v, want one cap/ip refusal with no name", p)
	}
}

func TestVisitorSeenOnceStreamIsOpen(t *testing.T) {
	_, _, reg, box := rig(t)
	visitor := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}
	perBox, e := newConnCap(1, "test"), newEvents()
	v1, c1 := tcpPair(t)
	defer v1.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer c1.Close()
		toTunnel(reg, perBox, e, "alpha", fromAddr{c1, visitor}, c1)
	}()
	in, err := box.Accept()
	if err != nil {
		t.Fatal(err)
	}
	v2, c2 := tcpPair(t) // same address, past the per-box cap
	defer v2.Close()
	toTunnel(reg, perBox, e, "alpha", fromAddr{c2, visitor}, c2)
	c2.Close()
	in.Close()
	v1.Close()
	<-done
	p := flushed(t, e)
	if len(p) != 1 || len(p[0].Seen) != 1 || p[0].Seen[0] != (seenItem{"203.0.113.9/32", "7"}) ||
		len(p[0].Refusals) != 1 || p[0].Refusals[0].Name != "alpha" || p[0].Refusals[0].Source != "ip-box" {
		t.Fatalf("posts = %+v, want seen (key, node 7) and one cap/ip-box refusal for alpha", p)
	}
}
