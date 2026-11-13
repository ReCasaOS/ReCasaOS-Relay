package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/journal"
	"github.com/ReCasaOS/recasaos-relay/internal/proxyproto"
	"github.com/ReCasaOS/recasaos-relay/internal/tunnel"
)

func testJournal(t *testing.T) (*journal.Writer, func() []journal.Entry) {
	dir := t.TempDir()
	w, err := journal.Open(dir, "share", time.Hour, 1<<20, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w, func() []journal.Entry {
		w.Close()
		files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
		var out []journal.Entry
		for _, f := range files {
			b, _ := os.ReadFile(f)
			dec := json.NewDecoder(bytes.NewReader(b))
			for {
				var e journal.Entry
				if dec.Decode(&e) != nil {
					break
				}
				out = append(out, e)
			}
		}
		return out
	}
}

func TestJournalPassAndClose(t *testing.T) {
	_, _, reg, box := rig(t)
	w, lines := testJournal(t)
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
		toTunnel(reg, newConnCap(tunnel.MaxStreams, "test"), nil, nil, w, "app.alpha.box.relay.test", "alpha", c, c)
	}()
	visitor, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	visitor.Write([]byte("ping"))
	in, err := box.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_, _, rest, err := proxyproto.ReadProxyV2(in)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadFull(rest, make([]byte, 4))
	in.Write([]byte("pong!"))
	io.ReadFull(visitor, make([]byte, 5))
	visitor.Close()
	in.Close()
	<-done

	got := lines()
	if len(got) != 2 || got[0].Act != "pass" || got[1].Act != "close" {
		t.Fatalf("lines = %+v, want pass then close", got)
	}
	for _, e := range got {
		if e.Src != "share" || e.Svc != "share" || e.IP != "127.0.0.1" || e.Host != "app.alpha.box.relay.test" {
			t.Errorf("line %+v: want src/svc share, ip 127.0.0.1, the full host", e)
		}
	}
	if got[1].In != 4 || got[1].Out != 5 {
		t.Errorf("close in/out = %d/%d, want 4/5", got[1].In, got[1].Out)
	}
}

func TestJournalCutLines(t *testing.T) {
	var s snapshot
	s.Manual.Address = []string{"203.0.113.7/32"}
	h := holderWith(snap(t, s))
	_, _, reg, _ := rig(t)
	w, lines := testJournal(t)
	v, c := tcpPair(t)
	defer v.Close()
	toTunnel(reg, newConnCap(5, "t"), h, nil, w, "app.alpha.box.relay.test", "alpha", fromAddr{c, testVisitor}, c)
	c.Close()

	c1, p1 := net.Pipe()
	c2, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	hold := make(chan struct{})
	var wg sync.WaitGroup
	other := &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}
	accept(&listOf{conns: []net.Conn{fromAddr{c1, other}, fromAddr{c2, other}}}, &wg, newConnCap(1, "test"), nil, w,
		func(net.Conn) { <-hold })
	close(hold)
	wg.Wait()

	got := lines()
	if len(got) != 2 {
		t.Fatalf("lines = %+v, want two cuts", got)
	}
	a, b := got[0], got[1]
	if a.Act != "cut" || a.Reason != "manual" || a.Source != "address" || a.Host != "app.alpha.box.relay.test" || a.IP != "203.0.113.7" {
		t.Errorf("filter cut = %+v", a)
	}
	if b.Act != "cut" || b.Reason != "cap" || b.Source != "ip" || b.Host != "" || b.IP != "203.0.113.9" {
		t.Errorf("cap cut = %+v", b)
	}
}

func TestJournalNotForRelayHost(t *testing.T) {
	_, _, reg, _ := rig(t)
	w, lines := testJournal(t)
	front, got := fakeFront(t)
	v, c := tcpPair(t)
	ch := clientHello("relay.test")
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer c.Close()
		handleTLS(filterCfg(front), reg, newConnCap(5, "t"), &filterHolder{}, nil, w, fromAddr{c, testVisitor})
	}()
	v.Write(ch)
	v.(*net.TCPConn).CloseWrite()
	io.Copy(io.Discard, v)
	<-done
	<-got
	if l := lines(); len(l) != 0 {
		t.Fatalf("lines for the relay host: %+v", l)
	}
}

// A flood past a cap must not fill the journal: the first refusal of a key is written at once, then at
// most one line per key per cutWindow carries the count of the refusals since; a key quiet for a whole
// window frees its slot. Past maxCutKeys keys, refusals go to one line with no address.
func TestJournalCapRefusalsSummarised(t *testing.T) {
	w, lines := testJournal(t)
	old := maxCutKeys
	maxCutKeys = 1
	defer func() { maxCutKeys = old }()
	cc := newConnCap(1, "t")
	c, p := net.Pipe()
	defer c.Close()
	defer p.Close()
	a := fromAddr{c, &net.TCPAddr{IP: net.ParseIP("203.0.113.9"), Port: 1}}
	b := fromAddr{c, &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 1}}
	t0 := time.Unix(1_800_000_000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	for i := 0; i < 5; i++ {
		cc.cuts.log(w, "203.0.113.9", peerIP(a), "", "cap", "ip", at(i))
	}
	cc.cuts.flush(w, at(9))  // window not over: nothing
	cc.cuts.flush(w, at(10)) // count 4
	cc.cuts.flush(w, at(20)) // quiet window: the slot is freed
	cc.cuts.log(w, "203.0.113.9", peerIP(a), "", "cap", "ip", at(21))
	cc.cuts.log(w, "198.51.100.1", peerIP(b), "", "cap", "ip", at(22)) // past the bound: aggregate
	cc.cuts.log(w, "198.51.100.1", peerIP(b), "", "cap", "ip", at(23))
	if n := len(cc.cuts.m); n > maxCutKeys+1 {
		t.Fatalf("%d keys kept, bound %d (+1 aggregate)", n, maxCutKeys)
	}
	cc.cuts.flush(w, at(32))

	got := lines()
	want := []struct {
		ip    string
		count int64
	}{{"203.0.113.9", 0}, {"203.0.113.9", 4}, {"203.0.113.9", 0}, {"", 0}, {"", 1}}
	if len(got) != len(want) {
		t.Fatalf("lines = %+v, want %d", got, len(want))
	}
	for i, e := range got {
		if e.Act != "cut" || e.Reason != "cap" || e.Source != "ip" || e.IP != want[i].ip || e.Count != want[i].count {
			t.Errorf("line %d = %+v, want ip %q count %d", i, e, want[i].ip, want[i].count)
		}
	}
}

// Filter cuts are summarised the same way, per key, reason and source: a blocked address hammering
// gives one line at once, then one with the count; another reason of the same address stays apart.
func TestJournalFilterCutsSummarised(t *testing.T) {
	var s snapshot
	s.Manual.Address = []string{"203.0.113.7/32"}
	h := holderWith(snap(t, s))
	_, _, reg, _ := rig(t)
	w, lines := testJournal(t)
	for i := 0; i < 3; i++ {
		v, c := tcpPair(t)
		toTunnel(reg, newConnCap(5, "t"), h, nil, w, "app.alpha.box.relay.test", "alpha", fromAddr{c, testVisitor}, c)
		c.Close()
		v.Close()
	}
	h.cuts.log(w, "203.0.113.7/32", "203.0.113.7", "app.alpha.box.relay.test", "feed", "x", time.Now())
	h.cuts.flush(w, time.Now().Add(cutWindow))

	got := lines()
	if len(got) != 3 {
		t.Fatalf("lines = %+v, want manual once, feed once, manual count 2", got)
	}
	for _, e := range got {
		if e.Act != "cut" || e.IP != "203.0.113.7" || e.Host != "app.alpha.box.relay.test" {
			t.Errorf("line %+v", e)
		}
	}
	if got[0].Reason != "manual" || got[0].Count != 0 || got[1].Reason != "feed" || got[1].Count != 0 ||
		got[2].Reason != "manual" || got[2].Source != "address" || got[2].Count != 2 {
		t.Errorf("lines = %+v", got)
	}
}
