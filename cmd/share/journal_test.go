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
