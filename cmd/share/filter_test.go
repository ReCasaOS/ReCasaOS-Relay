package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"testing"
	"time"
)

func TestPrefixSetContains(t *testing.T) {
	s := newPrefixSet([]string{
		"10.0.0.0/25", "10.0.0.128/25", // adjacent: merged
		"10.0.1.0/24", "10.0.1.64/26", // nested
		"192.0.2.7/32", "not a prefix", "",
	})
	for _, c := range []struct {
		a    string
		want bool
	}{
		{"10.0.0.0", true}, {"10.0.0.255", true}, {"10.0.1.0", true}, {"10.0.1.255", true},
		{"10.0.2.0", false}, {"9.255.255.255", false},
		{"192.0.2.7", true}, {"192.0.2.6", false}, {"192.0.2.8", false},
		{"::ffff:192.0.2.7", true}, // an IPv4-mapped address is the IPv4 one
	} {
		if got := s.contains(netip.MustParseAddr(c.a)); got != c.want {
			t.Errorf("contains(%s) = %v, want %v", c.a, got, c.want)
		}
	}
	if len(s.v4) != 2 {
		t.Errorf("v4 ranges = %d, want 2 after merging", len(s.v4))
	}

	v6 := newPrefixSet([]string{"2001:db8::/32", "2001:db9::/32", "2001:db8:1::/48", "::1/128"})
	if len(v6.v6) != 2 {
		t.Errorf("v6 ranges = %d, want 2 after merging", len(v6.v6))
	}
	for a, want := range map[string]bool{
		"2001:db7:ffff:ffff:ffff:ffff:ffff:ffff": false, "2001:db8::": true,
		"2001:db9:ffff:ffff:ffff:ffff:ffff:ffff": true, "2001:dba::": false, "::1": true, "::2": false,
		"1.2.3.4": false,
	} {
		if got := v6.contains(netip.MustParseAddr(a)); got != want {
			t.Errorf("v6 contains(%s) = %v, want %v", a, got, want)
		}
	}
	all := newPrefixSet([]string{"0.0.0.0/0", "::/0"})
	for _, a := range []string{"0.0.0.0", "255.255.255.255", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"} {
		if !all.contains(netip.MustParseAddr(a)) {
			t.Errorf("/0 does not contain %s", a)
		}
	}
	if newPrefixSet(nil).contains(netip.MustParseAddr("1.2.3.4")) {
		t.Error("empty set contains an address")
	}
}

func snap(t *testing.T, s snapshot) *filter {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseFilter(b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestDecideOrder(t *testing.T) {
	var s snapshot
	s.Allow = []string{"198.51.100.0/24"}
	s.Manual.Address = []string{"198.51.100.5/32", "203.0.113.1/32"}
	s.Manual.Range = []string{"203.0.114.0/24"}
	s.Manual.ASN = []string{"203.0.115.0/24"}
	s.Manual.Country = []string{"203.0.116.0/24"}
	s.External = map[string][]string{"FireHOL level 1": {"192.0.2.0/24"}}
	s.Community.Address = []string{"192.0.3.1/32"}
	s.Community.Range = []string{"192.0.4.0/24"}
	s.Names = map[string]nameFilter{
		"off":  {},
		"on":   {Filter: true},
		"both": {Filter: true, Community: true},
		"comm": {Community: true}, // community without filter: nothing
	}
	s.Suspended = []string{"badname", "on"}
	f := snap(t, s)
	for _, c := range []struct{ addr, name, reason, source string }{
		{"198.51.100.5", "both", "", ""}, // allow wins over manual
		{"203.0.113.1", "off", "manual", "address"},
		{"203.0.114.9", "off", "manual", "range"},
		{"203.0.115.9", "off", "manual", "asn"},
		{"203.0.116.9", "off", "manual", "country"},
		{"1.1.1.1", "badname", "suspended", ""},    // suspended even for a name with no row
		{"203.0.113.1", "on", "manual", "address"}, // manual before suspended
		{"1.1.1.1", "on", "suspended", ""},
		{"192.0.2.9", "off", "", ""},  // feed, filter off
		{"192.0.2.9", "comm", "", ""}, // feed, filter off (community alone)
		{"192.0.2.9", "both", "external", "FireHOL level 1"},
		{"192.0.3.1", "both", "community", "address"},
		{"192.0.4.77", "both", "community", "range"},
		{"192.0.3.1", "off", "", ""},
		{"192.0.3.1", "comm", "", ""}, // community needs the filter too
		{"192.0.2.9", "gone", "", ""}, // old box: name absent, only manual and suspended
		{"192.0.3.1", "gone", "", ""},
		{"203.0.114.9", "gone", "manual", "range"},
	} {
		r, src := f.decide(netip.MustParseAddr(c.addr), c.name)
		if r != c.reason || src != c.source {
			t.Errorf("decide(%s, %s) = %q/%q, want %q/%q", c.addr, c.name, r, src, c.reason, c.source)
		}
	}
	// filter on, community off: the community list does not apply
	if r, _ := f.decide(netip.MustParseAddr("192.0.3.1"), "on"); r != "suspended" {
		t.Errorf("name on, community address: %q, want suspended only", r)
	}
	s.Suspended = nil
	if r, _ := snap(t, s).decide(netip.MustParseAddr("192.0.3.1"), "on"); r != "" {
		t.Errorf("name on, community address, not suspended: %q, want pass", r)
	}
}

// hello records the bytes of a TLS client's first flight.
type hello struct{ b []byte }

func (h *hello) Write(p []byte) (int, error)      { h.b = append(h.b, p...); return len(p), nil }
func (h *hello) Read([]byte) (int, error)         { return 0, io.EOF }
func (h *hello) Close() error                     { return nil }
func (h *hello) LocalAddr() net.Addr              { return nil }
func (h *hello) RemoteAddr() net.Addr             { return nil }
func (h *hello) SetDeadline(time.Time) error      { return nil }
func (h *hello) SetReadDeadline(time.Time) error  { return nil }
func (h *hello) SetWriteDeadline(time.Time) error { return nil }

func clientHello(name string) []byte {
	h := &hello{}
	tls.Client(h, &tls.Config{ServerName: name, InsecureSkipVerify: true}).Handshake()
	return h.b
}

func filterCfg(front string) Config {
	return Config{RelayHost: "relay.test", ShareDomain: "box.relay.test", FrontTLS: front, PeekTimeout: 2 * time.Second}
}

func holderWith(f *filter) *filterHolder {
	h := &filterHolder{}
	h.cur.Store(f)
	return h
}

var testVisitor = &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 40000}

func TestNoSnapshotLetsThrough(t *testing.T) {
	_, _, reg, box := rig(t)
	v, c := tcpPair(t)
	defer v.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer c.Close()
		handleTLS(filterCfg("127.0.0.1:1"), reg, newConnCap(5, "t"), &filterHolder{}, fromAddr{c, testVisitor})
	}()
	v.Write(clientHello("app.alpha.box.relay.test"))
	in, err := box.Accept()
	if err != nil {
		t.Fatal("no stream into the tunnel with no filter yet: ", err)
	}
	in.Close()
	v.Close()
	<-done
}

func TestRelayHostNeverFiltered(t *testing.T) {
	var s snapshot
	s.Manual.Range = []string{"0.0.0.0/0"}
	h := holderWith(snap(t, s))
	_, _, reg, box := rig(t)

	// the relay host reaches front
	front, got := fakeFront(t)
	v, c := tcpPair(t)
	ch := clientHello("relay.test")
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer c.Close()
		handleTLS(filterCfg(front), reg, newConnCap(5, "t"), h, fromAddr{c, testVisitor})
	}()
	v.Write(ch)
	v.(*net.TCPConn).CloseWrite()
	io.Copy(io.Discard, v)
	<-done
	if b := <-got; string(b) != string(ch) {
		t.Fatalf("front got %d bytes, want the %d of the hello", len(b), len(ch))
	}
	v.Close()

	// a share name: closed with no byte written, nothing opened in the tunnel
	v, c = tcpPair(t)
	defer v.Close()
	done = make(chan struct{})
	go func() {
		defer close(done)
		defer c.Close()
		handleTLS(filterCfg("127.0.0.1:1"), reg, newConnCap(5, "t"), h, fromAddr{c, testVisitor})
	}()
	v.Write(clientHello("app.alpha.box.relay.test"))
	if b, _ := io.ReadAll(v); len(b) != 0 {
		t.Fatalf("refused visitor received %d bytes", len(b))
	}
	<-done
	got2 := make(chan struct{})
	go func() {
		if s, err := box.Accept(); err == nil {
			s.Close()
			close(got2)
		}
	}()
	select {
	case <-got2:
		t.Fatal("refused visitor reached the tunnel")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestKeepsSnapshotWhenEnrolmentDown(t *testing.T) {
	f, url, _, _ := rig(t)
	var s snapshot
	s.Version = "v1"
	s.Manual.Address = []string{"203.0.113.7/32"}
	b, _ := json.Marshal(s)
	f.mu.Lock()
	f.filterVersion, f.filterBody = "v1", string(b)
	f.mu.Unlock()

	h := &filterHolder{}
	a := netip.MustParseAddr("203.0.113.7")
	h.poll(context.Background(), url)
	if cur := h.get(); cur == nil {
		t.Fatal("no filter after a poll")
	} else if r, _ := cur.decide(a, "x"); r != "manual" {
		t.Fatalf("decide = %q", r)
	}
	h.poll(context.Background(), url) // 304
	f.mu.Lock()
	if f.notModified != 1 {
		t.Fatalf("304 answers = %d, want 1 (the second poll must send If-None-Match)", f.notModified)
	}
	f.mu.Unlock()
	f.mu.Lock()
	f.filterStatus = 500
	f.mu.Unlock()
	h.poll(context.Background(), url)
	h.poll(context.Background(), "http://127.0.0.1:1") // unreachable
	if cur := h.get(); cur == nil {
		t.Fatal("snapshot dropped after failures")
	} else if r, _ := cur.decide(a, "x"); r != "manual" {
		t.Fatalf("after failures decide = %q, want the snapshot kept", r)
	}
}

func TestFilterPollHasItsOwnTimeout(t *testing.T) {
	if filterClient.Timeout < 60*time.Second {
		t.Fatalf("filterClient timeout %v, want >= 60s", filterClient.Timeout)
	}
	f, url, _, _ := rig(t)
	f.mu.Lock()
	f.filterVersion, f.filterBody, f.filterDelay = "v1", `{"version":"v1"}`, 300*time.Millisecond
	f.mu.Unlock()
	old := filterClient
	defer func() { filterClient = old }()
	filterClient = &http.Client{Timeout: 50 * time.Millisecond}
	h := &filterHolder{}
	h.poll(context.Background(), url)
	if h.get() != nil {
		t.Fatal("slow answer past the filter client's timeout was accepted")
	}
	filterClient = &http.Client{Timeout: 5 * time.Second}
	h.poll(context.Background(), url)
	if h.get() == nil {
		t.Fatal("slow answer within the filter client's timeout was not taken")
	}
}

func TestRemoteAddr(t *testing.T) {
	for _, c := range []struct {
		a    net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.ParseIP("203.0.113.7")}, "203.0.113.7"},
		{&net.TCPAddr{IP: net.ParseIP("::ffff:203.0.113.7")}, "203.0.113.7"},
		{&net.TCPAddr{IP: net.ParseIP("2001:db8::1")}, "2001:db8::1"},
	} {
		a, ok := remoteAddr(fromAddr{ra: c.a})
		if !ok || a.String() != c.want {
			t.Errorf("remoteAddr(%v) = %v, %v; want %s", c.a, a, ok, c.want)
		}
	}
	if _, ok := remoteAddr(fromAddr{ra: &net.UnixAddr{Name: "x", Net: "unix"}}); ok {
		t.Error("non-TCP address accepted")
	}
}

func BenchmarkDecide500k(b *testing.B) {
	rng := rand.New(rand.NewPCG(1, 2))
	entries := make([]string, 500_000)
	for i := range entries {
		a := rng.Uint32()
		entries[i] = netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)}).String() + "/32"
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	s := newPrefixSet(entries)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	runtime.KeepAlive(entries) // live in both readings: the delta is the set alone
	heap := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	b.Logf("prefixSet of %d entries: %d ranges, heap %d bytes (%.1f MiB)", len(entries), len(s.v4), heap, float64(heap)/(1<<20))
	f := &filter{ext: []feedSet{{name: "big", set: s}}, names: map[string]nameFilter{"n": {Filter: true}}}
	probes := make([]netip.Addr, 1024)
	for i := range probes {
		a := rng.Uint32()
		probes[i] = netip.AddrFrom4([4]byte{byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a)})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.decide(probes[i%len(probes)], "n")
	}
	runtime.KeepAlive(s)
}
