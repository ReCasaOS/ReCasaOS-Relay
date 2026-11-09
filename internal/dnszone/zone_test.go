package dnszone

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const origin = "box.relay.test"

func newZone() *Zone {
	return &Zone{
		Origin: origin,
		A:      netip.MustParseAddr("192.0.2.7"),
		AAAA:   netip.MustParseAddr("2001:db8::7"),
		TXT: func(_ context.Context, n string) (string, bool, error) {
			if n == "_acme-challenge.boxa."+origin {
				return "tok-123", true, nil
			}
			return "", false, nil
		},
		Now: func() time.Time { return time.Unix(7200*3600+5, 0) },
	}
}

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func ask(t *testing.T, z *Zone, name string, typ dnsmessage.Type) dnsmessage.Message {
	t.Helper()
	out, err := z.Answer(context.Background(), query(t, name, typ))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) > 512 {
		t.Fatalf("response is %d bytes", len(out))
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatal(err)
	}
	if m.ID != 0x1234 || !m.Response || !m.RecursionDesired {
		t.Fatalf("header = %+v", m.Header)
	}
	return m
}

func TestApexSOAandNS(t *testing.T) {
	z := newZone()
	m := ask(t, z, origin, dnsmessage.TypeSOA)
	if !m.Authoritative || m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("%+v", m)
	}
	soa := m.Answers[0].Body.(*dnsmessage.SOAResource)
	if soa.NS.String() != "ns."+origin+"." || soa.MBox.String() != "hostmaster."+origin+"." || soa.Serial != 7200 ||
		soa.Refresh != 3600 || soa.Retry != 600 || soa.Expire != 86400 || soa.MinTTL != 60 {
		t.Fatalf("soa = %+v", soa)
	}
	m = ask(t, z, origin, dnsmessage.TypeNS)
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.NSResource).NS.String() != "ns."+origin+"." {
		t.Fatalf("%+v", m.Answers)
	}
	m = ask(t, z, "ns."+origin, dnsmessage.TypeA)
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 7} {
		t.Fatalf("%+v", m.Answers)
	}
}

func TestWildcardAUnderZone(t *testing.T) {
	z := newZone()
	for _, n := range []string{"boxa." + origin, "app.boxa." + origin, "APP.BoxA." + origin} {
		m := ask(t, z, n, dnsmessage.TypeA)
		if !m.Authoritative || len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{192, 0, 2, 7} ||
			m.Answers[0].Header.TTL != 300 {
			t.Fatalf("%s: %+v", n, m)
		}
		if m.Answers[0].Header.Name.String() != n+"." {
			t.Fatalf("owner = %s, want query case %s", m.Answers[0].Header.Name, n)
		}
	}
	m := ask(t, z, "app.boxa."+origin, dnsmessage.TypeAAAA)
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA != netip.MustParseAddr("2001:db8::7").As16() {
		t.Fatalf("%+v", m.Answers)
	}
	z.AAAA = netip.Addr{}
	m = ask(t, z, "app.boxa."+origin, dnsmessage.TypeAAAA)
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("no AAAA configured: %+v", m)
	}
}

func TestTXTOnlyForAcmeChallenge(t *testing.T) {
	z := newZone()
	m := ask(t, z, "_acme-challenge.boxa."+origin, dnsmessage.TypeTXT)
	if len(m.Answers) != 1 || m.Answers[0].Header.TTL != 60 || m.Answers[0].Body.(*dnsmessage.TXTResource).TXT[0] != "tok-123" {
		t.Fatalf("%+v", m.Answers)
	}
	m = ask(t, z, "_acme-challenge.boxb."+origin, dnsmessage.TypeTXT)
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("unknown value: %+v", m)
	}
	m = ask(t, z, "foo.boxa."+origin, dnsmessage.TypeTXT)
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("foo.boxa: %+v", m)
	}
}

func TestNXDomainAndRefused(t *testing.T) {
	z := newZone()
	m := ask(t, z, "a.b.c."+origin, dnsmessage.TypeA)
	if m.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 || len(m.Authorities) != 1 || m.Authorities[0].Header.Type != dnsmessage.TypeSOA {
		t.Fatalf("%+v", m)
	}
	m = ask(t, z, "example.org", dnsmessage.TypeA)
	if m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("%+v", m)
	}
	m = ask(t, z, "xbox.relay.test", dnsmessage.TypeA)
	if m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("suffix without dot boundary: %+v", m)
	}
}

func TestServeUDPAndTCP(t *testing.T) {
	z := newZone()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- z.Serve(ctx, pc, l) }()
	q := query(t, "app.boxa."+origin, dnsmessage.TypeA)
	want, _ := z.Answer(ctx, q)

	uc, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.SetDeadline(time.Now().Add(5 * time.Second))
	uc.Write(q)
	buf := make([]byte, 1024)
	n, err := uc.Read(buf)
	if err != nil || string(buf[:n]) != string(want) {
		t.Fatalf("udp: %v %x", err, buf[:n])
	}

	tc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 2; i++ { // two queries on one connection
		tc.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
		var hdr [2]byte
		if _, err := io.ReadFull(tc, hdr[:]); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(tc, got); err != nil || string(got) != string(want) {
			t.Fatalf("tcp: %v %x", err, got)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not stop")
	}
}
