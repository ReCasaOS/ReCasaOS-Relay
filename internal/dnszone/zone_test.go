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

// wantSOA checks the negative-caching SOA in the authority section.
func wantSOA(t *testing.T, m dnsmessage.Message) {
	t.Helper()
	if len(m.Authorities) != 1 || m.Authorities[0].Header.Name.String() != origin+"." {
		t.Fatalf("authority = %+v", m.Authorities)
	}
	soa, ok := m.Authorities[0].Body.(*dnsmessage.SOAResource)
	if !ok || soa.NS.String() != "ns."+origin+"." || soa.MinTTL != 60 || soa.Serial != 7200 {
		t.Fatalf("authority SOA = %+v", m.Authorities[0].Body)
	}
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
	wantSOA(t, m)
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
	wantSOA(t, m)
}

func TestNXDomainAndRefused(t *testing.T) {
	z := newZone()
	m := ask(t, z, "a.b.c."+origin, dnsmessage.TypeA)
	if m.RCode != dnsmessage.RCodeNameError || !m.Authoritative || len(m.Answers) != 0 {
		t.Fatalf("%+v", m)
	}
	wantSOA(t, m)
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

func TestHostileInput(t *testing.T) {
	z := newZone()
	ctx := context.Background()
	q := query(t, "boxa."+origin, dnsmessage.TypeA)
	for name, pkt := range map[string][]byte{
		"empty": nil, "short": q[:5], "truncated question": q[:15],
		"response bit": func() []byte { r := append([]byte(nil), q...); r[2] |= 0x80; return r }(),
	} {
		if out, err := z.Answer(ctx, pkt); err == nil {
			t.Errorf("%s: answered with %x", name, out)
		}
	}
	rcode := func(pkt []byte) dnsmessage.RCode {
		out, err := z.Answer(ctx, pkt)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(out); err != nil {
			t.Fatal(err)
		}
		return m.RCode
	}
	op := append([]byte(nil), q...)
	op[2] |= 4 << 3 // opcode NOTIFY
	if rc := rcode(op); rc != dnsmessage.RCodeNotImplemented {
		t.Errorf("opcode: %v", rc)
	}
	for _, n := range []byte{0, 2} {
		bad := append([]byte(nil), q...)
		bad[5] = n
		if rc := rcode(bad); rc != dnsmessage.RCodeFormatError {
			t.Errorf("QDCount %d: %v", n, rc)
		}
	}
}

type flakyListener struct {
	net.Listener
	failed bool
}

type tempErr struct{}

func (tempErr) Error() string { return "too many open files" }

func (l *flakyListener) Accept() (net.Conn, error) {
	if !l.failed {
		l.failed = true
		return nil, tempErr{}
	}
	return l.Listener.Accept()
}

func TestServeSurvivesTransientAcceptError(t *testing.T) {
	z := newZone()
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- z.Serve(ctx, pc, &flakyListener{Listener: l}) }()
	q := query(t, "boxa."+origin, dnsmessage.TypeA)
	tc, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	tc.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	var hdr [2]byte
	if _, err := io.ReadFull(tc, hdr[:]); err != nil {
		t.Fatalf("no answer after a transient Accept error: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPSLTXT(t *testing.T) {
	z := newZone()
	m := ask(t, z, "_psl."+origin, dnsmessage.TypeTXT)
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("unset: %+v", m)
	}
	wantSOA(t, m)
	z.PSLTXT = "https://github.com/publicsuffix/list/pull/1"
	m = ask(t, z, "_psl."+origin, dnsmessage.TypeTXT)
	if len(m.Answers) != 1 || m.Answers[0].Header.TTL != 300 || m.Answers[0].Body.(*dnsmessage.TXTResource).TXT[0] != z.PSLTXT {
		t.Fatalf("set: %+v", m.Answers)
	}
	if m = ask(t, z, "_psl.boxa."+origin, dnsmessage.TypeTXT); len(m.Answers) != 0 {
		t.Fatalf("deeper name answered: %+v", m.Answers)
	}
}
