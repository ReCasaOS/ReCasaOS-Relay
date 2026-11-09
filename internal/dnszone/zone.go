// Package dnszone is a tiny authoritative DNS server for the zone delegated to the relay
// (box.<domain>): every name of one or two labels under it resolves to the relay, and the ACME
// DNS-01 TXT records come from a lookup function. No recursion, no zone transfer, no EDNS.
package dnszone

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const maxUDP = 512

// Zone answers for Origin (no trailing dot, e.g. "box.recasaos.org").
type Zone struct {
	Origin string
	A      netip.Addr // IPv4 of the relay
	AAAA   netip.Addr // optional; the zero Addr means none
	// TXT is given the full lowercase query name without trailing dot and returns the value to publish.
	TXT func(ctx context.Context, name string) (string, bool, error)
	Now func() time.Time // default time.Now
}

// Answer turns one query (wire format) into its response. An error means the packet is not a
// query worth answering (garbage): the caller drops it.
func (z *Zone) Answer(ctx context.Context, msg []byte) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	if h.Response {
		return nil, errors.New("not a query")
	}
	origin := strings.ToLower(strings.TrimSuffix(z.Origin, "."))
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	rcode := dnsmessage.RCodeSuccess
	var answers []dnsmessage.Resource
	soa := false // SOA in authority: negative answers
	apex := name == origin
	rel := strings.TrimSuffix(name, "."+origin)
	switch {
	case h.OpCode != 0:
		rcode = dnsmessage.RCodeNotImplemented
	case !apex && rel == name: // outside the zone
		rcode = dnsmessage.RCodeRefused
	case q.Class != dnsmessage.ClassINET && q.Class != dnsmessage.ClassANY:
		soa = true
	default:
		labels := 0
		if !apex {
			labels = strings.Count(rel, ".") + 1
		}
		if !apex && rel != "ns" && labels > 2 {
			rcode, soa = dnsmessage.RCodeNameError, true
			break
		}
		rh := func(t dnsmessage.Type, ttl uint32) dnsmessage.ResourceHeader {
			return dnsmessage.ResourceHeader{Name: q.Name, Type: t, Class: dnsmessage.ClassINET, TTL: ttl}
		}
		switch {
		case q.Type == dnsmessage.TypeSOA && apex:
			answers = append(answers, z.soa(q.Name, origin))
		case q.Type == dnsmessage.TypeNS && apex:
			answers = append(answers, dnsmessage.Resource{Header: rh(dnsmessage.TypeNS, 3600),
				Body: &dnsmessage.NSResource{NS: dnsmessage.MustNewName("ns." + origin + ".")}})
		case q.Type == dnsmessage.TypeA && !apex && z.A.Is4():
			answers = append(answers, dnsmessage.Resource{Header: rh(dnsmessage.TypeA, 300), Body: &dnsmessage.AResource{A: z.A.As4()}})
		case q.Type == dnsmessage.TypeAAAA && !apex && z.AAAA.IsValid() && !z.AAAA.Is4():
			answers = append(answers, dnsmessage.Resource{Header: rh(dnsmessage.TypeAAAA, 300), Body: &dnsmessage.AAAAResource{AAAA: z.AAAA.As16()}})
		case q.Type == dnsmessage.TypeTXT && labels == 2 && strings.HasPrefix(rel, "_acme-challenge."):
			v, ok, err := z.TXT(ctx, name)
			if err != nil {
				rcode = dnsmessage.RCodeServerFailure
			} else if ok {
				answers = append(answers, dnsmessage.Resource{Header: rh(dnsmessage.TypeTXT, 60), Body: &dnsmessage.TXTResource{TXT: []string{v}}})
			}
		}
		soa = len(answers) == 0 && rcode == dnsmessage.RCodeSuccess
	}

	b := dnsmessage.NewBuilder(make([]byte, 0, maxUDP), dnsmessage.Header{ID: h.ID, Response: true,
		Authoritative:    rcode != dnsmessage.RCodeRefused && rcode != dnsmessage.RCodeNotImplemented,
		RecursionDesired: h.RecursionDesired, RCode: rcode})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	for _, r := range answers {
		var err error
		switch body := r.Body.(type) {
		case *dnsmessage.SOAResource:
			err = b.SOAResource(r.Header, *body)
		case *dnsmessage.NSResource:
			err = b.NSResource(r.Header, *body)
		case *dnsmessage.AResource:
			err = b.AResource(r.Header, *body)
		case *dnsmessage.AAAAResource:
			err = b.AAAAResource(r.Header, *body)
		case *dnsmessage.TXTResource:
			err = b.TXTResource(r.Header, *body)
		}
		if err != nil {
			return nil, err
		}
	}
	if soa {
		if err := b.StartAuthorities(); err != nil {
			return nil, err
		}
		s := z.soa(dnsmessage.MustNewName(origin+"."), origin)
		if err := b.SOAResource(s.Header, *s.Body.(*dnsmessage.SOAResource)); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

func (z *Zone) soa(owner dnsmessage.Name, origin string) dnsmessage.Resource {
	now := time.Now
	if z.Now != nil {
		now = z.Now
	}
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: owner, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 60},
		Body: &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("ns." + origin + "."), MBox: dnsmessage.MustNewName("hostmaster." + origin + "."),
			Serial: uint32(now().Unix() / 3600), Refresh: 3600, Retry: 600, Expire: 86400, MinTTL: 60},
	}
}

// Serve answers on pc (UDP) and l (TCP, 2-byte length prefix) until ctx is done, then closes both
// and waits for the connections in flight. A UDP query is answered inline: the TXT lookup is one
// SQLite read, so a flood slows the zone down rather than growing goroutines (shortcut: no
// per-source rate limit, add one if the port is abused).
func (z *Zone) Serve(ctx context.Context, pc net.PacketConn, l net.Listener) error {
	var wg sync.WaitGroup
	conns := map[net.Conn]struct{}{}
	var mu sync.Mutex
	go func() {
		<-ctx.Done()
		pc.Close()
		l.Close()
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
	}()

	errc := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				errc <- err
				return
			}
			if out, err := z.Answer(ctx, buf[:n]); err == nil {
				pc.WriteTo(out, addr)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				errc <- err
				return
			}
			mu.Lock()
			if ctx.Err() != nil {
				mu.Unlock()
				c.Close()
				continue
			}
			conns[c] = struct{}{}
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				z.serveConn(ctx, c)
				mu.Lock()
				delete(conns, c)
				mu.Unlock()
			}()
		}
	}()

	err := <-errc
	if ctx.Err() == nil { // a listener died on its own: stop the other one too
		pc.Close()
		l.Close()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func (z *Zone) serveConn(ctx context.Context, c net.Conn) {
	defer c.Close()
	for {
		c.SetDeadline(time.Now().Add(10 * time.Second))
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil {
			return
		}
		msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		out, err := z.Answer(ctx, msg)
		if err != nil {
			return
		}
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...)); err != nil {
			return
		}
	}
}
