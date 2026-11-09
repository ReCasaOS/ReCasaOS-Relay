//go:build e2e

package e2e

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// boxNodeID starts a tailscale node in a fresh fleet (for a Headscale node id) and returns the fleet.
func (r *rig) boxNodeID(fleetName string) (id, secret, nodeID string) {
	id, secret = r.createFleet(fleetName)
	r.startNode(fleetName, strings.ToLower(fleetName)+"1", r.joinKey(id, secret))
	eventually(r.t, "node of "+fleetName+" registered", 30*time.Second, func() error {
		ns, err := r.hs.ListNodes(context.Background(), "f-"+id)
		if err != nil || len(ns) != 1 {
			return fmt.Errorf("nodes %v, err %v", ns, err)
		}
		nodeID = ns[0].ID
		return nil
	})
	return
}

// visit does GET / on host as a visitor of share's 443, pinning the box's own certificate; it returns the
// body and the visitor's local port.
func (r *rig) visit(host string, pin *fakeBox) (string, int, error) {
	return r.visitTLS(host, &tls.Config{ServerName: host, InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 || string(cs.PeerCertificates[0].Raw) != string(pin.cert.Certificate[0]) {
				return fmt.Errorf("certificate is not %s's", pin.name)
			}
			return nil
		}})
}

// visitTLS does GET / on host as a visitor of share's 443 with the given TLS config.
func (r *rig) visitTLS(host string, cfg *tls.Config) (string, int, error) {
	return r.visitPath(host, "/", cfg)
}

// visitPath does GET path on host as a visitor of share's 443 with the given TLS config.
func (r *rig) visitPath(host, path string, cfg *tls.Config) (string, int, error) {
	c, err := net.DialTimeout("tcp", r.shareAddr, 5*time.Second)
	if err != nil {
		return "", 0, err
	}
	port := c.LocalAddr().(*net.TCPAddr).Port
	tc := tls.Client(c, cfg)
	cl := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return tc, nil }}}
	defer cl.CloseIdleConnections()
	resp, err := cl.Get("https://" + host + path)
	if err != nil {
		return "", port, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), port, err
}

// txt asks the zone (enrolment's DNS on loopback) for the TXT records of name.
func (r *rig) txt(name string) ([]string, dnsmessage.RCode) {
	r.t.Helper()
	addr := r.mustCompose("port", "--protocol", "udp", "enrolment", "53")
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 7}, Questions: []dnsmessage.Question{{
		Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}}}
	pkt, _ := q.Pack()
	c, err := net.Dial("udp", addr)
	if err != nil {
		r.t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write(pkt)
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		r.t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(buf[:n]); err != nil {
		r.t.Fatal(err)
	}
	var out []string
	for _, a := range m.Answers {
		if t, ok := a.Body.(*dnsmessage.TXTResource); ok {
			out = append(out, strings.Join(t.TXT, ""))
		}
	}
	return out, m.Header.RCode
}

// mustNoTXT fails unless the zone answers NOERROR with an empty answer section (not SERVFAIL, not a timeout).
func (r *rig) mustNoTXT(name string) {
	r.t.Helper()
	if got, rc := r.txt(name); rc != dnsmessage.RCodeSuccess || len(got) != 0 {
		r.t.Fatalf("%s TXT = %v, rcode %v; want NOERROR and no answer", name, got, rc)
	}
}

func TestShareRoutesBySNIAndIsolates(t *testing.T) {
	r := newRig(t)
	r.up()
	ida, seca, na := r.boxNodeID("A")
	idb, secb, nb := r.boxNodeID("B")
	boxa := r.startBox(ida, seca, na, "boxa")
	boxb := r.startBox(idb, secb, nb, "boxb")

	// Routing by SNI: boxa answers for its names, with its own certificate and the visitor's source port.
	body, port, err := r.visit("app.boxa.box.relay.test", boxa)
	if err != nil || body != "hello from boxa" {
		t.Fatalf("visit boxa: %q, %v", body, err)
	}
	// Docker's port publishing (userland proxy, Docker Desktop NAT) rewrites the source address, so the
	// visitor's own port is only comparable when the source is untouched; otherwise a real one must arrive.
	srcs := boxa.sources()
	if len(srcs) != 1 || srcs[0].Port == 0 || srcs[0].IP == nil {
		t.Fatalf("PROXY sources %v, want one with a source address", srcs)
	}
	if srcs[0].IP.IsLoopback() && srcs[0].Port != port {
		t.Fatalf("PROXY source port %d, want the visitor's %d", srcs[0].Port, port)
	}
	t.Logf("PROXY source %v (visitor port %d)", srcs[0], port)
	if n := boxb.streams.Load(); n != 0 {
		t.Fatalf("boxb received %d stream(s) meant for boxa", n)
	}
	if _, _, err := r.visit("app.boxa.box.relay.test", boxb); err == nil {
		t.Fatal("boxa's name answered with boxb's certificate")
	}

	// boxb cannot take boxa's name.
	if code, out := boxb.signed("PUT", "/v1/share/name", `{"name":"boxa"}`); code != http.StatusConflict || !strings.Contains(out, "name taken") {
		t.Fatalf("boxb claims boxa: %d %s", code, out)
	}

	// boxb's ACME token lands under boxb only.
	if code, out := boxb.signed("PUT", "/v1/share/acme", `{"value":"token-of-b"}`); code != http.StatusNoContent {
		t.Fatalf("boxb acme: %d %s", code, out)
	}
	eventually(t, "boxb TXT published", 10*time.Second, func() error {
		if got, rc := r.txt("_acme-challenge.boxb.box.relay.test"); rc != dnsmessage.RCodeSuccess || len(got) != 1 || got[0] != "token-of-b" {
			return fmt.Errorf("boxb TXT = %v, rcode %v", got, rc)
		}
		return nil
	})
	r.mustNoTXT("_acme-challenge.boxa.box.relay.test")

	// The internal API is not reachable through the public front.
	tr := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return r.dialSNI("relay.test") }}}
	resp, err := tr.Get("https://relay.test/internal/share/boxes/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/internal through tlsfront: %d, want 404", resp.StatusCode)
	}

	// Shared traffic is metered: the `share` process posts its deltas every 15 s, and /admin/ shows
	// boxa's node with the volume it sent (data-shared-bytes), within +-10 % of the 20 MiB downloaded.
	const big = 20 << 20
	pin := &tls.Config{ServerName: "app.boxa.box.relay.test", InsecureSkipVerify: true}
	if got, _, err := r.visitPath("app.boxa.box.relay.test", "/big", pin); err != nil || len(got) != big {
		t.Fatalf("download /big: %d bytes, %v", len(got), err)
	}
	row := regexp.MustCompile(`(?s)data-node-id="` + na + `".*?data-shared-bytes="(\d+)"`)
	eventually(t, "boxa's shared volume on /admin", 45*time.Second, func() error {
		req, _ := http.NewRequest("GET", r.frontURL+"/admin/", nil)
		req.SetBasicAuth("e2e", e2eAdminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		page, _ := io.ReadAll(resp.Body)
		m := row.FindSubmatch(page)
		if m == nil {
			return fmt.Errorf("no shared volume for node %s on /admin (status %d)", na, resp.StatusCode)
		}
		v, _ := strconv.ParseInt(string(m[1]), 10, 64)
		if v < big*90/100 || v > big*110/100 {
			return fmt.Errorf("shared volume %d, want %d +-10 %%", v, big)
		}
		return nil
	})

	// Revoke boxa on /admin: the name joins the forbidden list, and within the 60 s revalidation its
	// tunnel closes with 4403 and its names stop answering.
	noRedirect := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	adminGet := func() string {
		req, _ := http.NewRequest("GET", r.frontURL+"/admin/", nil)
		req.SetBasicAuth("e2e", e2eAdminToken)
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	tok := regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`).FindStringSubmatch(adminGet())
	if tok == nil {
		t.Fatal("no csrf token on /admin")
	}
	req, _ := http.NewRequest("POST", r.frontURL+"/admin/share/names/boxa/revoke", strings.NewReader(url.Values{"csrf": {tok[1]}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("e2e", e2eAdminToken)
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke boxa: %d, want 303", resp.StatusCode)
	}
	eventually(t, "boxa's names closed and its tunnel reports 4403", 70*time.Second, func() error {
		if code := boxa.sess.CloseStatus(); code != 4403 {
			return fmt.Errorf("close status %d, want 4403", code)
		}
		c, err := r.dialSNI("app.boxa.box.relay.test")
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if err := c.Handshake(); err == nil {
			return errors.New("boxa's name still completes a handshake")
		}
		return nil
	})
	page := adminGet()
	i := strings.Index(page, "Forbidden names")
	if i < 0 || !strings.Contains(page[i:], "boxa") {
		t.Fatal("/admin does not list boxa under Forbidden names")
	}
}

func TestShareCertificateViaDNS01(t *testing.T) {
	r := newRig(t)
	r.up()
	ida, seca, na := r.boxNodeID("A")
	boxa := r.startBox(ida, seca, na, "boxa")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := boxa.obtainCert(ctx, "https://"+r.pebbleACME+"/dir"); err != nil {
		t.Fatal(err)
	}
	roots, err := pebbleRoots(r.pebbleMgmt)
	if err != nil {
		t.Fatal(err)
	}
	// No InsecureSkipVerify: the chain must verify against Pebble's root for the visited name.
	body, _, err := r.visitTLS("app.boxa.box.relay.test", &tls.Config{ServerName: "app.boxa.box.relay.test", RootCAs: roots})
	if err != nil || body != "hello from boxa" {
		t.Fatalf("visit with the ACME certificate: %q, %v", body, err)
	}
	r.mustNoTXT("_acme-challenge.boxa.box.relay.test")
}
