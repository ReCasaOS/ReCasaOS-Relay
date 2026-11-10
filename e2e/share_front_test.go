//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestShareFrontKeepsRelayWorking is the gate for the public-sharing front: with `share` on 443/80 in
// front of Caddy (and relay.test resolving to it), the relay must work exactly as before.
func TestShareFrontKeepsRelayWorking(t *testing.T) {
	r := newRig(t)
	r.up()

	// The API over a peeked TLS connection: share -> tlsfront -> front -> enrolment.
	viaShare := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialTLSContext: func(context.Context, string, string) (net.Conn, error) { return r.dialSNI("relay.test") }}}
	resp, err := viaShare.Get("https://relay.test/v1/fleets/00000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(body), "fleet not found") {
		t.Fatalf("API through share: %d %s", resp.StatusCode, body)
	}

	// Port 80 is forwarded raw: Caddy's own answer (its http->https redirect) comes back unchanged.
	noRedirect := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", "http://"+r.mustCompose("port", "share", "80")+"/healthz", nil)
	req.Host = "relay.test"
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != "https://relay.test/healthz" {
		t.Fatalf("port 80 through share: %d, Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// A real Tailscale client logs in through the peek (relay.test resolves to share in this network).
	id, sec := r.createFleet("S")
	n := r.startNode("S", "s1", r.joinKey(id, sec))
	eventually(t, "s1 is Running", 60*time.Second, func() error {
		out, _ := sh("docker", "exec", n.container, "tailscale", "status", "--json")
		if !strings.Contains(out, `"BackendState": "Running"`) {
			return fmt.Errorf("not Running yet: %.200s", out)
		}
		return nil
	})
	r.mustSeePeers(n)

	// A box name has no tunnel yet: closed without a byte.
	conn, err := r.dialSNI("app.nobody.box.relay.test") // the handshake starts at the first Read
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("box SNI: read %d byte(s), err %v; want EOF", n, err)
	}
}
