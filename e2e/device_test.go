//go:build e2e

package e2e

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
)

// TestWebLoginIsTakenOver is the gate of the remote-access feature: a client that logs in on the
// web (as the Tailscale phone app does) is sent to a page the relay serves, and approving its auth
// request through the API puts it in the fleet, key never expiring, with no access to other fleets.
//
//	go test -tags e2e ./e2e -run TestWebLoginIsTakenOver -v -timeout 15m
func TestWebLoginIsTakenOver(t *testing.T) {
	r := newRig(t)
	r.up()
	ctx := context.Background()

	idA, secA := r.createFleet("a")
	idB, secB := r.createFleet("b")
	userA := r.fleetUser["a"]
	a1 := r.startNode("a", "a1", r.joinKey(idA, secA))
	b1 := r.startNode("b", "b1", r.joinKey(idB, secB))

	dev, authURL := r.startNodeWeb("a", "phone")
	if !strings.HasPrefix(authURL, loginServer+"/register/hskey-authreq-") {
		t.Fatalf("AuthURL = %q", authURL)
	}
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}

	// Caddy sends /register/* to the enrolment service, not to Headscale's own page.
	resp, err := http.Get(r.frontURL + u.Path)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(page), "recasaos-device-login") {
		t.Fatalf("GET %s = %d, body %.200q", u.Path, resp.StatusCode, page)
	}

	// A well-formed id nobody is waiting on: Headscale's 404 maps to ErrAuthRequestNotFound.
	if _, err := r.hs.RegisterNode(ctx, userA, "hskey-authreq-"+strings.Repeat("Z", 24)); !errors.Is(err, headscale.ErrAuthRequestNotFound) {
		t.Fatalf("unknown auth id: err = %v, want ErrAuthRequestNotFound", err)
	}

	if _, err := r.hs.RegisterNode(ctx, userA, strings.TrimPrefix(u.Path, "/register/")); err != nil {
		t.Fatalf("approve login: %v", err)
	}
	eventually(t, "phone gets an address", 90*time.Second, func() error { return r.fetchIP(dev) })
	r.listen(dev)

	r.mustReach(dev, a1)
	r.mustNotReach([2]*node{dev, b1})

	nodes, err := r.hs.ListNodes(ctx, userA)
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, n := range nodes {
		if n.Hostname == "phone" {
			seen = true
			if !n.Expiry.IsZero() {
				t.Errorf("phone's key expires at %s, want never (node.expiry: 0)", n.Expiry)
			}
		}
	}
	if !seen {
		t.Fatalf("phone is not listed in %s", userA)
	}
}
