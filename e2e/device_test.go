//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
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
	page, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
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

type deviceInfo struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

// fleetCall sends an authenticated request to the front and returns the status and body.
func (r *rig) fleetCall(method, path, secret string) (int, []byte) {
	r.t.Helper()
	req, _ := http.NewRequest(method, r.frontURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// postCode submits the login form the way a browser does and returns the status.
func (r *rig) postCode(registerPath, code string) int {
	r.t.Helper()
	resp, err := http.PostForm(r.frontURL+registerPath, url.Values{"code": {code}})
	if err != nil {
		r.t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// TestDeviceJoinsWithCode is the whole remote-access flow: a box asks for a code, the phone's web
// login is approved by typing it, the phone reaches its own fleet only, the box lists and removes it.
//
//	go test -tags e2e ./e2e -run TestDeviceJoinsWithCode -v -timeout 15m
func TestDeviceJoinsWithCode(t *testing.T) {
	r := newRig(t)
	r.up()
	ctx := context.Background()

	idA, secA := r.createFleet("a")
	idB, secB := r.createFleet("b")
	userA := r.fleetUser["a"]
	a1 := r.startNode("a", "a1", r.joinKey(idA, secA))
	b1 := r.startNode("b", "b1", r.joinKey(idB, secB))

	status, raw := r.fleetCall("POST", "/v1/fleets/"+idA+"/device-codes", secA)
	var dc struct {
		Code      string `json:"code"`
		ExpiresAt string `json:"expires_at"`
	}
	if status != http.StatusCreated || json.Unmarshal(raw, &dc) != nil || dc.Code == "" || dc.ExpiresAt == "" {
		t.Fatalf("device code: %d (body withheld)", status)
	}

	dev, authURL := r.startNodeWeb("a", "phone")
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	loose := strings.ToLower(strings.ReplaceAll(dc.Code, "-", ""))
	if got := r.postCode(u.Path, loose); got != http.StatusOK {
		t.Fatalf("POST %s with the code = %d, want 200", u.Path, got)
	}
	eventually(t, "phone gets an address", 90*time.Second, func() error { return r.fetchIP(dev) })
	r.listen(dev)

	r.mustReach(dev, a1)
	r.mustNotReach([2]*node{dev, b1})

	// A code is good once.
	if got := r.postCode(u.Path, loose); got != http.StatusBadRequest {
		t.Errorf("reusing the code = %d, want 400", got)
	}

	var list struct{ Devices []deviceInfo }
	status, raw = r.fleetCall("GET", "/v1/fleets/"+idA+"/devices", secA)
	if status != http.StatusOK || json.Unmarshal(raw, &list) != nil {
		t.Fatalf("list devices: %d %.200s", status, raw)
	}
	var phoneID string
	for _, d := range list.Devices {
		if d.Hostname == "phone" {
			phoneID = d.ID
		}
	}
	if phoneID == "" {
		t.Fatalf("phone is not in the device list: %s", raw)
	}

	// Devices are not boxes: the fleet status does not list them.
	if status, raw = r.fleetCall("GET", "/v1/fleets/"+idA, secA); status != http.StatusOK || strings.Contains(string(raw), "phone") {
		t.Errorf("fleet status = %d, mentions phone: %v", status, strings.Contains(string(raw), "phone"))
	}

	if status, _ = r.fleetCall("DELETE", "/v1/fleets/"+idA+"/devices/"+phoneID, secA); status != http.StatusNoContent {
		t.Fatalf("remove device = %d, want 204", status)
	}
	eventually(t, "phone disappears from Headscale", 30*time.Second, func() error {
		nodes, err := r.hs.ListNodes(ctx, userA)
		if err != nil {
			return err
		}
		for _, n := range nodes {
			if n.Hostname == "phone" {
				return errors.New("phone is still a node")
			}
		}
		return nil
	})
}
