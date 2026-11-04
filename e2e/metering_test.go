//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// e2eAdminToken is ADMIN_TOKEN in e2e/compose.e2e.yaml (24+ characters).
const e2eAdminToken = "e2e-admin-token-0123456789abcdef"

var upMonthRow = regexp.MustCompile(`data-node-id="(\d+)" data-up-month="(\d+)"`)

// adminUpMonth reads /admin and returns data-up-month by Headscale node ID.
func (r *rig) adminUpMonth() (map[string]int64, error) {
	req, _ := http.NewRequest("GET", r.frontURL+"/admin/", nil)
	req.SetBasicAuth("e2e", e2eAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /admin/: %d %.200s", resp.StatusCode, body)
	}
	got := map[string]int64{}
	for _, m := range upMonthRow.FindAllStringSubmatch(string(body), -1) {
		v, _ := strconv.ParseInt(m[2], 10, 64)
		got[m[1]] = v
	}
	return got, nil
}

// TestRelayedTrafficIsMetered sends a known volume between two nodes forced through DERP and checks
// that /admin attributes it to the sender (and almost nothing to the receiver's upload).
//
//	go test -tags e2e ./e2e -run TestRelayedTrafficIsMetered -v -timeout 20m
func TestRelayedTrafficIsMetered(t *testing.T) {
	const sent = 20 << 20
	// DERP carries ~1.068x the payload (measured); 1.12 leaves a margin.
	const maxUp = sent * 112 / 100

	r := newRig(t)
	r.nodeEnv = []string{"TS_DEBUG_ALWAYS_USE_DERP=1"}
	r.up()

	id, sec := r.createFleet("A")
	a1 := r.startNode("A", "a1", r.joinKey(id, sec))
	a2 := r.startNode("A", "a2", r.joinKey(id, sec))

	r.mustReach(a1, a2) // peers and DERP home connections are ready (retries, like TestDerperAdmission)
	eventually(t, "a1 -> a2 is answered via DERP(relay)", 60*time.Second, func() error {
		out, err := sh("docker", "exec", a1.container, "tailscale", "ping", "--until-direct=false", "-c", "1", "--timeout", "5s", a2.ip)
		if err != nil || !strings.Contains(out, "via DERP(relay)") {
			return fmt.Errorf("not relayed yet: %v %s", err, out)
		}
		return nil
	})

	out, err := sh("docker", "exec", a1.container, "sh", "-c",
		fmt.Sprintf("head -c %d /dev/zero | nc -w 5 %s %s", sent, a2.ip, probePort))
	if err != nil {
		t.Fatalf("sending %d bytes to a2 failed: %v %s", sent, err, out)
	}

	nodes, err := r.hs.ListNodes(context.Background(), r.fleetUser["A"])
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, n := range nodes {
		ids[n.Hostname] = n.ID
	}
	if ids["a1"] == "" || ids["a2"] == "" {
		t.Fatalf("a1/a2 not in Headscale's node list: %v", ids)
	}

	// A new key is counted once Headscale's node list (refreshed at most every 60 s) knows it, then the
	// 15 s scrape picks it up: 150 s, not 90, so one missed refresh does not flake.
	eventually(t, "a1's relayed upload is on /admin", 150*time.Second, func() error {
		up, err := r.adminUpMonth()
		if err != nil {
			return err
		}
		a1Up, a2Up := up[ids["a1"]], up[ids["a2"]]
		if _, ok := up[ids["a2"]]; !ok {
			return fmt.Errorf("no /admin row for a2 (node %s)", ids["a2"])
		}
		t.Logf("data-up-month a1=%d a2=%d", a1Up, a2Up)
		if a1Up < sent || a1Up > maxUp {
			return fmt.Errorf("a1 up-month %d, want [%d, %d]", a1Up, sent, maxUp)
		}
		if a2Up >= 1<<20 {
			return fmt.Errorf("a2 up-month %d, want < %d", a2Up, 1<<20)
		}
		return nil
	})
}
