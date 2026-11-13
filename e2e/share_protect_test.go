//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// visitorIP is the visitor container's address on the `visitors` network of compose.e2e.yaml, where
// share is 198.51.100.10: a public-looking source, which share keeps in its events and filters.
const visitorIP = "198.51.100.20"

// TestCommunityBanCutsSharingBoxOnly: a visitor reported by two fleets is banned for every box that
// shares its bans, and only for those.
//
//	go test -tags e2e ./e2e -run TestCommunityBanCutsSharingBoxOnly -v -timeout 40m
func TestCommunityBanCutsSharingBoxOnly(t *testing.T) {
	r := newRig(t)
	r.up()
	boxes := map[string]*fakeBox{}
	for _, f := range []string{"A", "B", "C", "D"} {
		id, sec, n := r.boxNodeID(f)
		boxes[f] = r.startBox(id, sec, n, "box"+strings.ToLower(f))
		boxes[f].setProtection(true, f != "D") // D filters, but does not share
	}

	// The visitor: a curl container on the public-looking network only (label: removed by the rig).
	vis := r.proj + "-visitor"
	if out, err := sh("docker", "create", "--name", vis, "--label", "rre2e.project="+r.proj,
		"--network", r.proj+"_visitors", "--ip", visitorIP, "--entrypoint", "sleep", "curlimages/curl:8.11.1", "900"); err != nil {
		t.Fatalf("docker create visitor: %v\n%s", err, out)
	}
	if out, err := sh("docker", "start", vis); err != nil {
		t.Fatalf("docker start visitor: %v\n%s", err, out)
	}
	// visit fetches https://app.<box>.box.relay.test/ from the visitor (-v: the TLS trace goes to the output).
	visit := func(box string) (string, error) {
		host := "app." + box + ".box.relay.test"
		return sh("docker", "exec", vis, "curl", "-sS", "-v", "-k", "-m", "10",
			"--resolve", host+":443:198.51.100.10", "https://"+host+"/")
	}
	// answers fails unless box answers the visitor with its page; the "(IN)" line it also checks is
	// what cut() looks for, so the absence there means something.
	answers := func(box string) error {
		out, err := visit(box)
		if err != nil || !strings.Contains(out, "hello from "+box) || !strings.Contains(out, "(IN)") {
			return fmt.Errorf("visitor -> %s: %v\n%s", box, err, out)
		}
		return nil
	}
	// cut is nil when share closed the visitor's connection to box before sending it a single byte:
	// curl's handshake fails (exit 35) with no inbound TLS record in its trace.
	cut := func(box string) error {
		out, err := visit(box)
		if err == nil || !strings.Contains(err.Error(), "exit status 35") || strings.Contains(out, "(IN)") {
			return fmt.Errorf("visitor -> %s not cut: %v\n%s", box, err, out)
		}
		t.Logf("visitor -> %s cut: %v\n%s", box, err, out)
		return nil
	}

	// Every box answers before any report (share records the visitor reaching A and B).
	for _, b := range []string{"boxa", "boxb", "boxc", "boxd"} {
		if err := answers(b); err != nil {
			t.Fatal(err)
		}
	}

	// A and B report the visitor. A report is dropped until share's 15 s flush has told enrolment about
	// the visit, so both keep reporting until the community tick (every minute) opens the ban.
	key := visitorIP + "/32"
	row := regexp.MustCompile(`<code>` + regexp.QuoteMeta(key) + `</code></td><td class="mut">address</td><td class="mut wrap">[^<]*</td><td class="r">(\d+)</td>`)
	eventually(t, "the community ban on /admin/protection", 3*time.Minute, func() error {
		boxes["A"].reportBan(key, "scan")
		boxes["B"].reportBan(key, "scan")
		time.Sleep(4 * time.Second)
		page, err := r.adminProtection()
		if err != nil {
			return err
		}
		m := row.FindStringSubmatch(page)
		if m == nil {
			return fmt.Errorf("no ban row for %s yet", key)
		}
		if m[1] != "2" {
			return fmt.Errorf("ban of %s lists %s fleet(s), want 2", key, m[1])
		}
		return nil
	})

	// share picks the new list up at its next snapshot poll (every 30 s).
	eventually(t, "visitor cut from boxc", 90*time.Second, func() error { return cut("boxc") })
	// Same name from a private address (the host, through Docker's port publishing): never in the list,
	// so boxc itself is up and the cut is the ban.
	if body, _, err := r.visit("app.boxc.box.relay.test", boxes["C"]); err != nil || body != "hello from boxc" {
		t.Fatalf("host -> boxc: %q, %v", body, err)
	}
	// D filters but does not share bans: the community list does not apply to it.
	if err := answers("boxd"); err != nil {
		t.Fatal(err)
	}
}

// adminProtection returns /admin/protection.
func (r *rig) adminProtection() (string, error) {
	req, _ := http.NewRequest("GET", r.frontURL+"/admin/protection", nil)
	req.SetBasicAuth("e2e", e2eAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /admin/protection: %d %.200s", resp.StatusCode, body)
	}
	return string(body), nil
}
