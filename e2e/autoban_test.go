//go:build e2e

package e2e

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestAutoBanClosesRelayAndShares: a visitor that tries many share names no box holds is banned by the
// relay itself, and its new connections to the relay host are then closed without an answer.
// The trap path route is not run here: front sees tlsfront as the peer of every request (the visitor's
// address stops at tlsfront), so only share's own sight of the visitor, the share names, reaches the ban.
//
//	go test -tags e2e ./e2e -run TestAutoBanClosesRelayAndShares -v -timeout 40m
func TestAutoBanClosesRelayAndShares(t *testing.T) {
	r := newRig(t)
	r.up()

	vis := r.proj + "-visitor"
	if out, err := sh("docker", "create", "--name", vis, "--label", "rre2e.project="+r.proj,
		"--network", r.proj+"_visitors", "--ip", visitorIP, "--entrypoint", "sleep", "curlimages/curl:8.11.1", "900"); err != nil {
		t.Fatalf("docker create visitor: %v\n%s", err, out)
	}
	if out, err := sh("docker", "start", vis); err != nil {
		t.Fatalf("docker start visitor: %v\n%s", err, out)
	}
	fetch := func(host, path string) (string, error) {
		return sh("docker", "exec", vis, "curl", "-sS", "-v", "-k", "-m", "10",
			"--resolve", host+":443:198.51.100.10", "https://"+host+path)
	}
	relayAnswers := func() error {
		out, err := fetch("relay.test", "/v1/fleets/00000000000000000000000000000000")
		if err != nil || !strings.Contains(out, "fleet not found") {
			return fmt.Errorf("visitor -> relay.test: %v\n%.300s", err, out)
		}
		return nil
	}

	// Registered before the ban exists, so no failure path leaves it behind: the other tests share this address.
	t.Cleanup(func() {
		if err := r.liftAutoBan(visitorIP + "/32"); err != nil {
			t.Errorf("lifting the ban: %v", err)
			return
		}
		// share refreshes its filter every 30 s.
		eventually(t, "the visitor reaches the relay again", 90*time.Second, relayAnswers)
	})

	eventually(t, "the visitor reaches the relay before any ban", 30*time.Second, relayAnswers)

	// More different names than AUTOBAN_NAMES (10); each try may be reported later than it is made, so keep trying.
	n := 0
	key := visitorIP + "/32"
	eventually(t, "the automatic ban on /admin/protection", 90*time.Second, func() error {
		for i := 0; i < 12; i++ {
			n++
			fetch(fmt.Sprintf("app.nobody%d.box.relay.test", n), "/") // closed without an answer: the error is expected
		}
		page, err := r.adminProtection()
		if err != nil {
			return err
		}
		if !strings.Contains(page, "<code>"+key+"</code>") {
			return fmt.Errorf("no ban of %s yet", key)
		}
		return nil
	})

	// share picks the ban up with its next snapshot poll (every 30 s): the relay host is then closed without a byte.
	eventually(t, "the relay host closed to the visitor", 90*time.Second, func() error {
		out, err := fetch("relay.test", "/v1/fleets/00000000000000000000000000000000")
		if err == nil || !strings.Contains(err.Error(), "exit status 35") || strings.Contains(out, "(IN)") {
			return fmt.Errorf("visitor -> relay.test not cut: %v\n%.300s", err, out)
		}
		return nil
	})

	page, err := r.adminJournal(url.Values{"src": {"relay"}, "q": {"ban_auto"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page, "ban_auto") || !strings.Contains(page, visitorIP) {
		t.Fatalf("no ban_auto line for %s on /admin/journal", visitorIP)
	}
}

// liftAutoBan deletes the manual ban row of key through /admin/protection, as the Lift button does.
func (r *rig) liftAutoBan(key string) error {
	page, err := r.adminProtection()
	if err != nil {
		return err
	}
	m := regexp.MustCompile(`(?s)<code>` + regexp.QuoteMeta(key) + `</code>.*?/admin/protection/manual/(\d+)/delete"><input type="hidden" name="csrf" value="([0-9a-f]+)"`).FindStringSubmatch(page)
	if m == nil {
		return nil // never opened
	}
	req, _ := http.NewRequest("POST", r.frontURL+"/admin/protection/manual/"+m[1]+"/delete", strings.NewReader(url.Values{"csrf": {m[2]}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("e2e", e2eAdminToken)
	resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if body, _ := io.ReadAll(resp.Body); resp.StatusCode >= 400 {
		return fmt.Errorf("POST delete: %d %.200s", resp.StatusCode, body)
	}
	return nil
}
