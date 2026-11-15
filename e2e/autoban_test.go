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

// TestAutoBanCutsSharesNotRelay: a visitor that tries many share names no box holds is banned by the
// relay itself; shared apps are then closed to it, while the relay host keeps answering.
// The trap path route is not run here: front sees tlsfront as the peer of every request (the visitor's
// address stops at tlsfront), so only share's own sight of the visitor, the share names, reaches the ban.
//
//	go test -tags e2e ./e2e -run TestAutoBanCutsSharesNotRelay -v -timeout 40m
func TestAutoBanCutsSharesNotRelay(t *testing.T) {
	r := newRig(t)
	r.up()
	id, sec, node := r.boxNodeID("A")
	r.startBox(id, sec, node, "boxa") // a shared app the ban must cut

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

	// boxCut is nil once share closes the visitor's connection to the app before sending a byte
	// (curl's handshake fails with exit 35 and no inbound TLS record).
	boxCut := func() error {
		out, err := fetch("app.boxa.box.relay.test", "/")
		if err == nil || !strings.Contains(err.Error(), "exit status 35") || strings.Contains(out, "(IN)") {
			return fmt.Errorf("visitor -> boxa not cut: %v\n%.300s", err, out)
		}
		return nil
	}

	// Registered before the ban exists, so no failure path leaves it behind: the other tests share this address.
	t.Cleanup(func() {
		// Lifting sits inside the loop: a report still in flight can land a ban after the first lift.
		// Done only when no ban row of the visitor is left (the relay host answers with or without one).
		eventually(t, "no ban of the visitor is left", 120*time.Second, func() error {
			if err := r.liftAutoBan(visitorIP); err != nil {
				return err
			}
			page, err := r.adminProtection()
			if err != nil {
				return err
			}
			if _, _, ok := banRow(page, visitorIP); ok {
				return fmt.Errorf("ban of %s still listed", visitorIP)
			}
			return nil
		})
	})

	eventually(t, "the visitor reaches the relay before any ban", 30*time.Second, relayAnswers)
	eventually(t, "the visitor reaches boxa before any ban", 30*time.Second, func() error {
		if out, err := fetch("app.boxa.box.relay.test", "/"); err != nil || !strings.Contains(out, "hello from boxa") {
			return fmt.Errorf("visitor -> boxa: %v\n%.300s", err, out)
		}
		return nil
	})

	// More different names than AUTOBAN_NAMES (10); each try may be reported later than it is made, so keep trying.
	n := 0
	key := visitorIP // an IPv4 ban is stored without /32
	eventually(t, "the automatic ban on /admin/protection", 90*time.Second, func() error {
		for i := 0; i < 12; i++ {
			n++
			fetch(fmt.Sprintf("app.nobody%d.box.relay.test", n), "/") // closed without an answer: the error is expected
		}
		page, err := r.adminProtection()
		if err != nil {
			return err
		}
		if _, _, ok := banRow(page, key); !ok {
			return fmt.Errorf("no ban of %s yet", key)
		}
		return nil
	})

	// share picks the ban up with its next snapshot poll (every 30 s): the shared app is then closed.
	eventually(t, "boxa closed to the visitor", 90*time.Second, boxCut)

	page, err := r.adminJournal(url.Values{"src": {"relay"}, "q": {"ban_auto"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page, "ban_auto") || !strings.Contains(page, visitorIP) {
		t.Fatalf("no ban_auto line for %s on /admin/journal", visitorIP)
	}

	// boxa may also be cut because its tunnel dropped: share's own journal must say the automatic ban did it,
	// which proves the filter with the ban is loaded before the relay host is checked.
	eventually(t, "share's cut by the automatic ban on /admin/journal", 30*time.Second, func() error {
		fetch("app.boxa.box.relay.test", "/") // a fresh cut line, whatever the journal's rate limit kept
		page, err := r.adminJournal(url.Values{"src": {"share"}, "q": {visitorIP}})
		if err != nil {
			return err
		}
		if !strings.Contains(page, "cut · manual · auto") {
			return fmt.Errorf("no cut · manual · auto line for %s yet", visitorIP)
		}
		return nil
	})
	// An automatic ban must leave the relay's own pages open.
	if err := relayAnswers(); err != nil {
		t.Fatalf("the automatic ban closed the relay host: %v", err)
	}
}

// liftAutoBan deletes the manual ban row of key through /admin/protection, as the Lift button does.
func (r *rig) liftAutoBan(key string) error {
	page, err := r.adminProtection()
	if err != nil {
		return err
	}
	id, csrf, ok := banRow(page, key)
	if !ok {
		return nil // no ban
	}
	req, _ := http.NewRequest("POST", r.frontURL+"/admin/protection/manual/"+id+"/delete", strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
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

// banRow finds the Manual bans row of value (it holds both the value and its own delete form) and
// returns the row id and the CSRF token of that form. Other tables print the same keys with /32.
func banRow(page, value string) (id, csrf string, ok bool) {
	re := regexp.MustCompile(`/admin/protection/manual/(\d+)/delete"><input type="hidden" name="csrf" value="([0-9a-f]+)"`)
	for _, row := range strings.Split(page, "</tr>") {
		if i := strings.LastIndex(row, "<tr>"); i >= 0 {
			row = row[i:]
		}
		if m := re.FindStringSubmatch(row); m != nil && strings.Contains(row, "<code>"+value+"</code>") {
			return m[1], m[2], true
		}
	}
	return "", "", false
}
