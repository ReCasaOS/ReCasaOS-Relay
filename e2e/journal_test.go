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

// TestJournalShowsVisitorAndAPI: a visitor of a shared app and a box's API call show on /admin/journal,
// written by share (its own volume) and by front (through enrolment) with no step by hand, and no header
// or secret reaches the page.
//
//	go test -tags e2e ./e2e -run TestJournalShowsVisitorAndAPI -v -timeout 40m
func TestJournalShowsVisitorAndAPI(t *testing.T) {
	r := newRig(t)
	r.up()
	id, sec, n := r.boxNodeID("A")
	boxa := r.startBox(id, sec, n, "boxa")

	// The visitor: a curl container on the public-looking network only (label: removed by the rig).
	vis := r.proj + "-visitor"
	if out, err := sh("docker", "create", "--name", vis, "--label", "rre2e.project="+r.proj,
		"--network", r.proj+"_visitors", "--ip", visitorIP, "--entrypoint", "sleep", "curlimages/curl:8.11.1", "900"); err != nil {
		t.Fatalf("docker create visitor: %v\n%s", err, out)
	}
	if out, err := sh("docker", "start", vis); err != nil {
		t.Fatalf("docker start visitor: %v\n%s", err, out)
	}
	host := "app.boxa.box.relay.test"

	// Rendered rows of journal.html: share's with the visitor's address and the name it asked for; front's
	// with the box's call (its address is tlsfront's or Docker's, so only the request is checked).
	shareRow := regexp.MustCompile(`<span class="src share">share</span><span class="ip"><button type="button" class="q">` +
		regexp.QuoteMeta(visitorIP) + `</button></span><span class="host"><button type="button" class="q">` +
		regexp.QuoteMeta(host) + `</button></span><span class="tx">passed`)
	frontRow := regexp.MustCompile(`<span class="src front">front</span><span class="ip">(<button type="button" class="q">[^<]*</button>)?</span>` +
		`<span class="host">(<button type="button" class="q">[^<]*</button>)?</span><span class="tx">PUT /v1/share/protection · 200`)
	never := []string{"Authorization", "X-Box-Signature", "X-Box-Key", "Bearer", sec, e2eAdminToken}

	// Visit and call again on each try: a line front sent while enrolment's port 8083 was not up yet goes
	// to front's own output, not to the journal.
	eventually(t, "the visit and the API call on /admin/journal", 30*time.Second, func() error {
		if out, err := sh("docker", "exec", vis, "curl", "-sS", "-k", "-m", "10",
			"--resolve", host+":443:198.51.100.10", "https://"+host+"/"); err != nil || !strings.Contains(out, "hello from boxa") {
			return fmt.Errorf("visitor -> boxa: %v %s", err, out)
		}
		boxa.setProtection(true, false)
		for _, c := range []struct {
			q   url.Values
			row *regexp.Regexp
		}{
			{url.Values{"src": {"share"}, "q": {visitorIP}}, shareRow},
			{url.Values{"src": {"front"}, "q": {"/v1/share/protection"}}, frontRow},
		} {
			page, err := r.adminJournal(c.q)
			if err != nil {
				return err
			}
			if !c.row.MatchString(page) {
				return fmt.Errorf("no %s row on /admin/journal?%s yet", c.q.Get("src"), c.q.Encode())
			}
			for _, s := range never {
				if strings.Contains(page, s) {
					t.Fatalf("/admin/journal?%s shows %q", c.q.Encode(), s)
				}
			}
		}
		return nil
	})
}

// adminJournal returns /admin/journal?<q>.
func (r *rig) adminJournal(q url.Values) (string, error) {
	req, _ := http.NewRequest("GET", r.frontURL+"/admin/journal?"+q.Encode(), nil)
	req.SetBasicAuth("e2e", e2eAdminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /admin/journal: %d %.200s", resp.StatusCode, body)
	}
	return string(body), nil
}
