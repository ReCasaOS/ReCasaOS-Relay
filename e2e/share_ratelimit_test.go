//go:build e2e

package e2e

import (
	"strconv"
	"strings"
	"testing"
)

// TestShareFrontKeepsClientAddresses: behind share, Caddy must see each visitor's own address (PROXY
// protocol), or enrolment's per-IP limits become one global bucket. Two containers with distinct addresses
// POST to the login form through share: the first is limited (429) after LOGIN_RATE_PER_HOUR requests,
// the second is not.
func TestShareFrontKeepsClientAddresses(t *testing.T) {
	r := newRig(t)
	r.up()

	const limit = 20 // LOGIN_RATE_PER_HOUR: the default, compose.e2e.yaml does not override it
	start := func(name string) string {
		c := r.proj + "-" + name
		// Root, not the image's curl_user: `docker cp` keeps the CA file's host mode (0600 on Linux, Caddy's
		// pki files) and makes it root-owned, so an unprivileged curl fails with exit 77 on a Linux runner.
		args := []string{"create", "--name", c, "--label", "rre2e.project=" + r.proj, "--network", r.proj + "_default",
			"--user", "0:0", "--entrypoint", "sleep", "curlimages/curl:8.11.1", "600"}
		if out, err := sh("docker", args...); err != nil {
			t.Fatalf("docker create %s: %v\n%s", name, err, out)
		}
		if out, err := sh("docker", "cp", r.caFile, c+":/ca.crt"); err != nil {
			t.Fatalf("docker cp CA: %v\n%s", err, out)
		}
		if out, err := sh("docker", "start", c); err != nil {
			t.Fatalf("docker start %s: %v\n%s", name, err, out)
		}
		return c
	}
	ip := func(c string) string {
		out, err := sh("docker", "inspect", "-f", "{{(index .NetworkSettings.Networks \""+r.proj+"_default\").IPAddress}}", c)
		if err != nil {
			t.Fatalf("inspect %s: %v\n%s", c, err, out)
		}
		return out
	}
	// post sends n bogus-code logins and returns the status codes in order.
	post := func(c string, n int) []string {
		script := `for i in $(seq 1 ` + strconv.Itoa(n) + `); do curl -s -m 15 -o /dev/null -w '%{http_code}\n' --cacert /ca.crt ` +
			`-d code=bogus https://relay.test/register/hskey-authreq-abcdefghijklmnopqrstuvwx; done`
		out, err := sh("docker", "exec", c, "sh", "-c", script)
		if err != nil {
			t.Fatalf("curl in %s: %v\n%s", c, err, out)
		}
		return strings.Fields(out)
	}

	a, b := start("clienta"), start("clientb")
	if ip(a) == ip(b) {
		t.Fatalf("both containers have address %s", ip(a))
	}

	codes := post(a, limit+5)
	if len(codes) != limit+5 {
		t.Fatalf("got %d answers: %v", len(codes), codes)
	}
	for i, c := range codes {
		if want429 := i >= limit; (c == "429") != want429 {
			t.Fatalf("request %d from the first address answered %s (limit %d): %v", i+1, c, limit, codes)
		}
	}
	if got := post(b, 1); got[0] == "429" || !strings.HasPrefix(got[0], "4") {
		t.Fatalf("the second address's first request answered %v: want a 4xx for the bogus code, not 429 (one shared bucket?)", got)
	}
}
