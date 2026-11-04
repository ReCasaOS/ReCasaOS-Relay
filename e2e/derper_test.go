//go:build e2e

package e2e

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ReCasaOS/recasaos-relay/internal/meter"
)

// derperDebugKey is the e2e value of DERPER_DEBUG_KEY (newRig puts it in r.env).
const derperDebugKey = "e2e-derper-debug-key-0123456789abcdef"

// derpcheckImage builds and runs e2e/derpcheck: tailscale.com v1.104.5 requires Go 1.27.3.
const derpcheckImage = "golang:1.27.3"

// derpcheck runs the e2e/derpcheck program on the compose network and returns its stdout. The binary
// is built once, next to the Caddy CA. A failed run is fatal: it must never read as "refused".
func (r *rig) derpcheck(args ...string) string {
	t := r.t
	t.Helper()
	dir := filepath.Dir(r.caFile)
	run := func(docker ...string) string {
		var stderr strings.Builder
		cmd := exec.Command("docker", docker...)
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("docker %s: %v\n%s", strings.Join(docker, " "), err, stderr.String())
		}
		return strings.TrimSpace(string(out))
	}
	if _, err := os.Stat(filepath.Join(dir, "derpcheck")); errors.Is(err, os.ErrNotExist) {
		run("run", "--rm", "-v", filepath.Join(r.root, "e2e", "derpcheck")+":/src:ro", "-v", dir+":/out",
			"-w", "/src", "-e", "CGO_ENABLED=0", derpcheckImage, "go", "build", "-o", "/out/derpcheck", ".")
	}
	return run(append([]string{"run", "--rm", "--network", r.proj + "_default", "-v", dir + ":/w:ro",
		"-e", "SSL_CERT_FILE=/w/" + filepath.Base(r.caFile), derpcheckImage, "/w/derpcheck"}, args...)...)
}

// derpCheck opens a DERP connection through the public path (https://relay.test/derp) and reports
// whether derper admitted it. nodeKeyMode "random" uses a fresh node key that Headscale never saw.
// Only a refusal by derper itself returns false: if derper cannot be reached, the test fails.
func (r *rig) derpCheck(nodeKeyMode string) (accepted bool) {
	r.t.Helper()
	if nodeKeyMode != "random" {
		r.t.Fatalf("derpCheck: unknown node key mode %q", nodeKeyMode)
	}
	out := r.derpcheck("https://relay.test/derp")
	r.t.Logf("derpcheck: %s", out)
	switch {
	case out == "accepted":
		return true
	case strings.HasPrefix(out, "refused: "):
		return false
	}
	r.t.Fatalf("derpcheck: unexpected output %q", out)
	return false
}

// stunCheck sends one STUN binding request to derper. relay.test is tlsfront here, so this targets
// the derper service directly.
func (r *rig) stunCheck() bool {
	r.t.Helper()
	out := r.derpcheck("stun", "derper:3478")
	r.t.Logf("derpcheck: %s", out)
	return out == "stun ok"
}

// debugClientsBody returns derper's raw /debug/clients/?all=1&format=json, read on the compose network.
func (r *rig) debugClientsBody() string {
	r.t.Helper()
	return r.derpcheck("debugclients", "http://derper:8090", derperDebugKey)
}

// TestDerperAdmission is the gate of the standalone derper: known nodes relay through it, an unknown
// node key is refused, and stays refused while Headscale is down (fail-closed).
//
//	go test -tags e2e ./e2e -run TestDerperAdmission -v -timeout 20m
func TestDerperAdmission(t *testing.T) {
	r := newRig(t)
	// Every packet between a1 and a2 crosses derper: reaching each other proves they were admitted.
	r.nodeEnv = []string{"TS_DEBUG_ALWAYS_USE_DERP=1"}
	r.up()

	id, sec := r.createFleet("A")
	a1 := r.startNode("A", "a1", r.joinKey(id, sec))
	a2 := r.startNode("A", "a2", r.joinKey(id, sec))
	r.mustReach(a1, a2)
	r.mustReach(a2, a1)

	// derper's listing, as the meter reads it: both nodes connected, traffic counted.
	body := r.debugClientsBody()
	t.Logf("derper /debug/clients/: %s", body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	defer srv.Close()
	conns, err := meter.NewDerper(srv.URL, derperDebugKey, nil).Clients(context.Background())
	if err != nil {
		t.Fatalf("meter on derper's listing: %v", err)
	}
	if len(conns) < 2 {
		t.Fatalf("derper lists %d connections, want at least a1's and a2's", len(conns))
	}
	var rx bool
	for _, c := range conns {
		if c.Key == "" {
			t.Errorf("connection %d without a key", c.ConnNum)
		}
		rx = rx || c.Rx > 0
	}
	if !rx {
		t.Errorf("no connection received bytes, though a1 and a2 talk through derper")
	}

	if r.derpCheck("random") {
		t.Fatal("ADMISSION BROKEN: derper accepted an unknown node key")
	}
	if !r.stunCheck() {
		t.Fatal("derper's STUN does not answer")
	}

	// derper's debug pages never go through the public front, even with the right key.
	for _, p := range []string{"/debug/clients/", "/debug/varz"} {
		resp, err := http.Get(r.frontURL + p + "?debugkey=" + derperDebugKey)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET front %s: %d, want 404", p, resp.StatusCode)
		}
	}

	// Fail-closed: with Headscale unreachable, derper still refuses the unknown key.
	r.mustCompose("stop", "headscale")
	if r.derpCheck("random") {
		t.Fatal("FAIL-OPEN: derper accepted an unknown node key while Headscale was down")
	}
	r.mustCompose("start", "headscale")
}
