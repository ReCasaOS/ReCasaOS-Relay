//go:build e2e

// Package e2e proves the one property the relay exists for: a fleet never reaches another.
//
// It needs Docker and runs the real stack (Headscale, derper, the front Caddy, the enrolment service) plus
// one tailscaled container per node, each registered with a join key obtained through the real
// HTTP API:
//
//	go test -tags e2e ./e2e -run TestFleetsAreIsolated -v -timeout 15m
//
// E2E_NEUTRALISE_POLICY=allow-all (or empty) replaces the policy by a permissive one behind the
// service's back before the cross-fleet checks; the test must then FAIL. That is how the test is
// shown to have teeth.
package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
)

const (
	loginServer = "https://relay.test"
	probePort   = "9000"
)

type rig struct {
	t                      *testing.T
	proj                   string
	root                   string // repository root (compose project directory)
	apiKey                 string
	hs                     *headscale.Client
	hsURL                  string // Headscale on loopback (admin API; the test's own way in)
	frontURL               string // the public front, as boxes reach it
	pebbleACME, pebbleMgmt string // Pebble's ACME directory and management ports, mapped on loopback
	shareAddr              string // share's public 443, mapped on loopback
	caFile                 string
	ts                     map[string]*node
	fleetUser              map[string]string // fleet name -> Headscale user
	env                    []string          // extra variables for docker compose (compose.yaml interpolates them)
	nodeEnv                []string          // extra variables for every tailscaled container (docker create -e)
}

type node struct {
	name, container, fleet, ip string
}

func sh(name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func (r *rig) compose(args ...string) (string, error) {
	full := append([]string{"compose", "-p", r.proj,
		"-f", filepath.Join(r.root, "compose.yaml"), "-f", filepath.Join(r.root, "e2e", "compose.e2e.yaml")}, args...)
	cmd := exec.Command("docker", full...)
	cmd.Dir = r.root
	cmd.Env = append(append(os.Environ(), "HEADSCALE_API_KEY="+r.apiKey), r.env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func (r *rig) mustCompose(args ...string) string {
	r.t.Helper()
	out, err := r.compose(args...)
	if err != nil {
		r.t.Fatalf("docker compose %s: %v\n%s", args[0], err, out)
	}
	return out
}

func eventually(t *testing.T, what string, timeout time.Duration, f func() error) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var err error
	for {
		if err = f(); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: still failing after %s: %v", what, timeout, err)
		}
		time.Sleep(time.Second)
	}
}

func newRig(t *testing.T) *rig {
	t.Helper()
	if _, err := sh("docker", "version"); err != nil {
		t.Skip("docker is not available")
	}
	wd, _ := os.Getwd()
	var b [4]byte
	rand.Read(b[:])
	r := &rig{t: t, proj: "rre2e" + hex.EncodeToString(b[:]), root: filepath.Dir(wd),
		ts: map[string]*node{}, fleetUser: map[string]string{}, env: []string{"DERPER_DEBUG_KEY=" + derperDebugKey}}
	t.Cleanup(func() {
		if os.Getenv("E2E_KEEP") != "" { // debugging: leave the stack up (remove it yourself)
			t.Logf("kept project %s", r.proj)
			return
		}
		out, _ := sh("docker", "ps", "-aq", "--filter", "label=rre2e.project="+r.proj)
		if ids := strings.Fields(out); len(ids) > 0 {
			sh("docker", append([]string{"rm", "-f"}, ids...)...)
		}
		r.compose("down", "-v", "--remove-orphans")
	})
	return r
}

// up starts the stack: Headscale first (to mint the API key), then the rest.
func (r *rig) up() {
	t := r.t
	r.mustCompose("up", "-d", "headscale")
	eventually(t, "apikeys create", 60*time.Second, func() error {
		out, err := r.compose("exec", "-T", "headscale", "headscale", "apikeys", "create")
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		lines := strings.Split(out, "\n")
		r.apiKey = strings.TrimSpace(lines[len(lines)-1])
		return nil
	})
	r.mustCompose("up", "-d", "--build", "derper", "enrolment", "front", "tlsfront", "share", "pebble")
	r.hsURL = "http://" + r.mustCompose("port", "headscale", "8080")
	r.frontURL = "http://" + r.mustCompose("port", "front", "8080")
	r.shareAddr = r.mustCompose("port", "share", "443")
	r.pebbleACME = r.mustCompose("port", "pebble", "14000")
	r.pebbleMgmt = r.mustCompose("port", "pebble", "15000")
	r.hs = headscale.New(r.hsURL, r.apiKey, nil)

	// The service must not answer before the deny-by-default policy is in place.
	eventually(t, "enrolment answers", 90*time.Second, func() error {
		resp, err := http.Get(r.frontURL + "/v1/fleets/00000000000000000000000000000000")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(body), "fleet not found") {
			return fmt.Errorf("status %d: %s", resp.StatusCode, body)
		}
		return nil
	})
	if got := r.policy(); got != `{"groups":{},"acls":[]}` {
		t.Fatalf("policy after startup = %s, want the explicit deny-all", got)
	}

	// Caddy's internal root CA, for the tailscale containers (the client insists on TLS).
	r.caFile = filepath.Join(t.TempDir(), "relay-ca.crt")
	eventually(t, "caddy root CA", 60*time.Second, func() error {
		out, err := r.compose("cp", "tlsfront:/data/caddy/pki/authorities/local/root.crt", r.caFile)
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	})
}

// dialSNI opens a TCP connection to share's 443 and returns it as a TLS client for serverName (trusting
// tlsfront's CA). The handshake is lazy (first Read/Write), so a peer that closes without answering shows
// up as io.EOF on Read.
func (r *rig) dialSNI(serverName string) (*tls.Conn, error) {
	pem, err := os.ReadFile(r.caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	c, err := net.DialTimeout("tcp", r.shareAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return tls.Client(c, &tls.Config{ServerName: serverName, RootCAs: pool}), nil
}

func (r *rig) hsDo(method, path string, body any) []byte {
	r.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, r.hsURL+path, rd)
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		r.t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, out)
	}
	return out
}

// policy returns the policy text Headscale currently enforces.
func (r *rig) policy() string {
	var res struct{ Policy string }
	if err := json.Unmarshal(r.hsDo("GET", "/api/v1/policy", nil), &res); err != nil {
		r.t.Fatal(err)
	}
	return res.Policy
}

// createFleet calls POST /v1/fleets with a fresh, correctly signed box key.
func (r *rig) createFleet(name string) (id, secret string) {
	t := r.t
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	enc := base64.RawURLEncoding
	req, _ := http.NewRequest("POST", r.frontURL+"/v1/fleets", nil)
	req.Header.Set("X-Box-Key", enc.EncodeToString(pub))
	req.Header.Set("X-Box-Time", ts)
	req.Header.Set("X-Box-Signature", enc.EncodeToString(ed25519.Sign(priv, []byte("POST /v1/fleets\n"+ts))))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		FleetID string `json:"fleet_id"`
		Secret  string `json:"secret"`
		Login   string `json:"login_server"`
	}
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(raw, &body) != nil || body.FleetID == "" {
		t.Fatalf("create fleet %s: %d (body withheld)", name, resp.StatusCode)
	}
	if body.Login != loginServer {
		t.Fatalf("login_server = %q", body.Login)
	}
	r.fleetUser[name] = "f-" + body.FleetID
	return body.FleetID, body.Secret
}

func (r *rig) joinKey(id, secret string) string {
	r.t.Helper()
	req, _ := http.NewRequest("POST", r.frontURL+"/v1/fleets/"+id+"/keys", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct{ Key string }
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(raw, &body) != nil || body.Key == "" {
		r.t.Fatalf("join key: %d (body withheld)", resp.StatusCode)
	}
	return body.Key
}

// usedKeys counts the used and unused pre-auth keys of a fleet's user.
func (r *rig) usedKeys(user string) (used, unused int) {
	r.t.Helper()
	keys, err := r.hs.ListPreAuthKeys(context.Background(), user)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, k := range keys {
		if k.Used {
			used++
		} else {
			unused++
		}
	}
	return
}

// startNode runs a tailscaled container for fleet, registers it with key and waits for its address.
func (r *rig) startNode(fleet, name, key string) *node {
	return r.startNodeAs(fleet, name, name, key)
}

// startNodeAs is startNode with a container name (suffix) that differs from the hostname, so two
// nodes can share a hostname.
func (r *rig) startNodeAs(fleet, name, ctr, key string) *node {
	n := r.launch(fleet, name, ctr, key)
	r.t.Helper()
	eventually(r.t, name+" gets an address", 90*time.Second, func() error { return r.fetchIP(n) })
	r.listen(n)
	return n
}

// startNodeWeb starts a node without a key: tailscaled asks for a web login. It returns the node
// (no address yet) and the login URL tailscale shows, taken from `tailscale status --json`.
func (r *rig) startNodeWeb(fleet, name string) (n *node, authURL string) {
	n = r.launch(fleet, name, name, "")
	eventually(r.t, name+" shows a login URL", 90*time.Second, func() error {
		out, _ := sh("docker", "exec", n.container, "tailscale", "status", "--json")
		var st struct{ AuthURL string }
		if json.Unmarshal([]byte(out), &st) != nil || st.AuthURL == "" {
			return fmt.Errorf("no AuthURL yet: %.200s", out)
		}
		authURL = st.AuthURL
		return nil
	})
	return n, authURL
}

// launch creates and starts the tailscaled container; an empty key means no TS_AUTHKEY (web login).
// An entrypoint (program, then its arguments) replaces the image's containerboot.
func (r *rig) launch(fleet, name, ctr, key string, entrypoint ...string) *node {
	t := r.t
	n := &node{name: ctr, container: r.proj + "-" + ctr, fleet: fleet}
	args := []string{"create", "--name", n.container, "--hostname", name,
		"--label", "rre2e.project=" + r.proj, "--network", r.proj + "_default",
		"--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--device", "/dev/net/tun:/dev/net/tun",
		"-e", "TS_USERSPACE=false", "-e", "TS_HOSTNAME=" + name, "-e", "TS_STATE_DIR=/var/lib/tailscale",
		"-e", "TS_EXTRA_ARGS=--login-server=" + loginServer, "-e", "SSL_CERT_FILE=/relay-ca.crt"}
	if key != "" {
		args = append(args, "-e", "TS_AUTHKEY="+key)
	}
	for _, e := range r.nodeEnv {
		args = append(args, "-e", e)
	}
	if len(entrypoint) > 0 {
		args = append(args, "--entrypoint", entrypoint[0])
	}
	args = append(args, "tailscale/tailscale:v1.104.4") // pinned: what :stable was when this was last run
	if len(entrypoint) > 0 {
		args = append(args, entrypoint[1:]...)
	}
	out, err := sh("docker", args...)
	if err != nil {
		t.Fatalf("docker create %s: %v\n%s", name, err, out)
	}
	if out, err := sh("docker", "cp", r.caFile, n.container+":/relay-ca.crt"); err != nil {
		t.Fatalf("docker cp CA: %v\n%s", err, out)
	}
	if out, err := sh("docker", "start", n.container); err != nil {
		t.Fatalf("docker start %s: %v\n%s", name, err, out)
	}
	r.ts[ctr] = n
	return n
}

// fetchIP records the node's tailnet IPv4 once it has one.
func (r *rig) fetchIP(n *node) error {
	ip, err := sh("docker", "exec", n.container, "tailscale", "ip", "-4")
	if err != nil || ip == "" || strings.ContainsAny(ip, " \n") {
		return fmt.Errorf("no address yet: %v %s", err, ip)
	}
	n.ip = ip
	return nil
}

// listen starts a TCP listener to connect to over the tailnet, restarted by the loop after each probe.
func (r *rig) listen(n *node) {
	if out, err := sh("docker", "exec", "-d", n.container, "sh", "-c",
		"while true; do nc -l -p "+probePort+" >/dev/null 2>&1; done"); err != nil {
		r.t.Fatalf("listener %s: %v\n%s", n.name, err, out)
	}
}

func (r *rig) tcpReach(from, to *node) bool {
	_, err := sh("docker", "exec", from.container, "nc", "-z", "-w", "2", to.ip, probePort)
	return err == nil
}

func (r *rig) pingReach(from, to *node) bool {
	// --until-direct=false: a pong relayed by DERP counts (with -c 1 the default fails on it).
	_, err := sh("docker", "exec", from.container, "tailscale", "ping", "--until-direct=false", "-c", "1", "--timeout", "3s", to.ip)
	return err == nil
}

// mustReach waits until from reaches to by tailscale ping and by a TCP connect.
func (r *rig) mustReach(from, to *node) {
	r.t.Helper()
	eventually(r.t, fmt.Sprintf("%s reaches %s", from.name, to.name), 60*time.Second, func() error {
		if !r.pingReach(from, to) {
			return fmt.Errorf("tailscale ping fails")
		}
		if !r.tcpReach(from, to) {
			return fmt.Errorf("tcp connect to %s:%s fails", to.ip, probePort)
		}
		return nil
	})
}

// mustNotReach fails if any from -> to pair reaches, by TCP connect or tailscale ping, at any time
// in a window long enough for a netmap update to arrive. The pairs are probed concurrently.
func (r *rig) mustNotReach(pairs ...[2]*node) {
	r.t.Helper()
	var wg sync.WaitGroup
	for _, p := range pairs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			from, to := p[0], p[1]
			for i := 0; i < 3; i++ {
				if r.tcpReach(from, to) {
					r.t.Errorf("ISOLATION BROKEN: %s (fleet %s) connected to %s (fleet %s) over TCP", from.name, from.fleet, to.name, to.fleet)
					return
				}
				time.Sleep(time.Second)
			}
			if r.pingReach(from, to) {
				r.t.Errorf("ISOLATION BROKEN: %s (fleet %s) pinged %s (fleet %s)", from.name, from.fleet, to.name, to.fleet)
			}
		}()
	}
	wg.Wait()
}

// peers returns the hostnames in from's network map.
func (r *rig) peers(from *node) []string {
	r.t.Helper()
	out, err := sh("docker", "exec", from.container, "tailscale", "status", "--json")
	if err != nil {
		r.t.Fatalf("status %s: %v", from.name, err)
	}
	var st struct {
		Peer map[string]struct{ HostName string }
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		r.t.Fatalf("status %s: %v", from.name, err)
	}
	var names []string
	for _, p := range st.Peer {
		names = append(names, p.HostName)
	}
	return names
}

// mustSeePeers waits until n's network map holds exactly the named peers. The netmap is computed by
// Headscale from the policy, so unlike a failed probe this cannot pass because of a broken data plane.
func (r *rig) mustSeePeers(n *node, want ...string) {
	r.t.Helper()
	sort.Strings(want)
	eventually(r.t, n.name+" netmap", 30*time.Second, func() error {
		got := r.peers(n)
		sort.Strings(got)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			return fmt.Errorf("peers = %v, want %v", got, want)
		}
		return nil
	})
}

func (r *rig) neutralise() {
	var p string
	switch os.Getenv("E2E_NEUTRALISE_POLICY") {
	case "":
		return
	case "allow-all":
		p = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
	case "empty":
		p = `{}`
	default:
		r.t.Fatalf("unknown E2E_NEUTRALISE_POLICY %q", os.Getenv("E2E_NEUTRALISE_POLICY"))
	}
	r.t.Logf("NEUTRALISING the policy with %s: the isolation checks below are expected to FAIL", p)
	if err := r.hs.SetPolicy(context.Background(), []byte(p)); err != nil {
		r.t.Fatal(err)
	}
	time.Sleep(5 * time.Second) // let the new netmaps reach the nodes
}

func TestFleetsAreIsolated(t *testing.T) {
	r := newRig(t)
	r.up()
	// Subtests report through r.t, which must be the subtest's own *testing.T.
	run := func(name string, f func(t *testing.T)) {
		t.Run(name, func(st *testing.T) {
			r.t = st
			defer func() { r.t = t }()
			f(st)
		})
	}

	idA, secA := r.createFleet("A")
	idB, secB := r.createFleet("B")
	userA, userB := r.fleetUser["A"], r.fleetUser["B"]

	// The policy covers both fleets: every fleet in the store, not just the newest.
	pol := r.policy()
	for _, u := range []string{userA, userB} {
		if !strings.Contains(pol, `"group:`+u+`":["`+u+`@"]`) || !strings.Contains(pol, `"dst":["group:`+u+`:*"]`) {
			t.Fatalf("policy lacks fleet %s: %s", u, pol)
		}
	}

	// Join keys: a fresh key is unused; registering a node with it flips "used".
	keyA1 := r.joinKey(idA, secA)
	if used, unused := r.usedKeys(userA); used != 0 || unused != 1 {
		t.Fatalf("fresh key: used=%d unused=%d, want 0 and 1", used, unused)
	}
	a1 := r.startNode("A", "a1", keyA1)
	eventually(t, "A's key is marked used", 30*time.Second, func() error {
		if used, unused := r.usedKeys(userA); used != 1 || unused != 0 {
			return fmt.Errorf("used=%d unused=%d", used, unused)
		}
		return nil
	})
	a2 := r.startNode("A", "a2", r.joinKey(idA, secA))
	b1 := r.startNode("B", "b1", r.joinKey(idB, secB))

	run("within a fleet nodes reach each other", func(t *testing.T) {
		r.mustReach(a1, a2)
		r.mustReach(a2, a1)
		r.mustSeePeers(a1, "a2")
		r.mustSeePeers(a2, "a1")
	})

	r.neutralise() // no-op unless E2E_NEUTRALISE_POLICY is set (teeth check)

	run("across fleets nothing reaches", func(t *testing.T) {
		r.mustNotReach([2]*node{a1, b1}, [2]*node{a2, b1}, [2]*node{b1, a1}, [2]*node{b1, a2})
		r.mustSeePeers(b1) // alone in its fleet
		r.mustSeePeers(a1, "a2")
	})

	// A node re-registers: new container, fresh key, the old Headscale node removed first.
	run("after b1 re-registers", func(t *testing.T) {
		if out, err := sh("docker", "rm", "-f", b1.container); err != nil {
			t.Fatalf("rm b1: %v %s", err, out)
		}
		if err := r.hs.DeleteNode(context.Background(), userB, "b1"); err != nil {
			t.Fatal(err)
		}
		b1 = r.startNode("B", "b1", r.joinKey(idB, secB))
		r.mustNotReach([2]*node{a1, b1}, [2]*node{b1, a1}, [2]*node{b1, a2})
		r.mustSeePeers(b1)
		r.mustSeePeers(a1, "a2")
	})

	// A third fleet is a second (and third) policy sync; the earlier fleets must keep working and
	// stay apart.
	var c1 *node
	run("after a second policy sync", func(t *testing.T) {
		idC, secC := r.createFleet("C")
		c1 = r.startNode("C", "c1", r.joinKey(idC, secC))
		r.mustReach(a1, a2)
		r.mustReach(a2, a1)
		r.mustNotReach([2]*node{a1, b1}, [2]*node{b1, a1}, [2]*node{a1, c1}, [2]*node{c1, a1},
			[2]*node{b1, c1}, [2]*node{c1, b1}, [2]*node{c1, a2})
		r.mustSeePeers(a1, "a2")
		r.mustSeePeers(a2, "a1")
		r.mustSeePeers(b1)
		r.mustSeePeers(c1)
		// a1's key was used, then deleted by the key request for a2 (requests prune spent keys).
		if used, unused := r.usedKeys(userA); used != 1 || unused != 0 {
			t.Errorf("fleet A keys: used=%d unused=%d, want 1 (a2's) and 0", used, unused)
		}
	})

	// Positive control, run every time: the "unreachable" results above would also come out of a
	// broken data plane or a failed docker exec. Open the policy wide and require the very same
	// probes to succeed from b1 and c1 (alone in their fleets, so nothing else shows they carry
	// traffic), then restore the policy and require isolation again.
	run("control: probes succeed when the policy allows, isolation returns when restored", func(t *testing.T) {
		saved := r.policy()
		restore := func() {
			if err := r.hs.SetPolicy(context.Background(), []byte(saved)); err != nil {
				t.Errorf("restoring the policy: %v", err)
			}
		}
		restored := false
		defer func() {
			if !restored {
				restore()
			}
		}()
		if err := r.hs.SetPolicy(context.Background(), []byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`)); err != nil {
			t.Fatal(err)
		}
		r.mustSeePeers(a1, "a2", "b1", "c1") // polls until the new netmap has arrived
		r.mustReach(a1, b1)
		r.mustReach(b1, a1)
		r.mustReach(c1, a1)

		restore()
		restored = true
		if got := r.policy(); got != saved {
			t.Fatalf("policy after restore differs: got %s, want %s", got, saved)
		}
		r.mustSeePeers(a1, "a2")
		r.mustSeePeers(a2, "a1")
		r.mustSeePeers(b1)
		r.mustSeePeers(c1)
		r.mustNotReach([2]*node{a1, b1}, [2]*node{b1, a1}, [2]*node{c1, a1}, [2]*node{a1, c1},
			[2]*node{b1, c1}, [2]*node{c1, b1})
		r.mustReach(a1, a2)
	})

	run("findings on deleting a Headscale user", func(t *testing.T) { deletionFindings(t, r) })
}

// deletionFindings records, for the fleet-deletion task, what Headscale does with a user's pre-auth
// keys and nodes when the user is deleted. It asserts nothing.
func deletionFindings(t *testing.T, r *rig) {
	ctx := context.Background()
	keyCount := func(user string) (n int) {
		var res struct {
			PreAuthKeys []struct{ User struct{ Name string } }
		}
		json.Unmarshal(r.hsDo("GET", "/api/v1/preauthkey", nil), &res)
		for _, k := range res.PreAuthKeys {
			if k.User.Name == user {
				n++
			}
		}
		return
	}
	totalKeys := func() int {
		var res struct{ PreAuthKeys []json.RawMessage }
		json.Unmarshal(r.hsDo("GET", "/api/v1/preauthkey", nil), &res)
		return len(res.PreAuthKeys)
	}

	var b [16]byte
	rand.Read(b[:])
	u := "f-" + hex.EncodeToString(b[:])
	if err := r.hs.CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := r.hs.CreatePreAuthKey(ctx, u, time.Hour); err != nil {
		t.Fatal(err)
	}
	before, total := keyCount(u), totalKeys()
	err := r.hs.DeleteUser(ctx, u)
	t.Logf("FINDING keys: user without nodes, 1 unused key: delete err=%v; keys of that user %d -> %d; all keys %d -> %d",
		err, before, keyCount(u), total, totalKeys())

	cUser := r.fleetUser["C"]
	nodesBefore, _ := r.hs.ListNodes(ctx, cUser)
	err = r.hs.DeleteUser(ctx, cUser)
	var all struct{ Nodes []struct{ Name string } }
	json.Unmarshal(r.hsDo("GET", "/api/v1/node", nil), &all)
	var names []string
	for _, n := range all.Nodes {
		names = append(names, n.Name)
	}
	t.Logf("FINDING nodes: user with %d node(s) and 1 used key: delete err=%v; keys left for the user %d; nodes still listed: %v",
		len(nodesBefore), err, keyCount(cUser), names)

	// Task 7 order: nodes first, then the user.
	derr := r.hs.DeleteNode(ctx, cUser, "c1")
	err = r.hs.DeleteUser(ctx, cUser)
	t.Logf("FINDING order: delete node c1 (err=%v), then the user: err=%v; keys left for the user %d", derr, err, keyCount(cUser))
}
