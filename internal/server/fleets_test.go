package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

var now0 = time.Unix(1_800_000_000, 0)

// fakeHS is an in-memory headscale.API that records what the handler did.
type fakeHS struct {
	headscale.API // methods the handler must not call panic on the nil embedded value
	mu            sync.Mutex
	users         map[string]bool
	calls         []string
	createErr     error
}

func newFakeHS() *fakeHS { return &fakeHS{users: map[string]bool{}} }

func (f *fakeHS) CreateUser(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "create "+name)
	if f.createErr != nil {
		return f.createErr
	}
	f.users[name] = true
	return nil
}

func (f *fakeHS) DeleteUser(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "delete "+name)
	delete(f.users, name)
	return nil
}

func (f *fakeHS) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeHS) userNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for u := range f.users {
		out = append(out, u)
	}
	return out
}

// failingStore wraps a real store and fails CreateFleet.
type failingStore struct{ store.Store }

func (failingStore) CreateFleet(context.Context, store.Fleet) error { return errors.New("disk full") }

type env struct {
	h  http.Handler
	hs *fakeHS
	st store.Store
}

func setup(t *testing.T, mutate func(*Config, *Deps)) env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hs := newFakeHS()
	cfg := Config{CreateRatePerHour: 5, IdleAfter: 720 * time.Hour, LoginServer: "https://relay.example"}
	deps := Deps{Store: st, Headscale: hs, Now: func() time.Time { return now0 }}
	if mutate != nil {
		mutate(&cfg, &deps)
	}
	return env{New(cfg, deps), hs, st}
}

func signedRequest(pub ed25519.PublicKey, priv ed25519.PrivateKey, remote string) *http.Request {
	ts := strconv.FormatInt(now0.Unix(), 10)
	r := httptest.NewRequest(http.MethodPost, "/v1/fleets", nil)
	r.RemoteAddr = remote
	enc := base64.RawURLEncoding
	r.Header.Set("X-Box-Key", enc.EncodeToString(pub))
	r.Header.Set("X-Box-Time", ts)
	r.Header.Set("X-Box-Signature", enc.EncodeToString(ed25519.Sign(priv, []byte("POST /v1/fleets\n"+ts))))
	return r
}

// post sends a correctly signed POST /v1/fleets from the given remote address with a fresh box key.
func (e env) post(t *testing.T, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return e.do(signedRequest(pub, priv, remote), hdr)
}

func (e env) do(r *http.Request, hdr map[string]string) *httptest.ResponseRecorder {
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func TestCreateFleetReturnsSecretOnce(t *testing.T) {
	e := setup(t, nil)
	rec := e.post(t, "192.0.2.1:4000", nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	var body struct {
		FleetID           string `json:"fleet_id"`
		Secret            string `json:"secret"`
		LoginServer       string `json:"login_server"`
		ExpiresInDaysIdle int    `json:"expires_in_days_idle"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.FleetID) != 32 || len(body.Secret) != 64 || body.LoginServer != "https://relay.example" || body.ExpiresInDaysIdle != 30 {
		t.Fatalf("unexpected body %+v", body)
	}
	f, err := e.st.Fleet(context.Background(), body.FleetID)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body.Secret))
	if f.SecretHash == body.Secret || f.SecretHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("stored hash %q is not sha256(secret)", f.SecretHash)
	}
	if f.HeadscaleUser != "f-"+body.FleetID {
		t.Fatalf("headscale user %q", f.HeadscaleUser)
	}
	if got := e.hs.userNames(); len(got) != 1 || got[0] != f.HeadscaleUser {
		t.Fatalf("headscale users %v", got)
	}
}

func TestCreateFleetRateLimited(t *testing.T) {
	e := setup(t, nil)
	// Five creations from one IP, each with a different box key: the limiter counts the IP.
	for i := 0; i < 5; i++ {
		if rec := e.post(t, "192.0.2.1:"+strconv.Itoa(4000+i), nil); rec.Code != http.StatusCreated {
			t.Fatalf("call %d: %d %s", i+1, rec.Code, rec.Body)
		}
	}
	before := e.hs.callCount()
	rec := e.post(t, "192.0.2.1:5000", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th call = %d, want 429", rec.Code)
	}
	if ra, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || ra < 1 || ra > 3600 {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	if e.hs.callCount() != before {
		t.Fatal("rate-limited call reached Headscale")
	}
	if rec := e.post(t, "192.0.2.2:4000", nil); rec.Code != http.StatusCreated {
		t.Fatalf("other IP = %d, want 201", rec.Code)
	}
}

func TestRateLimitRunsBeforeSignatureCheck(t *testing.T) {
	e := setup(t, func(c *Config, _ *Deps) { c.CreateRatePerHour = 1 })
	if rec := e.post(t, "192.0.2.1:1", map[string]string{"X-Box-Signature": "AAAA"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first bad call = %d", rec.Code)
	}
	if rec := e.post(t, "192.0.2.1:1", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("junk calls must consume the IP's quota, got %d", rec.Code)
	}
}

func TestCreateFleetBadSignature(t *testing.T) {
	e := setup(t, nil)
	stale := e.post(t, "192.0.2.1:1", map[string]string{"X-Box-Time": strconv.FormatInt(now0.Unix()-3600, 10)})
	if stale.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", stale.Code)
	}
	if e.hs.callCount() != 0 {
		t.Fatal("Headscale called for an unauthenticated request")
	}
	// A replay is refused with the very same generic body: no hint about the reason.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	if rec := e.do(signedRequest(pub, priv, "192.0.2.3:1"), nil); rec.Code != http.StatusCreated {
		t.Fatalf("first = %d", rec.Code)
	}
	replay := e.do(signedRequest(pub, priv, "192.0.2.3:1"), nil)
	if replay.Code != http.StatusUnauthorized || replay.Body.String() != stale.Body.String() {
		t.Fatalf("replay = %d %q vs %q", replay.Code, replay.Body, stale.Body)
	}
}

func TestCreateFleetBodyTooLarge(t *testing.T) {
	e := setup(t, nil)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := signedRequest(pub, priv, "192.0.2.1:1")
	r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", 2048)))
	rec := e.do(r, nil)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", rec.Code)
	}
	if e.hs.callCount() != 0 {
		t.Fatal("Headscale called")
	}
}

func TestCreateFleetHeadscaleFailure(t *testing.T) {
	e := setup(t, nil)
	e.hs.createErr = errors.New("headscale down: internal-detail")
	rec := e.post(t, "192.0.2.1:1", nil)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "internal-detail") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
}

func TestCreateFleetHookErrorRollsBack(t *testing.T) {
	var got []string
	e := setup(t, func(_ *Config, d *Deps) {
		d.PolicyHook = func(users []string) error { got = users; return errors.New("policy refused") }
	})
	rec := e.post(t, "192.0.2.1:1", nil)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "policy refused") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "f-") {
		t.Fatalf("hook got %v", got)
	}
	if n := len(e.hs.userNames()); n != 0 {
		t.Fatalf("%d Headscale users left", n)
	}
	id := strings.TrimPrefix(got[0], "f-")
	if _, err := e.st.Fleet(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("fleet row left behind: %v", err)
	}
}

func TestCreateFleetStoreFailureDeletesUser(t *testing.T) {
	e := setup(t, func(_ *Config, d *Deps) { d.Store = failingStore{d.Store} })
	rec := e.post(t, "192.0.2.1:1", nil)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "disk full") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if n := len(e.hs.userNames()); n != 0 {
		t.Fatalf("%d Headscale users left", n)
	}
	if len(e.hs.calls) != 2 || !strings.HasPrefix(e.hs.calls[1], "delete f-") {
		t.Fatalf("calls %v", e.hs.calls)
	}
}

func TestClientIPKeying(t *testing.T) {
	trusted := func(c *Config, _ *Deps) { c.TrustedProxyHeader = "X-Forwarded-For"; c.CreateRatePerHour = 2 }
	codes := func(e env, n int, remote func(i int) string, hdr func(i int) map[string]string) []int {
		var out []int
		for i := 0; i < n; i++ {
			out = append(out, e.post(t, remote(i), hdr(i)).Code)
		}
		return out
	}
	same := func(s string) func(int) string { return func(int) string { return s } }
	want := func(t *testing.T, got []int, w ...int) {
		t.Helper()
		if len(got) != len(w) {
			t.Fatalf("got %v, want %v", got, w)
		}
		for i := range w {
			if got[i] != w[i] {
				t.Fatalf("got %v, want %v", got, w)
			}
		}
	}

	t.Run("no trusted header: X-Forwarded-For is ignored", func(t *testing.T) {
		e := setup(t, func(c *Config, _ *Deps) { c.CreateRatePerHour = 2 })
		got := codes(e, 3, same("192.0.2.1:1"), func(i int) map[string]string {
			return map[string]string{"X-Forwarded-For": "10.0.0." + strconv.Itoa(i)}
		})
		want(t, got, 201, 201, 429)
	})

	t.Run("trusted header: the last value is the client, spoofed first hops do not help", func(t *testing.T) {
		e := setup(t, trusted)
		got := codes(e, 3, same("172.18.0.5:1"), func(i int) map[string]string {
			return map[string]string{"X-Forwarded-For": "10.0." + strconv.Itoa(i) + ".1, 198.51.100.7"}
		})
		want(t, got, 201, 201, 429)
		if c := e.post(t, "172.18.0.5:1", map[string]string{"X-Forwarded-For": "198.51.100.8"}).Code; c != 201 {
			t.Fatalf("other client = %d", c)
		}
	})

	t.Run("trusted header on separate lines: the last line wins", func(t *testing.T) {
		e := setup(t, trusted)
		var got []int
		for _, first := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
			pub, priv, _ := ed25519.GenerateKey(rand.Reader)
			r := signedRequest(pub, priv, "172.18.0.5:1")
			r.Header.Add("X-Forwarded-For", first)
			r.Header.Add("X-Forwarded-For", "198.51.100.7")
			got = append(got, e.do(r, nil).Code)
		}
		want(t, got, 201, 201, 429)
	})

	t.Run("trusted header missing or garbage: falls back to the peer address", func(t *testing.T) {
		e := setup(t, trusted)
		got := codes(e, 3, same("172.18.0.5:1"), func(i int) map[string]string {
			if i == 1 {
				return map[string]string{"X-Forwarded-For": "not-an-ip"}
			}
			return nil
		})
		want(t, got, 201, 201, 429)
	})

	t.Run("IPv6 clients are keyed by their /64", func(t *testing.T) {
		e := setup(t, func(c *Config, _ *Deps) { c.CreateRatePerHour = 2 })
		a, b, c := "[2001:db8:1:2:aaaa::1]:1", "[2001:db8:1:2:bbbb::9]:1", "[2001:db8:1:3::1]:1" // a and b share a /64
		got := []int{e.post(t, a, nil).Code, e.post(t, b, nil).Code, e.post(t, a, nil).Code, e.post(t, c, nil).Code}
		want(t, got, 201, 201, 429, 201)
	})

	t.Run("trusted header, IPv6 client", func(t *testing.T) {
		e := setup(t, trusted)
		got := codes(e, 3, same("172.18.0.5:1"), func(i int) map[string]string {
			return map[string]string{"X-Forwarded-For": "2001:db8:9:9:" + strconv.Itoa(i+1) + "::1"}
		})
		want(t, got, 201, 201, 429)
	})
}
