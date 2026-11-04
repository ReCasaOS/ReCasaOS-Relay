package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/fakes"
	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

const token = "0123456789abcdef0123456789abcdef"

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

type env struct {
	h  http.Handler
	hs *fakes.HS
	st store.Store
}

func setup(t *testing.T) env {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hs := fakes.NewHS(&fakes.Log{}, func() time.Time { return t0 })
	for _, id := range []string{"aaaa", "bbbb"} {
		if err := st.CreateFleet(context.Background(), store.Fleet{ID: id, SecretHash: "x", HeadscaleUser: "f-" + id, CreatedAt: t0.Add(-time.Hour)}); err != nil {
			t.Fatal(err)
		}
		hs.AddUser("f-" + id)
	}
	hs.AddNode("f-aaaa", "b-one", true)
	hs.AddNode("f-bbbb", "b-two", false)
	h, err := New(Config{Token: token, NodesPerFleet: 50, MaxFleets: 1000}, Deps{
		Store: st, Headscale: hs, Now: func() time.Time { return t0 },
		Remover: &fleets.Remover{Store: st, Headscale: hs, Locks: &fleets.Locks{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return env{h, hs, st}
}

func (e env) do(method, path, pass string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if pass != "" {
		r.SetBasicAuth("admin", pass)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	return w
}

func csrf(e env) url.Values {
	body := e.do("GET", "/admin/", token, nil).Body.String()
	i := strings.Index(body, `name="csrf" value="`) + len(`name="csrf" value="`)
	return url.Values{"csrf": {body[i : i+strings.Index(body[i:], `"`)]}}
}

func TestShortTokenRefused(t *testing.T) {
	if _, err := New(Config{Token: "short"}, Deps{}); err == nil {
		t.Fatal("a short token was accepted")
	}
}

func TestAuthRequired(t *testing.T) {
	e := setup(t)
	for _, pass := range []string{"", "wrong"} {
		if w := e.do("GET", "/admin/", pass, nil); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("pass %q: %d", pass, w.Code)
		}
	}
	if w := e.do("POST", "/admin/fleets/aaaa/delete", "wrong", nil); w.Code != 401 {
		t.Fatalf("post without the token: %d", w.Code)
	}
}

func TestIndexListsFleetsAndNodes(t *testing.T) {
	e := setup(t)
	w := e.do("GET", "/admin/", token, nil)
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	for _, want := range []string{"aaaa", "bbbb", "b-one", "b-two", "1 / 2", "2 / 1000"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestIndexShowsNodeDetails(t *testing.T) {
	e := setup(t)
	// b-two is offline: addresses, "last seen", and a key expiry in the future.
	e.hs.SetNodeInfo("f-bbbb", "b-two", []string{"100.64.0.2", "fd7a::2"},
		t0.Add(-3*time.Hour), t0.Add(72*time.Hour))
	// b-one's key is already expired.
	e.hs.SetNodeInfo("f-aaaa", "b-one", []string{"100.64.0.1"}, t0, t0.Add(-time.Minute))
	body := e.do("GET", "/admin/", token, nil).Body.String()
	for _, want := range []string{"100.64.0.2, fd7a::2", "3 h ago", "expires in 3 d", "key expired"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestPostNeedsCSRF(t *testing.T) {
	e := setup(t)
	if w := e.do("POST", "/admin/fleets/aaaa/delete", token, nil); w.Code != 400 {
		t.Fatalf("without csrf: %d", w.Code)
	}
	if _, err := e.st.Fleet(context.Background(), "aaaa"); err != nil {
		t.Fatal("fleet deleted without csrf")
	}
}

func TestDeleteFleet(t *testing.T) {
	e := setup(t)
	if w := e.do("POST", "/admin/fleets/aaaa/delete", token, csrf(e)); w.Code != 303 {
		t.Fatalf("%d", w.Code)
	}
	if _, err := e.st.Fleet(context.Background(), "aaaa"); err != store.ErrNotFound {
		t.Fatalf("fleet still there: %v", err)
	}
	if e.hs.HasUser("f-aaaa") || e.hs.NodeCount("f-aaaa") != 0 {
		t.Fatal("headscale user or nodes left")
	}
	if !e.hs.HasUser("f-bbbb") {
		t.Fatal("another fleet was touched")
	}
}

func TestRemoveNodeOnlyInItsFleet(t *testing.T) {
	e := setup(t)
	nodes, _ := e.hs.ListNodes(context.Background(), "f-bbbb")
	id := nodes[0].ID
	// the node of bbbb, asked through aaaa: nothing happens
	e.do("POST", "/admin/fleets/aaaa/nodes/"+id+"/remove", token, csrf(e))
	if e.hs.NodeCount("f-bbbb") != 1 {
		t.Fatal("removed a node of another fleet")
	}
	if w := e.do("POST", "/admin/fleets/bbbb/nodes/"+id+"/remove", token, csrf(e)); w.Code != 303 {
		t.Fatalf("%d", w.Code)
	}
	if e.hs.NodeCount("f-bbbb") != 0 || e.hs.NodeCount("f-aaaa") != 1 {
		t.Fatal("wrong nodes left")
	}
}

func TestRateLimited(t *testing.T) {
	e := setup(t)
	var last int
	for i := 0; i <= requestsPerHour; i++ {
		last = e.do("GET", "/admin/", "wrong", nil).Code
	}
	if last != 429 {
		t.Fatalf("request %d: %d, want 429", requestsPerHour+1, last)
	}
	if w := e.do("GET", "/admin/", token, nil); w.Code != 429 {
		t.Fatalf("the right token is not tried once limited: %d", w.Code)
	}
}

func TestAuthenticatedRequestsAreNotLimited(t *testing.T) {
	e := setup(t)
	for i := 0; i < 300; i++ {
		if w := e.do("GET", "/admin/", token, nil); w.Code != 200 {
			t.Fatalf("request %d: %d", i+1, w.Code)
		}
	}
}

func TestFailedAuthIsLimited(t *testing.T) {
	e := setup(t)
	for i := 0; i < requestsPerHour; i++ {
		if w := e.do("GET", "/admin/", "wrong", nil); w.Code != 401 {
			t.Fatalf("request %d: %d, want 401", i+1, w.Code)
		}
	}
	if w := e.do("GET", "/admin/", token, nil); w.Code != 429 {
		t.Fatalf("right token after the limit: %d, want 429", w.Code)
	}
}
