package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

type shareEnv struct {
	delEnv
	seq int // distinct box times: a signature is accepted once
}

type box struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	key  string
	node string
}

func setupShare(t *testing.T, mutate func(*Config)) *shareEnv {
	t.Helper()
	return &shareEnv{delEnv: setupDel(t, func(c *Config) {
		c.ShareDomain = "share.example"
		c.ShareQuarantine = 24 * time.Hour
		c.ShareACMETTL = 10 * time.Minute
		c.ShareACMERatePerHour = 20
		c.TrustedProxyHeader = "X-Client-IP"
		if mutate != nil {
			mutate(c)
		}
	})}
}

// newBox adds a node to the fleet and returns a key pair for it, not yet linked.
func (e *shareEnv) newBox(t *testing.T, host string) box {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return box{pub, priv, base64.RawURLEncoding.EncodeToString(pub), e.hs.AddNode(e.user, host, true)}
}

func (e *shareEnv) link(b box) *httptest.ResponseRecorder {
	body := `{"box_key":"` + b.key + `"}`
	r := httptest.NewRequest(http.MethodPut, "/v1/fleets/"+e.id+"/nodes/"+b.node+"/box-key", strings.NewReader(body))
	r.RemoteAddr = ip1
	r.Header.Set("Authorization", "Bearer "+e.secret)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func (e *shareEnv) linked(t *testing.T, host string) box {
	t.Helper()
	b := e.newBox(t, host)
	if rec := e.link(b); rec.Code != http.StatusNoContent {
		t.Fatalf("link: %d %s", rec.Code, rec.Body)
	}
	return b
}

// as sends a request signed by b.
func (e *shareEnv) as(b box, method, path, body string) *httptest.ResponseRecorder {
	e.seq++
	ts := strconv.FormatInt(now0.Unix()+int64(e.seq%100), 10)
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = ip1
	r.Header.Set("X-Box-Key", b.key)
	r.Header.Set("X-Box-Time", ts)
	r.Header.Set("X-Box-Signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(b.priv, []byte(method+" "+path+"\n"+ts))))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, code int, body string) {
	t.Helper()
	if rec.Code != code {
		t.Fatalf("status %d, want %d: %s", rec.Code, code, rec.Body)
	}
	if body != "" {
		var got, want map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("body %q: %v", rec.Body, err)
		}
		if err := json.Unmarshal([]byte(body), &want); err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Fatalf("body %s, want %s", rec.Body, body)
		}
		for k, v := range want {
			if got[k] != v {
				t.Fatalf("body %s, want %s", rec.Body, body)
			}
		}
	}
}

func TestBoxKeyRouteNeedsSecretAndNodeInFleet(t *testing.T) {
	e := setupShare(t, nil)
	b := e.newBox(t, "box-a")
	put := func(secret, node, key string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/v1/fleets/"+e.id+"/nodes/"+node+"/box-key", strings.NewReader(`{"box_key":"`+key+`"}`))
		r.RemoteAddr = ip1
		r.Header.Set("Authorization", "Bearer "+secret)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, r)
		return rec
	}
	wantStatus(t, put("wrong", b.node, b.key), 401, `{"error":"unauthorized"}`)
	wantStatus(t, put(e.secret, "9999", b.key), 404, `{"error":"node not found"}`)
	wantStatus(t, put(e.secret, b.node, "short"), 400, `{"error":"invalid box key"}`)
	wantStatus(t, put(e.secret, b.node, base64.RawURLEncoding.EncodeToString(make([]byte, 31))), 400, `{"error":"invalid box key"}`)
	rec := put(e.secret, b.node, b.key)
	wantStatus(t, rec, 204, "")
	ref, err := e.st.BoxByKey(t.Context(), b.key)
	if err != nil || ref.NodeID != b.node || ref.FleetID != e.id || ref.Name != "" {
		t.Fatalf("BoxByKey = %+v, %v", ref, err)
	}
	// upsert by node: a new key replaces the old one
	b2 := e.newBox(t, "box-b")
	wantStatus(t, put(e.secret, b.node, b2.key), 204, "")
	if _, err := e.st.BoxByKey(t.Context(), b.key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("old key still linked: %v", err)
	}
	// a key already linked to another node
	wantStatus(t, put(e.secret, b2.node, b2.key), 409, `{"error":"box key already linked"}`)
	big := httptest.NewRequest(http.MethodPut, "/v1/fleets/"+e.id+"/nodes/"+b.node+"/box-key", strings.NewReader(`{"box_key":"`+strings.Repeat("a", 2000)+`"}`))
	big.RemoteAddr = ip1
	big.Header.Set("Authorization", "Bearer "+e.secret)
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, big)
	wantStatus(t, rec, 413, "")
}

func TestClaimNameFlow(t *testing.T) {
	e := setupShare(t, nil)
	ctx := t.Context()
	a := e.newBox(t, "box-a")
	wantStatus(t, e.as(a, "PUT", "/v1/share/name", `{"name":"abc"}`), 403, `{"error":"box key not linked"}`)
	if rec := e.link(a); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	want := `{"name":"abc","host":"abc.share.example","domain":"share.example"}`
	wantStatus(t, e.as(a, "PUT", "/v1/share/name", `{"name":"abc"}`), 201, want)
	wantStatus(t, e.as(a, "PUT", "/v1/share/name", `{"name":"abc"}`), 200, want)

	b := e.linked(t, "box-b")
	wantStatus(t, e.as(b, "PUT", "/v1/share/name", `{"name":"abc"}`), 409, `{"error":"name taken"}`)
	wantStatus(t, e.as(b, "PUT", "/v1/share/name", `{"name":"www"}`), 409, `{"error":"name reserved"}`)
	if err := e.st.BanName(ctx, "banned1", now0); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.as(b, "PUT", "/v1/share/name", `{"name":"banned1"}`), 409, `{"error":"name revoked"}`)
	for _, n := range []string{"Boxa", "ab", "-ab", "ab-", "", "a.b"} {
		wantStatus(t, e.as(b, "PUT", "/v1/share/name", `{"name":"`+n+`"}`), 400, `{"error":"invalid name"}`)
	}
	wantStatus(t, e.as(b, "PUT", "/v1/share/name", `not json`), 400, "")

	// a releases abc: quarantined for ShareQuarantine
	wantStatus(t, e.as(a, "DELETE", "/v1/share/name", ""), 204, "")
	wantStatus(t, e.as(a, "DELETE", "/v1/share/name", ""), 204, "") // no name: still 204
	wantStatus(t, e.as(b, "PUT", "/v1/share/name", `{"name":"abc"}`), 409, `{"error":"name in quarantine"}`)
	wantStatus(t, e.as(b, "PUT", "/v1/share/name", `{"name":"a--b"}`), 201, `{"name":"a--b","host":"a--b.share.example","domain":"share.example"}`)

	// an unsigned request is 401
	r := httptest.NewRequest("PUT", "/v1/share/name", strings.NewReader(`{"name":"abc"}`))
	r.RemoteAddr = ip1
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	wantStatus(t, rec, 401, `{"error":"unauthorized"}`)
	// a body over 1 KiB
	wantStatus(t, e.as(b, "PUT", "/v1/share/name", `{"name":"`+strings.Repeat("a", 2000)+`"}`), 413, "")
}

func TestAuthLimiterRunsBeforeSignature(t *testing.T) {
	e := setupShare(t, func(c *Config) { c.AuthRatePerHour = 2 })
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("GET", "/v1/share", nil)
		r.RemoteAddr = ip1
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, r)
		wantStatus(t, rec, 401, "")
	}
	r := httptest.NewRequest("GET", "/v1/share", nil)
	r.RemoteAddr = ip1
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	wantStatus(t, rec, 429, "")
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
}

func TestACMEPutDeleteAndRate(t *testing.T) {
	e := setupShare(t, nil)
	ctx := t.Context()
	fqdn := "_acme-challenge.abc.share.example"
	b := e.linked(t, "box-a")
	wantStatus(t, e.as(b, "PUT", "/v1/share/acme", `{"value":"tok"}`), 404, `{"error":"no name"}`)
	wantStatus(t, e.as(b, "PUT", "/v1/share/name", `{"name":"abc"}`), 201, "")

	wantStatus(t, e.as(b, "PUT", "/v1/share/acme", `{"value":"tok1"}`), 204, "")
	v, ok, err := e.st.ACMEValue(ctx, fqdn, now0.Add(9*time.Minute))
	if err != nil || !ok || v != "tok1" {
		t.Fatalf("ACMEValue = %q %v %v", v, ok, err)
	}
	if _, ok, _ := e.st.ACMEValue(ctx, fqdn, now0.Add(10*time.Minute)); ok {
		t.Fatal("value outlives ShareACMETTL")
	}
	wantStatus(t, e.as(b, "PUT", "/v1/share/acme", `{"value":""}`), 400, `{"error":"invalid value"}`)
	wantStatus(t, e.as(b, "DELETE", "/v1/share/acme", ""), 204, "")
	if _, ok, _ := e.st.ACMEValue(ctx, fqdn, now0); ok {
		t.Fatal("value not deleted")
	}
	// tok1 and the empty value above were counted: 2 of 20 used
	for i := 2; i < 20; i++ {
		wantStatus(t, e.as(b, "PUT", "/v1/share/acme", `{"value":"tok"}`), 204, "")
	}
	rec := e.as(b, "PUT", "/v1/share/acme", `{"value":"tok"}`)
	wantStatus(t, rec, 429, `{"error":"rate limit exceeded"}`)
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
	// another box has its own budget
	c := e.linked(t, "box-c")
	wantStatus(t, e.as(c, "PUT", "/v1/share/name", `{"name":"xyz"}`), 201, "")
	wantStatus(t, e.as(c, "PUT", "/v1/share/acme", `{"value":"tok"}`), 204, "")
	// deleting needs no name
	d := e.linked(t, "box-d")
	wantStatus(t, e.as(d, "DELETE", "/v1/share/acme", ""), 204, "")
}

func TestShareStatus(t *testing.T) {
	e := setupShare(t, nil)
	b := e.linked(t, "box-a")
	wantStatus(t, e.as(b, "GET", "/v1/share", ""), 404, `{"error":"no name"}`)
	wantStatus(t, e.as(b, "PUT", "/v1/share/name", `{"name":"abc"}`), 201, "")
	base := `"name":"abc","host":"abc.share.example","domain":"share.example"`
	wantStatus(t, e.as(b, "GET", "/v1/share", ""), 200, `{`+base+`,"tunnel_online":false}`)

	usage := `[{"fleet_id":"` + e.id + `","node_id":"` + b.node + `","rx":0,"tx":0}]`
	r := httptest.NewRequest("POST", "/internal/share/usage", strings.NewReader(usage))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	wantStatus(t, rec, 204, "")
	wantStatus(t, e.as(b, "GET", "/v1/share", ""), 200, `{`+base+`,"tunnel_online":true}`)
}

func TestShareRoutesAre503WithoutDomain(t *testing.T) {
	e := setupShare(t, func(c *Config) { c.ShareDomain = "" })
	b := e.newBox(t, "box-a")
	r := httptest.NewRequest("PUT", "/v1/fleets/"+e.id+"/nodes/"+b.node+"/box-key", strings.NewReader(`{"box_key":"`+b.key+`"}`))
	r.RemoteAddr = ip1
	r.Header.Set("Authorization", "Bearer "+e.secret)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	wantStatus(t, rec, 503, `{"error":"sharing not enabled"}`)
	for _, c := range [][2]string{{"PUT", "/v1/share/name"}, {"DELETE", "/v1/share/name"}, {"GET", "/v1/share"}, {"PUT", "/v1/share/acme"}, {"DELETE", "/v1/share/acme"}} {
		wantStatus(t, e.as(b, c[0], c[1], `{}`), 503, `{"error":"sharing not enabled"}`)
	}
}

func TestRemoveNodeDropsItsBoxKey(t *testing.T) {
	e := setupShare(t, nil)
	a := e.linked(t, "box-a")
	b := e.linked(t, "box-b")
	wantStatus(t, e.as(a, "PUT", "/v1/share/name", `{"name":"abc"}`), 201, "")
	wantStatus(t, e.removeNode(e.secret, "box-a"), 204, "")
	if _, err := e.st.BoxByKey(t.Context(), a.key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("box key survives its node: %v", err)
	}
	if _, err := e.st.BoxByKey(t.Context(), b.key); err != nil {
		t.Fatalf("other box lost its key: %v", err)
	}
	wantStatus(t, e.as(a, "GET", "/v1/share", ""), 403, `{"error":"box key not linked"}`)
}
