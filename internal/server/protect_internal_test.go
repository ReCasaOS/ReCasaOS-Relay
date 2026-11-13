package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/protect"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

func setupProtect(t *testing.T) env {
	t.Helper()
	return setup(t, func(c *Config, d *Deps) {
		c.ShareDomain = "share.example"
		c.TrustedProxyHeader = "X-Client-IP"
		d.Protect = &protect.Compiler{Store: d.Store, Now: d.Now}
	})
}

func (e env) call(method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = ip1
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func TestFilterRoute304(t *testing.T) {
	e := setupProtect(t)
	e.st.AddAllow(context.Background(), store.AllowEntry{Prefix: "192.0.2.0/24", Added: now0})
	rec := e.call("GET", "/internal/share/filter", "", nil)
	wantStatus(t, rec, 200, "")
	etag := rec.Header().Get("ETag")
	if !strings.HasPrefix(etag, `"`) || !strings.Contains(rec.Body.String(), `"allow":["192.0.2.0/24"]`) ||
		!strings.Contains(rec.Body.String(), strings.Trim(etag, `"`)) {
		t.Fatalf("etag %q body %s", etag, rec.Body)
	}
	wantStatus(t, e.call("GET", "/internal/share/filter", "", map[string]string{"If-None-Match": etag}), 304, "")
	wantStatus(t, e.call("GET", "/internal/share/filter", "", map[string]string{"If-None-Match": `"old"`}), 200, "")
}

func TestFilterRouteRefusesProxiedRequest(t *testing.T) {
	e := setupProtect(t)
	proxied := map[string]string{"X-Client-IP": "203.0.113.9"}
	wantStatus(t, e.call("GET", "/internal/share/filter", "", proxied), 404, "")
	wantStatus(t, e.call("POST", "/internal/share/events", `{}`, proxied), 404, "")
	wantStatus(t, e.call("POST", "/internal/share/events", `{}`, nil), 204, "")
}

func TestEventsRecordSeenAndRefusals(t *testing.T) {
	e := setupProtect(t)
	ctx := context.Background()
	body := `{"seen":[{"key":"203.0.113.7/32","node_id":"7"},{"key":"192.168.1.5","node_id":"7"}],
	 "refusals":[{"hour":"2026-11-13T10:25:00Z","name":"mybox","key":"203.0.113.7","reason":"external","source":"FireHOL level 1","count":3},
	             {"hour":"2026-11-13T10:00:00Z","name":"mybox","key":"203.0.113.7/32","reason":"external","source":"FireHOL level 1","count":2}]}`
	wantStatus(t, e.call("POST", "/internal/share/events", body, nil), 204, "")
	if ok, _ := e.st.SeenBetween(ctx, "203.0.113.7/32", "7", now0.Add(-time.Hour), now0.Add(time.Hour)); !ok {
		t.Fatal("seen not recorded")
	}
	if ok, _ := e.st.SeenBetween(ctx, "192.168.1.5/32", "7", now0.Add(-time.Hour), now0.Add(time.Hour)); ok {
		t.Fatal("private key kept")
	}
	rs, _ := e.st.RefusalsOf(ctx, "mybox", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), 10)
	if len(rs) != 1 || rs[0].Count != 5 || rs[0].Key != "203.0.113.7/32" || !rs[0].Hour.Equal(time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", rs)
	}
}

func TestEventsValidation(t *testing.T) {
	e := setupProtect(t)
	for _, body := range []string{
		`nope`, `{"seen":[{"key":"203.0.113.7","node_id":""}]}`,
		`{"refusals":[{"hour":"2026-11-13T10:00:00Z","name":"n","key":"203.0.113.7","reason":"bogus","source":"","count":1}]}`,
		`{"refusals":[{"hour":"2026-11-13T10:00:00Z","name":"n","key":"203.0.113.7","reason":"cap","source":"ip","count":0}]}`,
		`{"seen":[` + strings.Repeat(`{"key":"203.0.113.7","node_id":"1"},`, 20000) + `{"key":"203.0.113.7","node_id":"1"}]}`,
	} {
		wantStatus(t, e.call("POST", "/internal/share/events", body, nil), 400, "")
	}
	big := `{"seen":[` + strings.Repeat(`{"key":"203.0.113.7","node_id":"1"},`, 30000) + `{"key":"203.0.113.7","node_id":"1"}]}`
	wantStatus(t, e.call("POST", "/internal/share/events", big, nil), 413, "")
}
