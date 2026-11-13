package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/feeds"
	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/protect"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// withDeps rebuilds e's handler with the protection collaborators set by set.
func (e env) withDeps(t *testing.T, set func(*Deps)) env {
	t.Helper()
	d := Deps{Store: e.st, Headscale: e.hs, Now: func() time.Time { return t0 },
		Remover: &fleets.Remover{Store: e.st, Headscale: e.hs, Locks: &fleets.Locks{}}}
	set(&d)
	h, err := New(Config{Token: token, NodesPerFleet: 50, MaxFleets: 1000}, d)
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	return e
}

// withCompiler adds a snapshot compiler whose clock never moves, so only Invalidate can make it rebuild.
func (e env) withCompiler(t *testing.T) (env, *protect.Compiler) {
	c := &protect.Compiler{Store: e.st, Now: func() time.Time { return t0 }}
	return e.withDeps(t, func(d *Deps) { d.Protect = c }), c
}

func form(e env, kv ...string) url.Values {
	f := csrf(e)
	for i := 0; i+1 < len(kv); i += 2 {
		f.Set(kv[i], kv[i+1])
	}
	return f
}

func listFeeds(t *testing.T, e env) []store.Feed {
	t.Helper()
	fs, err := e.st.Feeds(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func TestProtectionPageSections(t *testing.T) {
	e := setup(t)
	if _, err := e.st.AddFeed(context.Background(), store.Feed{Name: "keyed", URL: "https://lists.example.net/x?key=secret-key-1234",
		AuthName: "Key", AuthValue: "secret-key-1234", Format: "text", EverySec: 3600, MaxEntries: 100000}); err != nil {
		t.Fatal(err)
	}
	w := e.do("GET", "/admin/protection", token, nil)
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	last := -1
	for _, id := range []string{"overview", "feeds", "community", "manual", "names", "allow", "caps"} {
		i := strings.Index(body, `id="`+id+`"`)
		if i < 0 || i < last {
			t.Errorf("section %s missing or out of order", id)
		}
		last = i
	}
	if strings.Contains(body, "secret-key-1234") {
		t.Error("the feed key (or the URL holding it) is in the page")
	}
	for _, want := range []string{"••••1234", "lists.example.net", "IP Geolocation by DB-IP"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if !strings.Contains(e.do("GET", "/admin/", token, nil).Body.String(), `href="/admin/protection"`) {
		t.Error("the main page has no link to the protection page")
	}
}

func TestAddFeedAndPreset(t *testing.T) {
	e := setup(t)
	w := e.do("POST", "/admin/protection/feeds", token, form(e, "name", "mine", "url", "https://lists.example.net/a.txt",
		"format", "text", "every_s", "3600", "max_entries", "", "auth_name", "", "auth_value", "", "note", "my list"))
	if w.Code != 303 || w.Header().Get("Location") != "/admin/protection#feeds" {
		t.Fatalf("add: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w := e.do("POST", "/admin/protection/feeds/presets/spamhaus-drop", token, form(e)); w.Code != 303 {
		t.Fatalf("preset: %d", w.Code)
	}
	fs := listFeeds(t, e)
	if len(fs) != 2 {
		t.Fatalf("%d feeds", len(fs))
	}
	if f := fs[0]; f.Name != "mine" || f.Enabled || f.MaxEntries != 100000 || f.Note != "my list" {
		t.Errorf("added feed: %+v", f)
	}
	if f := fs[1]; f.URL != "https://www.spamhaus.org/drop/drop.txt" || f.Enabled || f.Preset != "spamhaus-drop" || f.EverySec != 86400 {
		t.Errorf("preset feed: %+v", f)
	}
	body := e.do("GET", "/admin/protection", token, nil).Body.String()
	for _, want := range []string{"mine", "lists.example.net", "Spamhaus DROP", "www.spamhaus.org"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Refused: plain http, a short refresh, a bad header name, csv without a column.
	for _, bad := range [][]string{
		{"url", "http://lists.example.net/a.txt"},
		{"every_s", "60"},
		{"auth_name", "Bad Header"},
		{"format", "csv", "column", "0"},
		{"name", ""},
	} {
		f := form(e, "name", "other", "url", "https://lists.example.net/b.txt", "format", "text", "every_s", "3600")
		for i := 0; i+1 < len(bad); i += 2 {
			f.Set(bad[i], bad[i+1])
		}
		if w := e.do("POST", "/admin/protection/feeds", token, f); w.Code != 400 {
			t.Errorf("%v: %d", bad, w.Code)
		}
	}
	// The crowdsec preset keeps its placeholder: it cannot be turned on.
	e.do("POST", "/admin/protection/feeds/presets/crowdsec", token, form(e))
	cs := listFeeds(t, e)[2]
	if w := e.do("POST", "/admin/protection/feeds/"+strconv.FormatInt(cs.ID, 10)+"/toggle", token, form(e)); w.Code != 400 {
		t.Errorf("crowdsec placeholder enabled: %d", w.Code)
	}
	if w := e.do("POST", "/admin/protection/feeds/"+strconv.FormatInt(fs[0].ID, 10)+"/toggle", token, form(e)); w.Code != 303 || !listFeeds(t, e)[0].Enabled {
		t.Errorf("toggle: %d", w.Code)
	}
	if w := e.do("POST", "/admin/protection/feeds/"+strconv.FormatInt(fs[0].ID, 10)+"/delete", token, form(e)); w.Code != 303 || len(listFeeds(t, e)) != 2 {
		t.Errorf("delete: %d", w.Code)
	}
}

func TestFeedEditKeepsKey(t *testing.T) {
	e := setup(t)
	e.do("POST", "/admin/protection/feeds/presets/abuseipdb-free", token, form(e))
	f := listFeeds(t, e)[0]
	if w := e.do("POST", "/admin/protection/feeds/"+strconv.FormatInt(f.ID, 10), token, form(e, "name", f.Name, "url", "", "format", "text",
		"every_s", "21600", "max_entries", "100000", "auth_name", "Key", "auth_value", "k-0123456789", "note", f.Note)); w.Code != 303 {
		t.Fatalf("set key: %d", w.Code)
	}
	if w := e.do("POST", "/admin/protection/feeds/"+strconv.FormatInt(f.ID, 10), token, form(e, "name", "renamed", "url", "", "format", "text",
		"every_s", "43200", "max_entries", "100000", "auth_name", "Key", "auth_value", "", "note", "")); w.Code != 303 {
		t.Fatalf("edit: %d", w.Code)
	}
	g := listFeeds(t, e)[0]
	if g.AuthValue != "k-0123456789" || g.Name != "renamed" || g.EverySec != 43200 || g.URL != f.URL || g.Preset != "abuseipdb-free" {
		t.Errorf("after edit: %+v", g)
	}
}

func TestManualBanValidation(t *testing.T) {
	e, c := setup(t).withCompiler(t)
	_, v0, err := c.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ban := func(kind, value, hours string) int {
		return e.do("POST", "/admin/protection/manual", token, form(e, "kind", kind, "value", value, "hours", hours, "note", "n")).Code
	}
	for _, bad := range [][3]string{
		{"country", "fr", "0"}, {"country", "FRA", "0"}, {"range", "garbage", "0"}, {"range", "10.0.0.0/7", "0"},
		{"address", "192.0.2.0/24", "0"}, {"asn", "ASx", "0"}, {"planet", "X", "0"}, {"country", "DE", "8761"},
	} {
		if code := ban(bad[0], bad[1], bad[2]); code != 400 {
			t.Errorf("%v: %d", bad, code)
		}
	}
	for _, ok := range [][3]string{{"country", "XX", "0"}, {"asn", "AS64500", "24"}, {"range", "198.51.100.7/24", "0"}, {"address", "2001:db8::1", "0"}} {
		if code := ban(ok[0], ok[1], ok[2]); code != 303 {
			t.Errorf("%v: %d", ok, code)
		}
	}
	bans, err := e.st.ManualBans(context.Background(), t0)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, b := range bans {
		got = append(got, b.Kind+" "+b.Value)
	}
	if want := "country XX,asn 64500,range 198.51.100.0/24,address 2001:db8::1/128"; strings.Join(got, ",") != want {
		t.Errorf("stored %v, want %s", got, want)
	}
	if !bans[0].Until.IsZero() || !bans[1].Until.Equal(t0.Add(24*time.Hour)) {
		t.Errorf("durations: %v %v", bans[0].Until, bans[1].Until)
	}
	if _, v1, _ := c.Current(context.Background()); v1 == v0 {
		t.Error("the snapshot was not rebuilt after a ban")
	}
	if w := e.do("POST", "/admin/protection/manual/"+strconv.FormatInt(bans[0].ID, 10)+"/delete", token, form(e)); w.Code != 303 || w.Header().Get("Location") != "/admin/protection#manual" {
		t.Errorf("delete: %d", w.Code)
	}
	if bans, _ := e.st.ManualBans(context.Background(), t0); len(bans) != 3 {
		t.Errorf("%d bans after delete", len(bans))
	}
}

func TestAllowList(t *testing.T) {
	e := setup(t)
	if w := e.do("POST", "/admin/protection/allow", token, form(e, "value", "garbage")); w.Code != 400 {
		t.Errorf("garbage: %d", w.Code)
	}
	if w := e.do("POST", "/admin/protection/allow", token, form(e, "value", "203.0.113.9/24", "note", "office")); w.Code != 303 || w.Header().Get("Location") != "/admin/protection#allow" {
		t.Fatalf("add: %d", w.Code)
	}
	al, _ := e.st.AllowList(context.Background())
	if len(al) != 1 || al[0].Prefix != "203.0.113.0/24" || al[0].Note != "office" {
		t.Fatalf("%+v", al)
	}
	if !strings.Contains(e.do("GET", "/admin/protection", token, nil).Body.String(), "203.0.113.0/24") {
		t.Error("allow entry not shown")
	}
	e.do("POST", "/admin/protection/allow/"+strconv.FormatInt(al[0].ID, 10)+"/delete", token, form(e))
	if al, _ := e.st.AllowList(context.Background()); len(al) != 0 {
		t.Errorf("%+v", al)
	}
}

func TestWritesNeedCSRF(t *testing.T) {
	e := setup(t)
	e.do("POST", "/admin/protection/feeds/presets/firehol1", token, form(e))
	id := strconv.FormatInt(listFeeds(t, e)[0].ID, 10)
	for _, p := range []string{"/admin/protection/feeds", "/admin/protection/feeds/presets/tor-exits", "/admin/protection/feeds/" + id,
		"/admin/protection/feeds/" + id + "/toggle", "/admin/protection/feeds/" + id + "/refresh", "/admin/protection/feeds/" + id + "/delete",
		"/admin/protection/manual", "/admin/protection/manual/1/delete", "/admin/protection/allow", "/admin/protection/allow/1/delete"} {
		if w := e.do("POST", p, token, url.Values{"name": {"x"}, "kind": {"country"}, "value": {"XX"}}); w.Code != 403 {
			t.Errorf("%s without csrf: %d", p, w.Code)
		}
	}
	if fs := listFeeds(t, e); len(fs) != 1 || fs[0].Enabled {
		t.Errorf("a write went through: %+v", fs)
	}
}

func TestFeedRefresh(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()
	e := setup(t)
	id, err := e.st.AddFeed(context.Background(), store.Feed{Name: "flaky", URL: srv.URL + "/list.txt", Format: "text", EverySec: 3600, MaxEntries: 100000})
	if err != nil {
		t.Fatal(err)
	}
	path := "/admin/protection/feeds/" + strconv.FormatInt(id, 10) + "/refresh"
	if w := e.do("POST", path, token, form(e)); w.Code != 503 {
		t.Errorf("refresh without a fetcher: %d", w.Code)
	}
	e = e.withDeps(t, func(d *Deps) { d.Feeds = &feeds.Fetcher{Store: e.st, Dir: t.TempDir(), Client: srv.Client()} })
	if w := e.do("POST", path, token, form(e)); w.Code != 303 || w.Header().Get("Location") != "/admin/protection#feeds" {
		t.Fatalf("refresh: %d", w.Code)
	}
	if !strings.Contains(e.do("GET", "/admin/protection", token, nil).Body.String(), "HTTP 500") {
		t.Error("the refresh error is not shown")
	}
}
