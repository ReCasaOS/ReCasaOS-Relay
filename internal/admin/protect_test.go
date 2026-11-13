package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/feeds"
	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/journal/journaltest"
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
	for _, bad := range []string{"garbage", "10.0.0.0/7", "0.0.0.0/0", "::/0", "2001:db8::/18"} {
		if w := e.do("POST", "/admin/protection/allow", token, form(e, "value", bad)); w.Code != 400 {
			t.Errorf("%s: %d", bad, w.Code)
		}
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

func TestMask(t *testing.T) {
	for in, want := range map[string]string{"": "", "abc": "••••", "1234567": "••••", "12345678": "••••5678", "secret-key-1234": "••••1234"} {
		if got := mask(in); got != want {
			t.Errorf("mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPresetNameTaken(t *testing.T) {
	e := setup(t)
	e.do("POST", "/admin/protection/feeds", token, form(e, "name", "Spamhaus DROP", "url", "https://lists.example.net/a.txt", "format", "text", "every_s", "3600"))
	if w := e.do("POST", "/admin/protection/feeds/presets/spamhaus-drop", token, form(e)); w.Code != 400 {
		t.Errorf("preset over a custom list's name: %d", w.Code)
	}
	e.do("POST", "/admin/protection/feeds/presets/tor-exits", token, form(e))
	if w := e.do("POST", "/admin/protection/feeds/presets/tor-exits", token, form(e)); w.Code != 303 {
		t.Errorf("second click on a preset: %d", w.Code)
	}
}

func TestDeleteFeedRemovesCopy(t *testing.T) {
	e := setup(t)
	dir := t.TempDir()
	e = e.withDeps(t, func(d *Deps) { d.Feeds = &feeds.Fetcher{Store: e.st, Dir: dir} })
	id, err := e.st.AddFeed(context.Background(), store.Feed{Name: "x", URL: "https://lists.example.net/a.txt", Format: "text", EverySec: 3600, MaxEntries: 10})
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(dir, strconv.FormatInt(id, 10)+".txt")
	if err := os.WriteFile(copyPath, []byte("192.0.2.0/24"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := e.do("POST", "/admin/protection/feeds/"+strconv.FormatInt(id, 10)+"/delete", token, form(e)); w.Code != 303 {
		t.Fatalf("delete: %d", w.Code)
	}
	if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
		t.Errorf("copy left after delete: %v", err)
	}
}

func openBan(t *testing.T, e env, key, kind string, strike int, until time.Time) {
	t.Helper()
	if err := e.st.OpenBan(context.Background(), store.CommunityBan{Key: key, Kind: kind, Strike: strike, Since: t0.Add(-time.Hour), Until: until, Reasons: "scan", Fleets: 3}, []string{"aaaa", "bbbb"}); err != nil {
		t.Fatal(err)
	}
}

func claim(t *testing.T, e env, fleet, node, name string) {
	t.Helper()
	ctx := context.Background()
	if err := e.st.SetBoxKey(ctx, fleet, node, "key"+node, t0); err != nil {
		t.Fatal(err)
	}
	if err := e.st.ClaimName(ctx, node, name, t0); err != nil {
		t.Fatal(err)
	}
}

func TestLiftKeepsStrikes(t *testing.T) {
	ctx := context.Background()
	e, c := setup(t).withCompiler(t)
	openBan(t, e, "198.51.100.7/32", "address", 2, t0.Add(time.Hour))
	if _, _, err := c.Current(ctx); err != nil {
		t.Fatal(err)
	}
	if w := e.do("POST", "/admin/protection/community/lift", token, form(e, "key", "198.51.100.7/32")); w.Code != 303 || w.Header().Get("Location") != "/admin/protection#community" {
		t.Fatalf("lift: %d %s", w.Code, w.Header().Get("Location"))
	}
	if b, _ := e.st.ActiveBans(ctx, t0); len(b) != 0 {
		t.Errorf("still banned: %+v", b)
	}
	if n, _, err := e.st.Strikes(ctx, "198.51.100.7/32"); err != nil || n != 2 {
		t.Errorf("strikes %d, %v", n, err)
	}
	for _, bad := range []string{"198.51.100.7/24", "garbage", "", "10.0.0.0/7"} {
		if w := e.do("POST", "/admin/protection/community/lift", token, form(e, "key", bad)); w.Code != 400 {
			t.Errorf("lift %q: %d", bad, w.Code)
		}
	}
}

func TestAllowFromCommunity(t *testing.T) {
	ctx := context.Background()
	e, _ := setup(t).withCompiler(t)
	openBan(t, e, "198.51.100.0/24", "range", 1, time.Time{})
	if w := e.do("POST", "/admin/protection/community/allow", token, form(e, "key", "198.51.100.0/24")); w.Code != 303 {
		t.Fatalf("allow: %d", w.Code)
	}
	al, _ := e.st.AllowList(ctx)
	if len(al) != 1 || al[0].Prefix != "198.51.100.0/24" || al[0].Note != "from community list" {
		t.Errorf("allow list %+v", al)
	}
	if b, _ := e.st.ActiveBans(ctx, t0); len(b) != 0 {
		t.Errorf("still banned: %+v", b)
	}
	if w := e.do("POST", "/admin/protection/community/allow", token, form(e, "key", "10.0.0.0/7")); w.Code != 400 {
		t.Errorf("too broad: %d", w.Code)
	}
}

func TestBanFlaggedASN(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	if w := e.do("POST", "/admin/protection/asn/64500/ban", token, form(e)); w.Code != 303 || w.Header().Get("Location") != "/admin/protection#community" {
		t.Fatalf("ban: %d %s", w.Code, w.Header().Get("Location"))
	}
	ms, _ := e.st.ManualBans(ctx, t0)
	if len(ms) != 1 || ms[0].Kind != "asn" || ms[0].Value != "64500" || !ms[0].Until.IsZero() || ms[0].Note != "flagged network" {
		t.Errorf("manual %+v", ms)
	}
	for _, bad := range []string{"0", "x", "-1"} {
		if w := e.do("POST", "/admin/protection/asn/"+bad+"/ban", token, form(e)); w.Code != 400 {
			t.Errorf("asn %q: %d", bad, w.Code)
		}
	}
}

func TestSuspendResume(t *testing.T) {
	ctx := context.Background()
	e, c := setup(t).withCompiler(t)
	claim(t, e, "aaaa", "7", "mybox")
	body, _, _ := c.Current(ctx)
	if strings.Contains(string(body), `"mybox"`) {
		t.Fatalf("suspended before: %s", body)
	}
	if w := e.do("POST", "/admin/protection/names/mybox/suspend", token, form(e)); w.Code != 303 || w.Header().Get("Location") != "/admin/protection#names" {
		t.Fatalf("suspend: %d %s", w.Code, w.Header().Get("Location"))
	}
	body, _, _ = c.Current(ctx)
	if !strings.Contains(string(body), `"suspended":["mybox"]`) {
		t.Errorf("snapshot after suspend: %s", body)
	}
	if !strings.Contains(e.do("GET", "/admin/protection", token, nil).Body.String(), "/admin/protection/names/mybox/resume") {
		t.Error("no Resume button")
	}
	if w := e.do("POST", "/admin/protection/names/mybox/resume", token, form(e)); w.Code != 303 {
		t.Fatalf("resume: %d", w.Code)
	}
	body, _, _ = c.Current(ctx)
	if !strings.Contains(string(body), `"suspended":[]`) {
		t.Errorf("snapshot after resume: %s", body)
	}
	if w := e.do("POST", "/admin/protection/names/Bad_Name/suspend", token, form(e)); w.Code != 400 {
		t.Errorf("bad name: %d", w.Code)
	}
}

func TestOverviewCounts(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	claim(t, e, "aaaa", "7", "mybox")
	claim(t, e, "bbbb", "8", "oldbox")
	e.st.SetProtection(ctx, "7", store.Protection{RelayFilter: true, ShareBans: true})
	openBan(t, e, "198.51.100.7/32", "address", 1, t0.Add(time.Hour))
	openBan(t, e, "203.0.113.9/32", "address", 4, time.Time{})
	today, yesterday := time.Date(2026, 11, 4, 3, 0, 0, 0, time.UTC), time.Date(2026, 11, 3, 23, 0, 0, 0, time.UTC)
	if err := e.st.AddRefusals(ctx, []store.Refusal{
		{Hour: today, Name: "mybox", Key: "192.0.2.1/32", Reason: "manual", Source: "manual", Count: 7},
		{Hour: today, Name: "mybox", Key: "192.0.2.2/32", Reason: "cap", Source: "ip-box", Count: 5},
		{Hour: today, Name: "", Key: "192.0.2.3/32", Reason: "cap", Source: "ip", Count: 11},
		{Hour: yesterday, Name: "mybox", Key: "192.0.2.1/32", Reason: "manual", Source: "manual", Count: 100},
	}); err != nil {
		t.Fatal(err)
	}
	body := e.do("GET", "/admin/protection", token, nil).Body.String()
	for _, want := range []string{
		`data-n="today-manual">7<`, `data-n="today-cap">16<`, `data-n="today-suspended">0<`, // yesterday's 100 is not today
		`data-n="sharing">1<`, `data-n="active-bans">2<`,
		`data-n="name-mybox-cap">5<`, `data-n="cap-key-192.0.2.3/32">11<`, `data-n="cap-name-mybox">5<`,
		"<svg", "relay filter", "not set", "/admin/share/names/mybox/revoke", "256", "64",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// The permanent ban is in its own table, the timed one in the other.
	perm, act := strings.Index(body, `id="permanent"`), strings.Index(body, `id="active-bans-table"`)
	if perm < 0 || act < 0 || !(strings.Index(body, "203.0.113.9/32") > perm) || !(strings.Index(body, "198.51.100.7/32") > act) || strings.Index(body, "198.51.100.7/32") > perm {
		t.Error("bans not split into active and permanent tables")
	}
}

func TestJournalAdminManualAdd(t *testing.T) {
	jw, read := journaltest.New(t, "enrolment")
	e := setup(t).withDeps(t, func(d *Deps) { d.Journal = jw })
	if c := e.do("POST", "/admin/protection/manual", token, form(e, "kind", "address", "value", "203.0.113.9", "hours", "0")).Code; c != 303 {
		t.Fatal(c)
	}
	if c := e.do("POST", "/admin/protection/allow", token, form(e, "value", "198.51.100.0/24")).Code; c != 303 {
		t.Fatal(c)
	}
	openBan(t, e, "203.0.113.7/32", "address", 1, t0.Add(time.Hour))
	e.do("POST", "/admin/protection/community/lift", token, form(e, "key", "203.0.113.7/32"))
	want := map[string][3]string{ // event: ip, host, msg
		"manual_add": {"", "", "address 203.0.113.9/32"},
		"allow_add":  {"198.51.100.0/24", "", ""},
		"ban_lift":   {"203.0.113.7/32", "", ""},
	}
	got := map[string]bool{}
	for _, l := range read() {
		w, ok := want[l.Event]
		if !ok {
			continue
		}
		got[l.Event] = true
		if l.Src != "relay" || l.Svc != "enrolment" || l.IP != w[0] || l.Msg != w[2] {
			t.Errorf("%s: %+v", l.Event, l)
		}
	}
	for ev := range want {
		if !got[ev] {
			t.Errorf("no %s line", ev)
		}
	}
}

func TestJournalFeedAdminHasNoKey(t *testing.T) {
	jw, read := journaltest.New(t, "enrolment")
	e := setup(t).withDeps(t, func(d *Deps) { d.Journal = jw })
	e.do("POST", "/admin/protection/feeds", token, form(e, "name", "Mine", "url", "https://lists.example.net/x?key=SECRETKEY", "format", "text", "every_s", "3600",
		"auth_name", "X-Key", "auth_value", "HEADERSECRET"))
	var n int
	for _, l := range read() {
		if strings.Contains(l.Msg, "SECRET") || strings.Contains(l.Msg, "example.net") {
			t.Fatalf("leak %+v", l)
		}
		if l.Event == "feed_admin" && l.Msg == "Mine add" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("feed_admin lines: %d", n)
	}
}
