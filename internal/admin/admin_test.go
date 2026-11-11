package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ReCasaOS/recasaos-relay/internal/fakes"
	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/meter"
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

// A box removed from /admin loses its box key at once (its name goes to quarantine), not at the next gc.
func TestRemoveNodeDropsItsBoxKey(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	nodes, _ := e.hs.ListNodes(ctx, "f-bbbb")
	id := nodes[0].ID
	if err := e.st.SetBoxKey(ctx, "bbbb", id, "keyb", t0); err != nil {
		t.Fatal(err)
	}
	if w := e.do("POST", "/admin/fleets/bbbb/nodes/"+id+"/remove", token, csrf(e)); w.Code != 303 {
		t.Fatalf("%d", w.Code)
	}
	if _, err := e.st.BoxByKey(ctx, "keyb"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("BoxByKey after remove = %v, want ErrNotFound", err)
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

func TestFullLimiterFailsClosed(t *testing.T) {
	e := setup(t)
	h, err := New(Config{Token: token, ClientHeader: "X-Client-IP"}, Deps{
		Store: e.st, Headscale: e.hs, Now: func() time.Time { return t0 },
		Remover: &fleets.Remover{Store: e.st, Headscale: e.hs, Locks: &fleets.Locks{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	get := func(ip string) int {
		r := httptest.NewRequest("GET", "/admin/", nil)
		r.Header.Set("X-Client-IP", ip)
		r.SetBasicAuth("admin", "wrong")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for i := 0; i < 100_000; i++ { // the limiter's key cap (ratelimit.defaultMaxKeys)
		get("10." + strconv.Itoa(i>>16) + "." + strconv.Itoa(i>>8&255) + "." + strconv.Itoa(i&255))
	}
	if c := get("192.0.2.1"); c != 429 {
		t.Fatalf("new address with a full limiter: %d, want 429", c)
	}
}

type fakeMeter meter.Live

func (f fakeMeter) Live() meter.Live { return meter.Live(f) }

// with rebuilds the handler over the same store and Headscale, with a reference and a meter.
func (e env) with(t *testing.T, reference int64, m interface{ Live() meter.Live }) env {
	t.Helper()
	h, err := New(Config{Token: token, NodesPerFleet: 50, MaxFleets: 1000, MonthlyReference: reference}, Deps{
		Store: e.st, Headscale: e.hs, Now: func() time.Time { return t0 }, Meter: m,
		Remover: &fleets.Remover{Store: e.st, Headscale: e.hs, Locks: &fleets.Locks{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	return e
}

func (e env) nodeID(t *testing.T, user, host string) string {
	t.Helper()
	ns, _ := e.hs.ListNodes(context.Background(), user)
	for _, n := range ns {
		if n.Hostname == host {
			return n.ID
		}
	}
	t.Fatalf("no node %s/%s", user, host)
	return ""
}

func (e env) usage(t *testing.T, samples ...store.UsageSample) {
	t.Helper()
	if err := e.st.ApplyUsage(context.Background(), t0.Add(-5*time.Minute), samples, nil); err != nil {
		t.Fatal(err)
	}
}

// between returns the text of body from the first from to the next to after it.
func between(t *testing.T, body, from, to string) string {
	t.Helper()
	i := strings.Index(body, from)
	if i < 0 {
		t.Fatalf("page lacks %q", from)
	}
	j := strings.Index(body[i:], to)
	if j < 0 {
		t.Fatalf("no %q after %q", to, from)
	}
	return body[i : i+j]
}

func TestIndexShowsRelayedUsage(t *testing.T) {
	e := setup(t)
	e.hs.AddNode("f-bbbb", "b-idle", true)
	one, two, idle := e.nodeID(t, "f-aaaa", "b-one"), e.nodeID(t, "f-bbbb", "b-two"), e.nodeID(t, "f-bbbb", "b-idle")
	e.usage(t, store.UsageSample{FleetID: "aaaa", NodeID: one, Rx: 2e9, Tx: 1},
		store.UsageSample{FleetID: "bbbb", NodeID: two, Rx: 5e9, Tx: 2},
		store.UsageSample{FleetID: "bbbb", NodeID: idle, Rx: 1e6})
	e = e.with(t, 0, fakeMeter{OK: true, At: t0, Nodes: map[string]meter.Rate{
		one: {Up: 1500, Down: 200e3}, two: {Up: 2.5e6}, idle: {Up: 10, Down: 500}}})
	w := e.do("GET", "/admin/", token, nil)
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("%d", w.Code)
	}
	for _, want := range []string{"<b>7.0 GB</b><span>relayed this month</span>", "<b>2.5 MB/s</b><span>relayed now</span>"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if a, b := strings.Index(body, "<code>aaaa</code>"), strings.Index(body, "<code>bbbb</code>"); b < 0 || a < b {
		t.Errorf("the fleet with more volume is not first (aaaa at %d, bbbb at %d)", a, b)
	}
	for fleet, want := range map[string][]string{"bbbb": {"5.0 GB", "2.5 MB/s"}, "aaaa": {"2.0 GB", "1.5 kB/s"}} {
		head := between(t, body, "<code>"+fleet+"</code>", "</summary>")
		for _, s := range want {
			if !strings.Contains(head, s) {
				t.Errorf("fleet %s header lacks %q: %s", fleet, s, head)
			}
		}
	}
	row := between(t, body, `data-node-id="`+one+`"`, "</tr>")
	for _, s := range []string{`data-up-month="2000000000"`, "↑ 1.5 kB/s", "↓ 200.0 kB/s", "2.0 GB this month"} {
		if !strings.Contains(row, s) {
			t.Errorf("node row lacks %q: %s", s, row)
		}
	}
	if row := between(t, body, `data-node-id="`+idle+`"`, "</tr>"); !strings.Contains(row, "≈ 0 relayed") {
		t.Errorf("idle node row: %s", row)
	}
	if row := between(t, body, `data-node-id="`+two+`"`, "</tr>"); strings.Contains(row, "≈ 0 relayed") {
		t.Errorf("busy node shown idle: %s", row)
	}
}

func TestIndexReferenceBar(t *testing.T) {
	e := setup(t)
	e.usage(t, store.UsageSample{FleetID: "aaaa", NodeID: e.nodeID(t, "f-aaaa", "b-one"), Rx: 85e9})
	if body := e.with(t, 100e9, nil).do("GET", "/admin/", token, nil).Body.String(); !strings.Contains(body, `class="bar warn"`) ||
		!strings.Contains(body, "85.0 GB / 100.0 GB") {
		t.Error("no warning bar at 85 %")
	}
	if body := e.with(t, 0, nil).do("GET", "/admin/", token, nil).Body.String(); strings.Contains(body, `class="bar`) {
		t.Error("a bar without a reference")
	}
}

func TestIndexDeletedFleets(t *testing.T) {
	e := setup(t)
	e.usage(t, store.UsageSample{FleetID: "zzzz", NodeID: "99", Rx: 3e9},
		store.UsageSample{FleetID: "aaaa", NodeID: e.nodeID(t, "f-aaaa", "b-one"), Rx: 1e9})
	body := e.do("GET", "/admin/", token, nil).Body.String()
	if line := between(t, body, "deleted fleets", "</p>"); !strings.Contains(line, "3.0 GB") {
		t.Errorf("deleted fleets line: %s", line)
	}
	if !strings.Contains(body, "<b>4.0 GB</b><span>relayed this month</span>") {
		t.Error("the global tile leaves out deleted fleets")
	}
}

func TestIndexMeteringUnavailable(t *testing.T) {
	for name, m := range map[string]interface{ Live() meter.Live }{"nil": nil, "not ok": fakeMeter{OK: false}} {
		w := setup(t).with(t, 0, m).do("GET", "/admin/", token, nil)
		body := w.Body.String()
		if w.Code != 200 {
			t.Fatalf("%s: %d", name, w.Code)
		}
		for _, want := range []string{"metering unavailable", "aaaa", "bbbb", "b-one", "b-two"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: page lacks %q", name, want)
			}
		}
	}
}

func TestIndexRange(t *testing.T) {
	e := setup(t)
	body := e.do("GET", "/admin/?range=24h", token, nil).Body.String()
	if !strings.Contains(body, `<a href="?range=24h" class="cur" aria-current="page">24 h</a>`) || !strings.Contains(body, `data-buckets="96"`) {
		t.Error("24h range not applied")
	}
	body = e.do("GET", "/admin/?range=bogus", token, nil).Body.String()
	if !strings.Contains(body, `<a href="?range=1h" class="cur" aria-current="page">1 h</a>`) || !strings.Contains(body, `data-buckets="60"`) {
		t.Error("bogus range does not fall back to 1h")
	}
}

func TestIndexAutoReloadScript(t *testing.T) {
	w := setup(t).do("GET", "/admin/", token, nil)
	if !strings.Contains(w.Body.String(), "setInterval(function(){ if (!document.hidden) location.reload() }, 15000)") {
		t.Error("no visibility-guarded reload")
	}
	if got := w.Header().Get("Content-Security-Policy"); got != "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'" {
		t.Errorf("CSP changed: %s", got)
	}
}

func TestIndexEscapesNodeNames(t *testing.T) {
	e := setup(t)
	id := e.hs.AddNode("f-aaaa", "<img src=x>", true)
	e.usage(t, store.UsageSample{FleetID: "aaaa", NodeID: id, Rx: 1e6})
	body := e.do("GET", "/admin/", token, nil).Body.String()
	if strings.Contains(body, "<img") {
		t.Error("raw hostname in the page")
	}
	if lg := between(t, body, `<div class="lg">`, "</div>"); !strings.Contains(lg, "&lt;img src=x&gt;") {
		t.Errorf("legend lacks the escaped name: %s", lg)
	}
	if svg := between(t, body, "<svg", "</svg>"); strings.Contains(svg, "src=x") {
		t.Errorf("name in the svg: %s", svg)
	}
}

func (e env) addDevice(t *testing.T, fleet, host string) string {
	t.Helper()
	id := e.hs.AddNode("f-"+fleet, host, true)
	if err := e.st.AddDevice(context.Background(), fleet, id, t0); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestIndexSplitsDevices(t *testing.T) {
	e := setup(t)
	e.addDevice(t, "aaaa", "phone-x")
	e.addDevice(t, "aaaa", "laptop-y")
	body := e.do("GET", "/admin/", token, nil).Body.String()
	fleet := between(t, body, `data-id="aaaa"`, `data-id="bbbb"`)
	box, devs, ok := strings.Cut(fleet, "Devices")
	if !ok || !strings.Contains(box, "b-one") || strings.Contains(box, "phone-x") || strings.Contains(box, "laptop-y") {
		t.Fatalf("boxes and devices not apart:\n%s", fleet)
	}
	if !strings.Contains(devs, "phone-x") || !strings.Contains(devs, "laptop-y") || strings.Contains(devs, "b-one") {
		t.Fatalf("devices sub-list wrong:\n%s", devs)
	}
	for _, want := range []string{"2 devices", "1 / 1 online", "<b>2</b><span>devices</span>"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// devices are not boxes: the summary counts one box online of two
	if !strings.Contains(body, "1 / 2</b><span>nodes online") {
		t.Error("summary counts devices as boxes")
	}
}

func TestRemoveDevice(t *testing.T) {
	e := setup(t)
	id := e.addDevice(t, "aaaa", "phone-x")
	if w := e.do("POST", "/admin/fleets/aaaa/nodes/"+id+"/remove", token, csrf(e)); w.Code != 303 {
		t.Fatalf("%d", w.Code)
	}
	if e.hs.NodeCount("f-aaaa") != 1 {
		t.Fatal("device node still in headscale")
	}
	if all, _ := e.st.AllDevices(context.Background()); len(all) != 0 {
		t.Fatalf("store row left: %v", all)
	}
}

func (e env) shared(t *testing.T, at time.Time, samples ...store.UsageSample) {
	t.Helper()
	if err := e.st.ApplyShareUsage(context.Background(), at, samples); err != nil {
		t.Fatal(err)
	}
}

func TestAdminShowsSharedThisMonth(t *testing.T) {
	e := setup(t)
	one, two := e.nodeID(t, "f-aaaa", "b-one"), e.nodeID(t, "f-bbbb", "b-two")
	// aaaa has relayed traffic, bbbb only shared traffic; the last sample is last month's.
	e.usage(t, store.UsageSample{FleetID: "aaaa", NodeID: one, Rx: 2e9})
	e.shared(t, t0.Add(-5*time.Minute), store.UsageSample{FleetID: "bbbb", NodeID: two, Rx: 3e9, Tx: 7})
	e.shared(t, t0.Add(-4*time.Minute), store.UsageSample{FleetID: "bbbb", NodeID: two, Rx: 1e9})
	e.shared(t, t0.Add(-3*time.Minute), store.UsageSample{FleetID: "zzzz", NodeID: "99", Rx: 2e9})
	e.shared(t, t0.AddDate(0, -1, 0), store.UsageSample{FleetID: "bbbb", NodeID: two, Rx: 9e9})
	body := e.do("GET", "/admin/", token, nil).Body.String()

	for _, want := range []string{"<b>6.0 GB</b><span>shared this month</span>", "<b>2.0 GB</b><span>relayed this month</span>"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if line := between(t, body, "deleted fleets", "</p>"); !strings.Contains(line, "0 B relayed") || !strings.Contains(line, "2.0 GB shared") {
		t.Errorf("deleted fleets line: %s", line)
	}
	if head := between(t, body, "<code>bbbb</code>", "</summary>"); !strings.Contains(head, "4.0 GB shared") {
		t.Errorf("fleet bbbb (shared only) header lacks its shared volume: %s", head)
	}
	if head := between(t, body, "<code>aaaa</code>", "</summary>"); !strings.Contains(head, "0 B shared") {
		t.Errorf("fleet aaaa header: %s", head)
	}
	if row := between(t, body, `data-node-id="`+two+`"`, "</tr>"); !strings.Contains(row, `data-shared-bytes="4000000000"`) ||
		!strings.Contains(row, "4.0 GB shared") || !strings.Contains(row, `data-up-month="0"`) {
		t.Errorf("node row: %s", row)
	}
	if row := between(t, body, `data-node-id="`+one+`"`, "</tr>"); !strings.Contains(row, `data-shared-bytes="0"`) {
		t.Errorf("node row without shared traffic: %s", row)
	}
	if a, b := strings.Index(body, "<code>aaaa</code>"), strings.Index(body, "<code>bbbb</code>"); a < 0 || b < a {
		t.Error("fleets are not sorted by relayed volume")
	}

	// The chart: relayed by default (and with kind=relayed), shared with kind=shared.
	chart := func(fleet, path string) string {
		return between(t, e.do("GET", path, token, nil).Body.String(), `<details data-id="`+fleet+`"`, "</svg>")
	}
	if none, relayed := chart("aaaa", "/admin/?range=24h"), chart("aaaa", "/admin/?range=24h&kind=relayed"); none != relayed || !strings.Contains(none, "<polygon") {
		t.Error("no kind is not the relayed chart of aaaa")
	}
	if chart("bbbb", "/admin/?range=24h") == chart("bbbb", "/admin/?range=24h&kind=shared") {
		t.Error("kind=shared did not change bbbb's chart")
	}
	if !strings.Contains(chart("bbbb", "/admin/?range=24h&kind=shared"), "<polygon") || strings.Contains(chart("aaaa", "/admin/?range=24h&kind=shared"), "<polygon") {
		t.Error("the shared chart does not follow the shared series")
	}
	sharedPage := e.do("GET", "/admin/?range=24h&kind=shared", token, nil).Body.String()
	for _, want := range []string{`<a href="?range=24h&amp;kind=shared" class="cur" aria-current="page">24 h</a>`, `<a href="?range=24h">relayed</a>`, `class="cur" aria-current="page">shared</a>`, "b-two"} {
		if !strings.Contains(sharedPage, want) {
			t.Errorf("shared chart page lacks %q", want)
		}
	}
	if p := e.do("GET", "/admin/?range=24h", token, nil).Body.String(); !strings.Contains(p, `<a href="?range=24h&amp;kind=shared">shared</a>`) {
		t.Error("no toggle to the shared chart")
	}
}

func TestPageTemplateIsUTF8(t *testing.T) {
	if !utf8.ValidString(pageHTML) {
		t.Fatal("page.html is not valid UTF-8")
	}
}

func TestAdminBanAndUnban(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	form := func(name string) url.Values { f := csrf(e); f.Set("name", name); return f }

	if w := e.do("POST", "/admin/share/banned", token, url.Values{"name": {"spam"}}); w.Code != 400 {
		t.Fatalf("ban without csrf: %d", w.Code)
	}
	for _, bad := range []string{"", "A b", "a-"} {
		if w := e.do("POST", "/admin/share/banned", token, form(bad)); w.Code != 400 {
			t.Fatalf("ban %q: %d, want 400", bad, w.Code)
		}
	}
	// A reserved word is a valid label: the operator may ban it too.
	for _, n := range []string{"spam", "www"} {
		if w := e.do("POST", "/admin/share/banned", token, form(n)); w.Code != 303 || w.Header().Get("Location") != "/admin/" {
			t.Fatalf("ban %s: %d %s", n, w.Code, w.Header().Get("Location"))
		}
	}
	if got, _ := e.st.BannedNames(ctx); strings.Join(got, ",") != "spam,www" {
		t.Fatalf("banned = %v", got)
	}
	body := e.do("GET", "/admin/", token, nil).Body.String()
	if !strings.Contains(body, "Forbidden names") || !strings.Contains(body, `action="/admin/share/banned/spam/delete"`) {
		t.Fatalf("page lacks the forbidden list:\n%s", body)
	}
	if w := e.do("POST", "/admin/share/banned/spam/delete", token, nil); w.Code != 400 {
		t.Fatalf("unban without csrf: %d", w.Code)
	}
	if w := e.do("POST", "/admin/share/banned/Bad%20Name/delete", token, csrf(e)); w.Code != 400 {
		t.Fatalf("unban of an invalid name: %d, want 400", w.Code)
	}
	if w := e.do("POST", "/admin/share/banned/spam/delete", token, csrf(e)); w.Code != 303 {
		t.Fatalf("unban: %d", w.Code)
	}
	if w := e.do("POST", "/admin/share/banned/spam/delete", token, csrf(e)); w.Code != 303 {
		t.Fatalf("second unban: %d, want 303", w.Code)
	}
	if got, _ := e.st.BannedNames(ctx); strings.Join(got, ",") != "www" {
		t.Fatalf("banned after unban = %v", got)
	}
}

func TestAdminRevokeBansAndReleases(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if err := e.st.SetBoxKey(ctx, "aaaa", "7", "key7", t0); err != nil {
		t.Fatal(err)
	}
	if err := e.st.ClaimName(ctx, "7", "boxa", t0); err != nil {
		t.Fatal(err)
	}
	body := e.do("GET", "/admin/", token, nil).Body.String()
	for _, want := range []string{"Shared names", "boxa", `action="/admin/share/names/boxa/revoke"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page lacks %q", want)
		}
	}
	if w := e.do("POST", "/admin/share/names/boxa/revoke", token, nil); w.Code != 400 {
		t.Fatalf("revoke without csrf: %d", w.Code)
	}
	if w := e.do("POST", "/admin/share/names/boxa/revoke", token, csrf(e)); w.Code != 303 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if names, _ := e.st.ListNames(ctx); len(names) != 0 {
		t.Fatalf("names after revoke: %v", names)
	}
	if got, _ := e.st.BannedNames(ctx); strings.Join(got, ",") != "boxa" {
		t.Fatalf("banned = %v", got)
	}
	if err := e.st.ClaimName(ctx, "7", "boxa", t0); !errors.Is(err, store.ErrBanned) {
		t.Fatalf("reclaim: %v, want ErrBanned", err)
	}
	body = e.do("GET", "/admin/", token, nil).Body.String()
	i := strings.Index(body, "Forbidden names")
	if i < 0 || !strings.Contains(body[i:], "boxa") {
		t.Fatal("boxa is not listed under Forbidden names")
	}
	if w := e.do("POST", "/admin/share/names/A_b/revoke", token, csrf(e)); w.Code != 400 {
		t.Fatalf("revoke of an invalid name: %d", w.Code)
	}
}

// The foot of the page names the version that runs, when the build set one.
func TestIndexShowsVersion(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/relay.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	hs := fakes.NewHS(&fakes.Log{}, func() time.Time { return t0 })
	h, err := New(Config{Token: token, NodesPerFleet: 50, MaxFleets: 1000, Version: "v9.9.9"}, Deps{
		Store: st, Headscale: hs, Now: func() time.Time { return t0 },
		Remover: &fleets.Remover{Store: st, Headscale: hs, Locks: &fleets.Locks{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := env{h, hs, st}
	if body := e.do("GET", "/admin/", token, nil).Body.String(); !strings.Contains(body, "<footer class=\"mut xs foot\">relay v9.9.9</footer>") {
		t.Errorf("no version in the foot of the page:\n%s", body)
	}
	if body := setup(t).do("GET", "/admin/", token, nil).Body.String(); strings.Contains(body, "<footer") {
		t.Error("a foot without a version")
	}
}

// The built-in list shows on the page, folded, apart from the operator's own.
func TestIndexShowsBuiltInReservedNames(t *testing.T) {
	body := setup(t).do("GET", "/admin/", token, nil).Body.String()
	block := between(t, body, `<details class="builtin">`, "</details>")
	for _, want := range []string{"names no box can claim", "<code>paypal</code>", "<code>login</code>"} {
		if !strings.Contains(block, want) {
			t.Errorf("built-in list lacks %q", want)
		}
	}
	if strings.Contains(block, "<button") {
		t.Error("a built-in name has a button")
	}
	if !strings.Contains(body, "0 yours &middot; ") {
		t.Error("the head of the card does not count both lists")
	}
}
