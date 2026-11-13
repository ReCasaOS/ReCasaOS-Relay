package protect

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/feeds"
	"github.com/ReCasaOS/recasaos-relay/internal/geo"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func mmdb(t *testing.T, typ string, nets map[string]mmdbtype.Map) []byte {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: typ, IPVersion: 6, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, v := range nets {
		_, n, _ := net.ParseCIDR(cidr)
		if err := w.Insert(n, v); err != nil {
			t.Fatal(err)
		}
	}
	var b bytes.Buffer
	if _, err := w.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func fixture(t *testing.T) (*Compiler, store.Store) {
	t.Helper()
	c, st := coldFixture(t)
	c.Geo.Tick(context.Background()) // opens the files; they are from this month, nothing is fetched
	return c, st
}

// coldFixture is fixture with the DB-IP files on disk but not opened yet (a relay just started).
func coldFixture(t *testing.T) (*Compiler, store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	dir := t.TempDir()
	cc := func(c string) mmdbtype.Map {
		return mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(c)}}
	}
	os.WriteFile(filepath.Join(dir, "dbip-country-lite.mmdb"), mmdb(t, "DBIP-Country-Lite", map[string]mmdbtype.Map{
		"203.0.113.0/24": cc("XX"), "198.51.100.0/25": cc("XX"), "192.0.2.0/24": cc("YY"),
	}), 0o644)
	os.WriteFile(filepath.Join(dir, "dbip-asn-lite.mmdb"), mmdb(t, "DBIP-ASN-Lite", map[string]mmdbtype.Map{
		"203.0.113.0/24": {"autonomous_system_number": mmdbtype.Uint32(64500), "autonomous_system_organization": mmdbtype.String("N")},
	}), 0o644)
	g := &geo.DB{Dir: dir, BaseURL: "http://127.0.0.1:1/"}
	f := &feeds.Fetcher{Store: st, Dir: t.TempDir()}
	return &Compiler{Store: st, Feeds: f, Geo: g, Now: func() time.Time { return t0 }}, st
}

func addFeed(t *testing.T, c *Compiler, name string, enabled bool, copyText string) {
	t.Helper()
	id, err := c.Store.AddFeed(context.Background(), store.Feed{Name: name, Format: "text", EverySec: 3600, MaxEntries: 10, Enabled: enabled})
	if err != nil {
		t.Fatal(err)
	}
	if copyText != "" {
		os.WriteFile(filepath.Join(c.Feeds.Dir, strconv.FormatInt(id, 10)+".txt"), []byte(copyText), 0o644)
	}
}

func TestSnapshotHasEverySource(t *testing.T) {
	ctx := context.Background()
	c, st := fixture(t)
	st.AddAllow(ctx, store.AllowEntry{Prefix: "192.0.2.0/24", Added: t0})
	st.AddManual(ctx, store.ManualBan{Kind: "address", Value: "198.51.100.200", Since: t0})
	st.AddManual(ctx, store.ManualBan{Kind: "country", Value: "XX", Since: t0})
	addFeed(t, c, "FireHOL level 1", true, "1.1.1.1\n2.2.2.0/24\n")
	addFeed(t, c, "Off", false, "9.9.9.9\n")
	st.OpenBan(ctx, store.CommunityBan{Key: "203.0.113.7/32", Kind: "address", Since: t0, Reasons: "scan", Fleets: 3}, nil)
	st.CreateFleet(ctx, store.Fleet{ID: "f1", SecretHash: "h", HeadscaleUser: "u", CreatedAt: t0})
	st.SetBoxKey(ctx, "f1", "7", "key7", t0)
	if err := st.ClaimName(ctx, "7", "mybox", t0); err != nil {
		t.Fatal(err)
	}
	st.SetProtection(ctx, "7", store.Protection{RelayFilter: true})
	st.SuspendName(ctx, "badname", t0)

	body, version, err := c.Build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got Snapshot
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	want := Snapshot{
		Version: version,
		Allow:   []string{"192.0.2.0/24"},
		Manual: Manual{Address: []string{"198.51.100.200/32"}, Range: []string{},
			ASN: []string{}, Country: []string{"198.51.100.0/25", "203.0.113.0/24"}},
		External:  map[string][]string{"FireHOL level 1": {"1.1.1.1/32", "2.2.2.0/24"}},
		Community: Community{Address: []string{"203.0.113.7/32"}, Range: []string{}},
		Names:     map[string]NameFilter{"mybox": {Filter: true, Community: false}},
		Suspended: []string{"badname"},
	}
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Fatalf("got  %s\nwant %s", g, w)
	}
	if len(version) != 64 {
		t.Fatalf("version %q", version)
	}
	// the version is stable and changes with the content
	if _, v2, _ := c.Build(ctx); v2 != version {
		t.Fatal("version not stable")
	}
	st.AddAllow(ctx, store.AllowEntry{Prefix: "10.0.0.0/8", Added: t0})
	if _, v3, _ := c.Build(ctx); v3 == version {
		t.Fatal("version did not change")
	}
}

func TestCurrentCachesUntilInvalidateOrAge(t *testing.T) {
	ctx := context.Background()
	c, st := fixture(t)
	now := t0
	c.Now = func() time.Time { return now }
	_, v1, _ := c.Current(ctx)
	st.AddAllow(ctx, store.AllowEntry{Prefix: "10.0.0.0/8", Added: t0})
	if _, v, _ := c.Current(ctx); v != v1 {
		t.Fatal("rebuilt without reason")
	}
	c.Invalidate()
	_, v2, _ := c.Current(ctx)
	if v2 == v1 {
		t.Fatal("Invalidate did not rebuild")
	}
	st.AddAllow(ctx, store.AllowEntry{Prefix: "172.16.0.0/12", Added: t0})
	now = now.Add(31 * time.Second) // the poll interval of share: no rebuild without a change
	if _, v, _ := c.Current(ctx); v != v2 {
		t.Fatal("rebuilt at 31 s without Invalidate")
	}
	now = now.Add(5 * time.Minute)
	if _, v, _ := c.Current(ctx); v == v2 {
		t.Fatal("old snapshot kept past maxAge")
	}
}

// A ban that ends leaves the snapshot at its end, without Invalidate and before maxAge: manual
// bans and community bans alike.
func TestCurrentRebuildsWhenABanEnds(t *testing.T) {
	ctx := context.Background()
	c, st := fixture(t)
	now := t0
	c.Now = func() time.Time { return now }
	st.AddManual(ctx, store.ManualBan{Kind: "address", Value: "198.51.100.200", Since: t0, Until: t0.Add(2 * time.Minute)})
	st.AddManual(ctx, store.ManualBan{Kind: "address", Value: "198.51.100.201", Since: t0})
	st.OpenBan(ctx, store.CommunityBan{Key: "203.0.113.7/32", Kind: "address", Since: t0, Until: t0.Add(3 * time.Minute), Reasons: "scan", Fleets: 2}, nil)
	has := func(s string) bool { b, _, _ := c.Current(ctx); return bytes.Contains(b, []byte(s)) }
	if !has("198.51.100.200/32") || !has("198.51.100.201/32") || !has("203.0.113.7/32") {
		t.Fatal("bans missing at start")
	}
	now = t0.Add(2 * time.Minute)
	if has("198.51.100.200/32") || !has("198.51.100.201/32") || !has("203.0.113.7/32") {
		t.Fatal("ended manual ban kept")
	}
	now = t0.Add(3 * time.Minute)
	if has("203.0.113.7/32") || !has("198.51.100.201/32") {
		t.Fatal("ended community ban kept")
	}
}

// share polls within seconds of a start, before the first protection tick has opened the DB-IP
// files: a country ban built then must fill in once the files are open and the cache invalidated.
func TestCountryBanFillsInAfterGeoOpens(t *testing.T) {
	ctx := context.Background()
	c, st := coldFixture(t)
	st.AddManual(ctx, store.ManualBan{Kind: "country", Value: "XX", Since: t0})
	if b, _, err := c.Current(ctx); err != nil || bytes.Contains(b, []byte("203.0.113.0/24")) {
		t.Fatalf("%s %v", b, err)
	}
	if changed, err := c.Geo.Tick(ctx); err != nil || !changed {
		t.Fatalf("first open: changed %v, %v", changed, err)
	}
	c.Invalidate()
	if b, _, _ := c.Current(ctx); !bytes.Contains(b, []byte("203.0.113.0/24")) {
		t.Fatalf("country prefixes missing after the files opened: %s", b)
	}
}

func TestCurrentConcurrent(t *testing.T) {
	c, _ := fixture(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); c.Current(context.Background()); c.Invalidate(); c.Allowed(netip.MustParsePrefix("1.1.1.1/32")) }()
	}
	wg.Wait()
}

func TestAllowedCoversPrefix(t *testing.T) {
	ctx := context.Background()
	c, st := fixture(t)
	id, _ := st.AddAllow(ctx, store.AllowEntry{Prefix: "192.0.2.0/24", Added: t0})
	for p, want := range map[string]bool{
		"192.0.2.9/32": true, "192.0.2.0/24": true, "192.0.2.0/25": true, "192.0.0.0/16": false, "198.51.100.1/32": false,
	} {
		if got := c.Allowed(netip.MustParsePrefix(p)); got != want { // before any build: from the store
			t.Errorf("%s = %v", p, got)
		}
	}
	c.Build(ctx)
	st.DeleteAllow(ctx, id)
	if !c.Allowed(netip.MustParsePrefix("192.0.2.9/32")) { // after a build: the last build
		t.Error("not read from the last build")
	}
}
