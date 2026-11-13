package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/feeds"
	"github.com/ReCasaOS/recasaos-relay/internal/protect"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// A snapshot built by enrolment's compiler parses here into the same decisions: the two sides keep
// their own copy of the JSON shape, this catches one drifting from the other.
func TestSnapshotRoundTrip(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = st.AddAllow(ctx, store.AllowEntry{Prefix: "192.0.2.0/24", Added: t0})
	must(err)
	_, err = st.AddManual(ctx, store.ManualBan{Kind: "range", Value: "192.0.2.0/23", Since: t0})
	must(err)
	_, err = st.AddManual(ctx, store.ManualBan{Kind: "address", Value: "198.51.100.200", Since: t0})
	must(err)
	id, err := st.AddFeed(ctx, store.Feed{Name: "FireHOL level 1", Format: "text", EverySec: 3600, MaxEntries: 10, Enabled: true})
	must(err)
	dir := t.TempDir()
	must(os.WriteFile(filepath.Join(dir, strconv.FormatInt(id, 10)+".txt"), []byte("1.1.1.1\n"), 0o644))
	must(st.OpenBan(ctx, store.CommunityBan{Key: "203.0.113.7/32", Kind: "address", Since: t0.Add(-time.Hour), Reasons: "scan", Fleets: 3}, nil))
	must(st.CreateFleet(ctx, store.Fleet{ID: "f1", SecretHash: "h", HeadscaleUser: "u", CreatedAt: t0}))
	must(st.SetBoxKey(ctx, "f1", "7", "key7", t0))
	must(st.ClaimName(ctx, "7", "mybox", t0))
	must(st.SetProtection(ctx, "7", store.Protection{RelayFilter: true, ShareBans: true}))
	must(st.SuspendName(ctx, "badname", t0))

	c := &protect.Compiler{Store: st, Feeds: &feeds.Fetcher{Store: st, Dir: dir}, Now: func() time.Time { return t0 }}
	body, version, err := c.Build(ctx)
	must(err)
	f, err := parseFilter(body)
	must(err)
	if f.version != version {
		t.Fatalf("version %q, want %q", f.version, version)
	}
	for _, x := range []struct{ addr, name, reason, source string }{
		{"192.0.2.5", "mybox", "", ""}, // allow list before the manual range around it
		{"192.0.3.5", "mybox", "manual", "range"},
		{"198.51.100.200", "plain", "manual", "address"},
		{"9.9.9.9", "badname", "suspended", ""},
		{"1.1.1.1", "mybox", "external", "FireHOL level 1"},
		{"203.0.113.7", "mybox", "community", "address"},
		{"1.1.1.1", "plain", "", ""}, // a name that set no protection: no list applies
		{"9.9.9.9", "mybox", "", ""},
	} {
		if r, s := f.decide(netip.MustParseAddr(x.addr), x.name); r != x.reason || s != x.source {
			t.Errorf("%s for %s: %q/%q, want %q/%q", x.addr, x.name, r, s, x.reason, x.source)
		}
	}
}
