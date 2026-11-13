package community

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

var t0 = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

type env struct {
	t   *testing.T
	st  store.Store
	e   *Engine
	now time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/r.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	v := &env{t: t, st: st, now: t0}
	v.e = &Engine{Store: st, Now: func() time.Time { return v.now }}
	return v
}

func (v *env) must(err error) {
	v.t.Helper()
	if err != nil {
		v.t.Fatal(err)
	}
}

// box adds node to fleet (created age ago), gives it a share name and turns sharing on or off.
func (v *env) box(fleet, node string, age time.Duration, share bool) store.BoxRef {
	v.t.Helper()
	ctx := context.Background()
	if err := v.st.CreateFleet(ctx, store.Fleet{ID: fleet, CreatedAt: v.now.Add(-age)}); err != nil && !errors.Is(err, store.ErrExists) {
		v.t.Fatal(err)
	}
	v.must(v.st.SetBoxKey(ctx, fleet, node, "key-"+node, v.now.Add(-age)))
	v.must(v.st.ClaimName(ctx, node, "n"+node, v.now.Add(-age)))
	v.must(v.st.SetProtection(ctx, node, store.Protection{RelayFilter: true, ShareBans: share}))
	return store.BoxRef{FleetID: fleet, NodeID: node, Name: "n" + node}
}

// report records that key reached ref through the relay (when seen), then reports it.
func (v *env) report(ref store.BoxRef, key, reason string, seen bool) {
	v.t.Helper()
	ctx := context.Background()
	if seen {
		v.must(v.st.RecordSeen(ctx, v.now, []store.Seen{{Key: key, NodeID: ref.NodeID}}))
	}
	v.must(v.e.Accept(ctx, ref, []Item{{Key: key, Reason: reason, App: "jellyfin", Since: v.now}}))
}

func (v *env) tick() bool {
	v.t.Helper()
	opened, err := v.e.Tick(context.Background())
	v.must(err)
	return opened
}

func (v *env) bans() map[string]store.CommunityBan {
	v.t.Helper()
	bs, err := v.st.ActiveBans(context.Background(), v.now)
	v.must(err)
	out := map[string]store.CommunityBan{}
	for _, b := range bs {
		out[b.Key] = b
	}
	return out
}

// two makes eligible fleets A and B with one sharing box each.
func two(v *env) (a, b store.BoxRef) {
	return v.box("A", "1", 8*day, true), v.box("B", "2", 8*day, true)
}

const ip = "203.0.113.7/32"

func TestTwoFleetsOpenADayBan(t *testing.T) {
	v := newEnv(t)
	a, b := two(v)
	v.report(a, ip, "waf", true)
	v.report(b, ip, "scan", true)
	v.tick()
	v.tick() // idempotent
	bs := v.bans()
	got, ok := bs[ip]
	if len(bs) != 1 || !ok {
		t.Fatalf("bans = %+v", bs)
	}
	if got.Kind != "address" || got.Strike != 1 || !got.Since.Equal(t0) || !got.Until.Equal(t0.Add(day)) || got.Reasons != "scan,waf" || got.Fleets != 2 {
		t.Fatalf("ban = %+v", got)
	}
	if n, err := v.st.ContributedSince(context.Background(), "A", t0.Add(-time.Hour)); err != nil || n != 1 {
		t.Fatalf("contributed A = %d, %v", n, err)
	}
}

// Tick reports when it opened a ban (an ended one leaves the snapshot by its own end time).
func TestTickReportsOpenedBan(t *testing.T) {
	v := newEnv(t)
	a, b := two(v)
	if v.tick() {
		t.Fatal("nothing reported, yet opened")
	}
	v.report(a, ip, "waf", true)
	v.report(b, ip, "scan", true)
	if !v.tick() {
		t.Fatal("ban opened, not reported")
	}
	if v.tick() {
		t.Fatal("second tick reported a change")
	}
}

func TestSameFleetTwiceIsOneFleet(t *testing.T) {
	v := newEnv(t)
	a1, a2 := v.box("A", "1", 8*day, true), v.box("A", "2", 8*day, true)
	v.report(a1, ip, "scan", true)
	v.report(a2, ip, "scan", true)
	v.tick()
	if bs := v.bans(); len(bs) != 0 {
		t.Fatalf("bans = %+v", bs)
	}
}

func TestReportNeedsSeenConnection(t *testing.T) {
	v := newEnv(t)
	a, b := two(v)
	v.report(a, ip, "scan", true)
	v.report(b, ip, "scan", false)
	// Seen by another box of the relay does not count for B either.
	v.must(v.st.RecordSeen(context.Background(), v.now, []store.Seen{{Key: ip, NodeID: "9"}}))
	v.tick()
	if bs := v.bans(); len(bs) != 0 {
		t.Fatalf("bans = %+v", bs)
	}
}

func TestSeenLongBeforeTheBanDoesNotCount(t *testing.T) {
	v := newEnv(t)
	a, b := two(v)
	v.report(a, ip, "scan", true)
	v.must(v.st.RecordSeen(context.Background(), v.now.Add(-25*time.Hour), []store.Seen{{Key: ip, NodeID: b.NodeID}}))
	v.report(b, ip, "scan", false)
	v.tick()
	if bs := v.bans(); len(bs) != 0 {
		t.Fatalf("bans = %+v", bs)
	}
}

func TestYoungFleetDoesNotCount(t *testing.T) {
	v := newEnv(t)
	a, b := v.box("A", "1", 8*day, true), v.box("B", "2", 6*day, true)
	v.report(a, ip, "scan", true)
	v.report(b, ip, "scan", true)
	v.tick()
	if bs := v.bans(); len(bs) != 0 {
		t.Fatalf("bans = %+v", bs)
	}
}

func TestFleetWithoutShareNameDoesNotCount(t *testing.T) {
	v := newEnv(t)
	a := v.box("A", "1", 8*day, true)
	ctx := context.Background()
	v.must(v.st.CreateFleet(ctx, store.Fleet{ID: "B", CreatedAt: v.now.Add(-8 * day)}))
	v.must(v.st.SetBoxKey(ctx, "B", "2", "key-2", v.now.Add(-8*day)))
	v.must(v.st.SetProtection(ctx, "2", store.Protection{ShareBans: true}))
	v.report(a, ip, "scan", true)
	v.report(store.BoxRef{FleetID: "B", NodeID: "2"}, ip, "scan", true)
	v.tick()
	if bs := v.bans(); len(bs) != 0 {
		t.Fatalf("bans = %+v", bs)
	}
}

func TestSharingOffDoesNotCount(t *testing.T) {
	v := newEnv(t)
	a, b := v.box("A", "1", 8*day, true), v.box("B", "2", 8*day, false)
	v.report(a, ip, "scan", true)
	v.report(b, ip, "scan", true)
	// A box with no protection row has sharing off too.
	ctx := context.Background()
	v.must(v.st.CreateFleet(ctx, store.Fleet{ID: "C", CreatedAt: v.now.Add(-8 * day)}))
	v.must(v.st.SetBoxKey(ctx, "C", "3", "key-3", v.now.Add(-8*day)))
	v.must(v.st.ClaimName(ctx, "3", "n3", v.now.Add(-8*day)))
	v.report(store.BoxRef{FleetID: "C", NodeID: "3"}, ip, "scan", true)
	v.tick()
	if bs := v.bans(); len(bs) != 0 {
		t.Fatalf("bans = %+v", bs)
	}
}

func TestAcceptDropsBadItems(t *testing.T) {
	v := newEnv(t)
	a := v.box("A", "1", 8*day, true)
	ctx := context.Background()
	v.must(v.st.RecordSeen(ctx, v.now, []store.Seen{{Key: "10.1.2.3/32", NodeID: "1"}, {Key: ip, NodeID: "1"}}))
	v.must(v.e.Accept(ctx, a, []Item{
		{Key: "10.1.2.3/32", Reason: "scan", App: "x", Since: v.now},
		{Key: ip, Reason: "scan", App: "x"}, // zero since
		{Key: "203.0.113.0/24", Reason: "scan", App: "x", Since: v.now},
	}))
	rs, err := v.st.ReportsSince(ctx, time.Time{})
	if err != nil || len(rs) != 0 {
		t.Fatalf("reports = %+v, %v", rs, err)
	}
	// A bare address is stored as its key.
	v.must(v.e.Accept(ctx, a, []Item{{Key: "203.0.113.7", Reason: "scan", App: "x", Since: v.now}}))
	if rs, err := v.st.ReportsSince(ctx, time.Time{}); err != nil || len(rs) != 1 || rs[0].Key != ip || rs[0].FleetID != "A" {
		t.Fatalf("reports = %+v, %v", rs, err)
	}
}

// expire moves the clock to at and ticks, so the running ban ends.
func (v *env) at(at time.Time) { v.now = at; v.tick() }

func TestRepeatEscalates(t *testing.T) {
	v := newEnv(t)
	a, b := two(v)
	v.report(a, ip, "scan", true)
	v.report(b, ip, "scan", true)
	v.tick()
	v.at(t0.Add(day))
	if bs := v.bans(); len(bs) != 0 {
		t.Fatalf("ban 1 not ended: %+v", bs)
	}
	v.now = t0.Add(10 * day)
	v.report(a, ip, "scan", true)
	v.report(b, ip, "waf", true)
	v.tick()
	got := v.bans()[ip]
	if got.Strike != 2 || !got.Until.Equal(v.now.Add(7*day)) {
		t.Fatalf("ban 2 = %+v", got)
	}
	v.at(v.now.Add(7 * day))
	v.now = v.now.Add(10 * day)
	v.report(a, ip, "scan", true)
	v.report(b, ip, "scan", true)
	v.tick()
	got = v.bans()[ip]
	if got.Strike != 3 || !got.Until.IsZero() {
		t.Fatalf("ban 3 = %+v", got)
	}
}

func TestRepeatAfter31DaysStartsOver(t *testing.T) {
	v := newEnv(t)
	a, b := two(v)
	v.report(a, ip, "scan", true)
	v.report(b, ip, "scan", true)
	v.tick()
	v.at(t0.Add(day))
	v.now = t0.Add(day + 31*day)
	v.report(a, ip, "scan", true)
	v.report(b, ip, "scan", true)
	v.tick()
	if got := v.bans()[ip]; got.Strike != 1 || !got.Until.Equal(v.now.Add(day)) {
		t.Fatalf("ban = %+v", got)
	}
}

func TestReportDuringBanDoesNotExtend(t *testing.T) {
	v := newEnv(t)
	a, b := two(v)
	c := v.box("C", "3", 8*day, true)
	v.report(a, ip, "scan", true)
	v.report(b, ip, "scan", true)
	v.tick()
	v.now = t0.Add(time.Hour)
	v.report(c, ip, "waf", true)
	v.report(a, ip, "rate", true)
	v.tick()
	if got := v.bans()[ip]; got.Strike != 1 || !got.Until.Equal(t0.Add(day)) || got.Reasons != "scan" {
		t.Fatalf("ban = %+v", got)
	}
}

// The reports that opened a ban are still under 24 h old when it ends (a box's since may run
// ahead of the relay clock): they must not open a second, longer ban on their own.
func TestEndedBanDoesNotReopenOnItsOwnReports(t *testing.T) {
	v := newEnv(t)
	a, b := two(v)
	v.now = t0.Add(-time.Minute) // the relay clock is a minute behind the boxes
	v.must(v.st.RecordSeen(context.Background(), v.now, []store.Seen{{Key: ip, NodeID: "1"}, {Key: ip, NodeID: "2"}}))
	ctx := context.Background()
	for _, r := range []store.BoxRef{a, b} {
		v.must(v.e.Accept(ctx, r, []Item{{Key: ip, Reason: "scan", App: "x", Since: t0}}))
	}
	v.tick()
	v.at(v.now.Add(day))
	if bs := v.bans(); len(bs) != 0 {
		t.Fatalf("reopened: %+v", bs)
	}
}

func TestLiftedBanDoesNotReopen(t *testing.T) {
	v := newEnv(t)
	a, b := two(v)
	v.report(a, ip, "scan", true)
	v.report(b, ip, "scan", true)
	v.tick()
	v.now = t0.Add(time.Hour)
	v.must(v.st.LiftBan(context.Background(), ip, v.now))
	v.tick()
	if bs := v.bans(); len(bs) != 0 {
		t.Fatalf("reopened: %+v", bs)
	}
}

// banAll has fleets A and B report every key.
func banAll(v *env, keys ...string) {
	a, b := two(v)
	for _, k := range keys {
		v.report(a, k, "scan", true)
		v.report(b, k, "scan", true)
	}
	v.tick()
}

func keys(format string, n int) []string {
	var out []string
	for i := 1; i <= n; i++ {
		out = append(out, fmt.Sprintf(format, i))
	}
	return out
}

func TestFiveInA24OpensRange(t *testing.T) {
	v := newEnv(t)
	banAll(v, keys("198.51.100.%d/32", 5)...)
	bs := v.bans()
	got, ok := bs["198.51.100.0/24"]
	if len(bs) != 6 || !ok || got.Kind != "range" || got.Strike != 1 || !got.Until.Equal(t0.Add(day)) || got.Reasons != "scan" || got.Fleets != 2 {
		t.Fatalf("bans = %+v", bs)
	}
	v.tick()
	if got2 := v.bans()["198.51.100.0/24"]; got2 != got {
		t.Fatalf("second tick changed the range: %+v", got2)
	}

	v = newEnv(t)
	banAll(v, keys("198.51.100.%d/32", 4)...)
	if bs := v.bans(); len(bs) != 4 {
		t.Fatalf("4 addresses: bans = %+v", bs)
	}
}

func TestLiftedRangeDoesNotReopenOnTheSameBans(t *testing.T) {
	v := newEnv(t)
	banAll(v, keys("198.51.100.%d/32", 5)...)
	v.now = t0.Add(time.Hour)
	v.must(v.st.LiftBan(context.Background(), "198.51.100.0/24", v.now))
	v.tick()
	if _, ok := v.bans()["198.51.100.0/24"]; ok {
		t.Fatal("range reopened on the bans that opened it")
	}
}

func TestIPv6RangeIs48(t *testing.T) {
	v := newEnv(t)
	banAll(v, keys("2001:db8:1:%d::/64", 5)...)
	if got, ok := v.bans()["2001:db8:1::/48"]; !ok || got.Kind != "range" || got.Strike != 1 {
		t.Fatalf("bans = %+v", v.bans())
	}
}

func TestAllowListWins(t *testing.T) {
	v := newEnv(t)
	allow := netip.MustParsePrefix("203.0.113.0/24")
	v.e.Allowed = func(p netip.Prefix) bool { return allow.Bits() <= p.Bits() && allow.Contains(p.Addr()) }
	banAll(v, ip)
	if bs := v.bans(); len(bs) != 0 {
		t.Fatalf("bans = %+v", bs)
	}

	v = newEnv(t)
	rng := netip.MustParsePrefix("198.51.100.0/24")
	v.e.Allowed = func(p netip.Prefix) bool { return p == rng }
	banAll(v, keys("198.51.100.%d/32", 5)...)
	if bs := v.bans(); len(bs) != 5 {
		t.Fatalf("allowed range banned: %+v", bs)
	}
}

func TestKeyRejectsPrivate(t *testing.T) {
	for _, s := range []string{"10.1.2.3", "100.64.1.1", "fe80::1", "::1", "127.0.0.1", "192.168.1.1/32", "0.0.0.0",
		"224.0.0.1", "::ffff:10.1.2.3", "::ffff:100.64.1.1", "fd00::1", "203.0.113.0/24", "2001:db8::/48", "nope", ""} {
		if k, ok := Key(s); ok {
			t.Errorf("Key(%q) = %q, want false", s, k)
		}
	}
	for in, want := range map[string]string{
		"2001:db8:1:2:3::9":      "2001:db8:1:2::/64",
		"2001:db8:1:2::/64":      "2001:db8:1:2::/64",
		"203.0.113.7":            "203.0.113.7/32",
		"203.0.113.7/32":         "203.0.113.7/32",
		"::ffff:203.0.113.7":     "203.0.113.7/32",
		"::ffff:203.0.113.7/128": "203.0.113.7/32",
	} {
		if got, ok := Key(in); !ok || got != want {
			t.Errorf("Key(%q) = %q, %v, want %q", in, got, ok, want)
		}
	}
}

func TestFlaggedASNs(t *testing.T) {
	asnOf := func(a netip.Addr) (uint, string) {
		if a.As4()[0] == 198 {
			return 64500, "Example Net"
		}
		return 0, ""
	}
	ranges := func(n int) []store.CommunityBan {
		bs := []store.CommunityBan{{Key: "198.51.200.7/32", Kind: "address"}, {Key: "203.0.113.0/24", Kind: "range"}}
		for i := 0; i < n; i++ {
			bs = append(bs, store.CommunityBan{Key: fmt.Sprintf("198.51.%d.0/24", i), Kind: "range"})
		}
		return bs
	}
	got := FlaggedASNs(ranges(10), asnOf)
	if len(got) != 1 || got[0] != (ASNFlag{ASN: 64500, Org: "Example Net", Ranges: 10}) {
		t.Fatalf("10 ranges: %+v", got)
	}
	if got := FlaggedASNs(ranges(9), asnOf); len(got) != 0 {
		t.Fatalf("9 ranges: %+v", got)
	}
}

func TestAcceptDropsSinceOutOfBounds(t *testing.T) {
	v := newEnv(t)
	a := v.box("A", "1", 8*day, true)
	ctx := context.Background()
	v.must(v.st.RecordSeen(ctx, v.now, []store.Seen{{Key: ip, NodeID: "1"}}))
	v.must(v.e.Accept(ctx, a, []Item{
		{Key: ip, Reason: "scan", App: "x", Since: v.now.Add(-day - time.Second)},
		{Key: ip, Reason: "scan", App: "x", Since: v.now.Add(3 * time.Minute)},
	}))
	if rs, err := v.st.ReportsSince(ctx, time.Time{}); err != nil || len(rs) != 0 {
		t.Fatalf("reports = %+v, %v", rs, err)
	}
	v.must(v.e.Accept(ctx, a, []Item{{Key: ip, Reason: "scan", App: "x", Since: v.now.Add(-day + time.Minute)}}))
	if rs, err := v.st.ReportsSince(ctx, time.Time{}); err != nil || len(rs) != 1 {
		t.Fatalf("reports = %+v, %v", rs, err)
	}
}
