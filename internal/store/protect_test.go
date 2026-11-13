package store

import (
	"context"
	"testing"
	"time"
)

var pt0 = time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)

// box makes a fleet created at created, with a box key for node.
func box(t *testing.T, s Store, fleetID, node string, created time.Time) {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateFleet(ctx, fleet(fleetID, created)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetBoxKey(ctx, fleetID, node, "key-"+node, created); err != nil {
		t.Fatal(err)
	}
}

func TestProtectionDefaultsAndRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	box(t, s, "f1", "7", pt0)
	if _, ok, err := s.GetProtection(ctx, "7"); err != nil || ok {
		t.Fatalf("no row: ok=%v err=%v", ok, err)
	}
	want := Protection{RelayFilter: true, ShareBans: true, ShareBansAt: pt0}
	if err := s.SetProtection(ctx, "7", want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GetProtection(ctx, "7")
	if err != nil || !ok || !got.RelayFilter || !got.ShareBans || !got.ShareBansAt.Equal(pt0) {
		t.Fatalf("got %+v ok=%v err=%v", got, ok, err)
	}
	if err := s.ClaimName(ctx, "7", "mybox", pt0); err != nil {
		t.Fatal(err)
	}
	names, err := s.ProtectedNames(ctx)
	if err != nil || len(names) != 1 || !names["mybox"].RelayFilter {
		t.Fatalf("names = %+v, %v", names, err)
	}
}

func TestShareBansOffDeletesReports(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	box(t, s, "f1", "7", pt0)
	box(t, s, "f2", "8", pt0)
	for _, r := range []Report{
		{NodeID: "7", FleetID: "f1", Key: "1.1.1.1/32", Reason: "scan", App: "a", Since: pt0},
		{NodeID: "7", FleetID: "f1", Key: "2.2.2.2/32", Reason: "scan", App: "a", Since: pt0},
		{NodeID: "8", FleetID: "f2", Key: "1.1.1.1/32", Reason: "scan", App: "a", Since: pt0},
	} {
		if err := s.AddReport(ctx, r, pt0); err != nil {
			t.Fatal(err)
		}
	}
	dup := Report{NodeID: "8", FleetID: "f2", Key: "1.1.1.1/32", Reason: "scan", App: "a", Since: pt0}
	if err := s.AddReport(ctx, dup, pt0); err != nil {
		t.Fatalf("duplicate must be nil: %v", err)
	}
	if err := s.SetProtection(ctx, "7", Protection{ShareBans: false}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReportsSince(ctx, pt0.Add(-time.Hour))
	if err != nil || len(got) != 1 || got[0].NodeID != "8" {
		t.Fatalf("reports = %+v, %v", got, err)
	}
}

func TestSeen(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	if err := s.RecordSeen(ctx, pt0, []Seen{{"1.1.1.1/32", "7"}}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.SeenBetween(ctx, "1.1.1.1/32", "7", pt0.Add(-time.Minute), pt0.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("in window: %v %v", ok, err)
	}
	if ok, _ := s.SeenBetween(ctx, "1.1.1.1/32", "8", pt0.Add(-time.Minute), pt0.Add(time.Minute)); ok {
		t.Fatal("other node must not match")
	}
	if ok, _ := s.SeenBetween(ctx, "1.1.1.1/32", "7", pt0.Add(time.Minute), pt0.Add(time.Hour)); ok {
		t.Fatal("outside window must not match")
	}
}

func TestRefusalsAddUp(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	r := Refusal{Hour: pt0, Name: "mybox", Key: "1.1.1.1/32", Reason: "external", Source: "FireHOL", Count: 2}
	if err := s.AddRefusals(ctx, []Refusal{r}); err != nil {
		t.Fatal(err)
	}
	r.Count = 3
	if err := s.AddRefusals(ctx, []Refusal{r}); err != nil {
		t.Fatal(err)
	}
	got, err := s.RefusalsOf(ctx, "mybox", pt0.Add(-time.Hour), 10)
	if err != nil || len(got) != 1 || got[0].Count != 5 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got, err := s.RefusalsOf(ctx, "other", pt0.Add(-time.Hour), 10); err != nil || len(got) != 0 {
		t.Fatalf("other = %+v, %v", got, err)
	}
	tot, err := s.RefusalTotals(ctx, pt0.Add(-time.Hour))
	if err != nil || len(tot) != 1 || tot[0].Count != 5 || tot[0].Name != "" || tot[0].Key != "" {
		t.Fatalf("totals = %+v, %v", tot, err)
	}
}

func TestRefusalsSince(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	if err := s.AddRefusals(ctx, []Refusal{
		{Hour: pt0, Name: "a", Key: "k1", Reason: "cap", Source: "ip", Count: 2},
		{Hour: pt0.Add(time.Hour), Name: "a", Key: "k1", Reason: "cap", Source: "ip", Count: 3},
		{Hour: pt0.Add(-time.Hour), Name: "a", Key: "k1", Reason: "cap", Source: "ip", Count: 50},
		{Hour: pt0, Name: "", Key: "k2", Reason: "cap", Source: "ip", Count: 4},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := s.RefusalsSince(ctx, pt0)
	if err != nil || len(got) != 2 || got[0].Name != "" || got[0].Count != 4 || got[1].Name != "a" || got[1].Count != 5 || !got[1].Hour.IsZero() {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestStrikesSurviveEnd(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	end := pt0.Add(24 * time.Hour)
	if err := s.OpenBan(ctx, CommunityBan{Key: "1.1.1.1/32", Kind: "address", Strike: 1, Since: pt0, Until: end, Reasons: "scan", Fleets: 2}, []string{"f1", "f2"}); err != nil {
		t.Fatal(err)
	}
	if a, err := s.ActiveBans(ctx, pt0.Add(time.Hour)); err != nil || len(a) != 1 {
		t.Fatalf("active = %+v, %v", a, err)
	}
	if n, err := s.ContributedSince(ctx, "f1", pt0.Add(-time.Hour)); err != nil || n != 1 {
		t.Fatalf("contributed = %d, %v", n, err)
	}
	if err := s.EndExpired(ctx, pt0.Add(25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if a, err := s.ActiveBans(ctx, pt0.Add(25*time.Hour)); err != nil || len(a) != 0 {
		t.Fatalf("active after end = %+v, %v", a, err)
	}
	n, last, err := s.Strikes(ctx, "1.1.1.1/32")
	if err != nil || n != 1 || !last.Equal(end) {
		t.Fatalf("strikes = %d %v, %v", n, last, err)
	}
	// A permanent ban, lifted, ends now and keeps its strikes.
	if err := s.OpenBan(ctx, CommunityBan{Key: "2.2.2.2/32", Kind: "address", Strike: 3, Since: pt0}, []string{"f1"}); err != nil {
		t.Fatal(err)
	}
	if p, err := s.PermanentBans(ctx); err != nil || len(p) != 1 {
		t.Fatalf("permanent = %+v, %v", p, err)
	}
	if err := s.LiftBan(ctx, "2.2.2.2/32", pt0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, last, _ := s.Strikes(ctx, "2.2.2.2/32"); n != 3 || !last.Equal(pt0.Add(time.Hour)) {
		t.Fatalf("lifted strikes = %d %v", n, last)
	}
}

func TestFleetEligible(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	now := pt0
	cut := now.Add(-7 * 24 * time.Hour)
	box(t, s, "young", "1", now.Add(-6*24*time.Hour))
	box(t, s, "noname", "2", now.Add(-8*24*time.Hour))
	box(t, s, "ok", "3", now.Add(-8*24*time.Hour))
	for _, node := range []string{"1", "3"} {
		if err := s.ClaimName(ctx, node, "n"+node, now); err != nil {
			t.Fatal(err)
		}
	}
	for id, want := range map[string]bool{"young": false, "noname": false, "ok": true, "ghost": false} {
		if got, err := s.FleetEligible(ctx, id, cut); err != nil || got != want {
			t.Fatalf("%s: got %v err %v, want %v", id, got, err, want)
		}
	}
}

func TestPruneProtection(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	box(t, s, "f1", "7", pt0.Add(-60*24*time.Hour))
	now := pt0
	day := 24 * time.Hour
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.RecordSeen(ctx, now.Add(-25*time.Hour), []Seen{{"old", "7"}}))
	must(s.RecordSeen(ctx, now.Add(-time.Hour), []Seen{{"new", "7"}}))
	must(s.AddReport(ctx, Report{NodeID: "7", FleetID: "f1", Key: "old", Reason: "scan", App: "a", Since: now.Add(-31 * day)}, now.Add(-31*day)))
	must(s.AddReport(ctx, Report{NodeID: "7", FleetID: "f1", Key: "new", Reason: "scan", App: "a", Since: now.Add(-day)}, now.Add(-day)))
	must(s.AddRefusals(ctx, []Refusal{
		{Hour: now.Add(-8 * day), Name: "n", Key: "k", Reason: "cap", Source: "ip", Count: 1},
		{Hour: now.Add(-day), Name: "n", Key: "k", Reason: "cap", Source: "ip", Count: 1},
	}))
	// A strike ended 31 days ago, and a permanent ban with strikes.
	must(s.OpenBan(ctx, CommunityBan{Key: "ended", Kind: "address", Strike: 1, Since: now.Add(-32 * day), Until: now.Add(-31 * day)}, []string{"f1"}))
	must(s.EndExpired(ctx, now.Add(-30*day)))
	must(s.OpenBan(ctx, CommunityBan{Key: "perm", Kind: "address", Strike: 3, Since: now.Add(-40 * day)}, []string{"f1"}))
	must(s.PruneProtection(ctx, now))

	if ok, _ := s.SeenBetween(ctx, "old", "7", time.Time{}, now); ok {
		t.Error("old seen kept")
	}
	if ok, _ := s.SeenBetween(ctx, "new", "7", time.Time{}, now); !ok {
		t.Error("new seen lost")
	}
	if r, _ := s.ReportsSince(ctx, time.Time{}); len(r) != 1 || r[0].Key != "new" {
		t.Errorf("reports = %+v", r)
	}
	if r, _ := s.RefusalsOf(ctx, "n", time.Time{}, 10); len(r) != 1 {
		t.Errorf("refusals = %+v", r)
	}
	if n, _, _ := s.Strikes(ctx, "ended"); n != 0 {
		t.Errorf("ended strikes kept: %d", n)
	}
	if n, _, _ := s.Strikes(ctx, "perm"); n != 3 {
		t.Errorf("permanent strikes = %d", n)
	}
	if p, _ := s.PermanentBans(ctx); len(p) != 1 {
		t.Errorf("permanent ban lost: %+v", p)
	}
}

func TestDeleteBoxCascades(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	box(t, s, "f1", "7", pt0)
	if err := s.SetProtection(ctx, "7", Protection{RelayFilter: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBoxKey(ctx, "7"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetProtection(ctx, "7"); ok {
		t.Fatal("protection row survived the box")
	}
}

// A feed id is never given again: the fetcher's copy <id>.txt of a deleted feed must not serve a new one.
func TestFeedIDsNotReused(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	var ids []int64
	for _, n := range []string{"a", "b"} {
		id, err := s.AddFeed(ctx, Feed{Name: n, URL: "https://x", Format: "text", EverySec: 3600, MaxEntries: 10})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := s.DeleteFeed(ctx, ids[1]); err != nil {
		t.Fatal(err)
	}
	id, err := s.AddFeed(ctx, Feed{Name: "c", URL: "https://x", Format: "text", EverySec: 3600, MaxEntries: 10})
	if err != nil {
		t.Fatal(err)
	}
	if id <= ids[1] {
		t.Fatalf("new feed got id %d after deleting %d", id, ids[1])
	}
}

func TestListsAndFeeds(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	id, err := s.AddAllow(ctx, AllowEntry{Prefix: "192.0.2.0/24", Note: "office", Added: pt0})
	if err != nil {
		t.Fatal(err)
	}
	if l, _ := s.AllowList(ctx); len(l) != 1 || l[0].ID != id {
		t.Fatalf("allow = %+v", l)
	}
	if err := s.DeleteAllow(ctx, id); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.AllowList(ctx); len(l) != 0 {
		t.Fatal("allow not deleted")
	}
	if _, err := s.AddManual(ctx, ManualBan{Kind: "country", Value: "XX", Since: pt0, Until: pt0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddManual(ctx, ManualBan{Kind: "asn", Value: "64500", Since: pt0}); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.ManualBans(ctx, pt0.Add(2*time.Hour)); len(m) != 1 || m[0].Kind != "asn" {
		t.Fatalf("manual = %+v", m)
	}
	if err := s.SuspendName(ctx, "bad", pt0); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.SuspendedNames(ctx); len(n) != 1 || n[0] != "bad" {
		t.Fatalf("suspended = %v", n)
	}
	if err := s.ResumeName(ctx, "bad"); err != nil {
		t.Fatal(err)
	}
	fid, err := s.AddFeed(ctx, Feed{Name: "f", URL: "https://x", Format: "text", EverySec: 3600, MaxEntries: 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddFeed(ctx, Feed{Name: "f", URL: "https://y"}); err == nil {
		t.Fatal("duplicate feed name accepted")
	}
	if err := s.FeedResult(ctx, fid, pt0, 42, ""); err != nil {
		t.Fatal(err)
	}
	if err := s.FeedResult(ctx, fid, pt0.Add(time.Hour), 0, "boom"); err != nil {
		t.Fatal(err)
	}
	fs, err := s.Feeds(ctx)
	if err != nil || len(fs) != 1 || fs[0].Count != 42 || !fs[0].LastOK.Equal(pt0) || fs[0].LastError != "boom" || !fs[0].LastTry.Equal(pt0.Add(time.Hour)) {
		t.Fatalf("feeds = %+v, %v", fs, err)
	}
	fs[0].Enabled = true
	if err := s.UpdateFeed(ctx, fs[0]); err != nil {
		t.Fatal(err)
	}
	if fs, _ = s.Feeds(ctx); !fs[0].Enabled {
		t.Fatal("update lost")
	}
	if err := s.DeleteFeed(ctx, fid); err != nil {
		t.Fatal(err)
	}
}

func TestSeenKeepsNewest(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	rec := func(at time.Time) {
		t.Helper()
		if err := s.RecordSeen(ctx, at, []Seen{{"1.1.1.1/32", "7"}}); err != nil {
			t.Fatal(err)
		}
	}
	rec(pt0)
	rec(pt0.Add(-time.Hour)) // out of order: must not move the time back
	if ok, err := s.SeenBetween(ctx, "1.1.1.1/32", "7", pt0.Add(-30*time.Minute), pt0.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("newest lost: %v %v", ok, err)
	}
	rec(pt0.Add(2 * time.Hour))
	if ok, err := s.SeenBetween(ctx, "1.1.1.1/32", "7", pt0.Add(time.Hour), pt0.Add(3*time.Hour)); err != nil || !ok {
		t.Fatalf("later time not kept: %v %v", ok, err)
	}
}

// Expired operator bans are deleted, not only hidden; a permanent one and one still running stay.
func TestPruneDeletesExpiredManualBans(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	now := pt0
	for _, until := range []time.Time{now.Add(-time.Hour), now, now.Add(time.Hour), {}} {
		if _, err := s.AddManual(ctx, ManualBan{Kind: "address", Value: "198.51.100.1", Since: now.Add(-2 * time.Hour), Until: until}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PruneProtection(ctx, now); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := s.(*sqlStore).db.QueryRowContext(ctx, `SELECT COUNT(*) FROM share_manual`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("%d rows left (%v), want the running and the permanent ban", n, err)
	}
}

// ReportsSince reads share_reports by since: it has its index.
func TestReportsSinceIndexed(t *testing.T) {
	var n int
	if err := openTmp(t).(*sqlStore).db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = 'share_reports_since'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("index count %d (%v)", n, err)
	}
}
