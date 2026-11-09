package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)

// shareBox creates a fleet with one box key.
func shareBox(t *testing.T, s Store, fleetID, nodeID, key string) {
	t.Helper()
	ctx := context.Background()
	if err := s.CreateFleet(ctx, fleet(fleetID, t0)); err != nil && !errors.Is(err, ErrExists) {
		t.Fatal(err)
	}
	if err := s.SetBoxKey(ctx, fleetID, nodeID, key, t0); err != nil {
		t.Fatal(err)
	}
}

func TestBoxKeyIsUniquePerNode(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	shareBox(t, s, "f1", "n1", "k1")
	if err := s.SetBoxKey(ctx, "f1", "n1", "k1b", t0); err != nil { // upsert by node
		t.Fatal(err)
	}
	if err := s.SetBoxKey(ctx, "f1", "n2", "k1b", t0); !errors.Is(err, ErrExists) {
		t.Fatalf("key on two nodes = %v, want ErrExists", err)
	}
	if _, err := s.BoxByKey(ctx, "k1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replaced key = %v, want ErrNotFound", err)
	}
	if err := s.ClaimName(ctx, "n1", "alice", t0); err != nil {
		t.Fatal(err)
	}
	ref, err := s.BoxByKey(ctx, "k1b")
	if err != nil || ref != (BoxRef{"f1", "n1", "alice"}) {
		t.Fatalf("BoxByKey = %+v, %v", ref, err)
	}
	keys, err := s.BoxKeysOf(ctx, "f1")
	if err != nil || len(keys) != 1 || keys["n1"] != "k1b" {
		t.Fatalf("BoxKeysOf = %v, %v", keys, err)
	}
	if err := s.DeleteBoxKey(ctx, "n1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.BoxByKey(ctx, "k1b"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted key = %v", err)
	}
	if names, _ := s.ListNames(ctx); len(names) != 0 {
		t.Fatalf("name survived its box: %+v", names)
	}
}

func TestClaimNameRefusesTakenBannedAndQuarantined(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	shareBox(t, s, "f1", "n1", "k1")
	shareBox(t, s, "f1", "n2", "k2")
	if err := s.ClaimName(ctx, "n1", "alice", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimName(ctx, "n1", "alice", t0); err != nil { // same node again: no-op
		t.Fatalf("re-claim = %v", err)
	}
	if err := s.ClaimName(ctx, "n2", "alice", t0); !errors.Is(err, ErrExists) {
		t.Fatalf("taken = %v, want ErrExists", err)
	}
	if err := s.ClaimName(ctx, "n1", "alice2", t0); !errors.Is(err, ErrExists) {
		t.Fatalf("second name = %v, want ErrExists", err)
	}
	if err := s.BanName(ctx, "evil", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimName(ctx, "n2", "evil", t0); !errors.Is(err, ErrBanned) {
		t.Fatalf("banned = %v, want ErrBanned", err)
	}
	if err := s.ReleaseName(ctx, "n1", t0.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimName(ctx, "n2", "alice", t0); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("quarantined = %v, want ErrQuarantined", err)
	}
	if err := s.ClaimName(ctx, "nope", "bob", t0); err == nil {
		t.Fatal("unknown node claimed a name")
	}
}

func TestReleaseThenClaimAfterQuarantine(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	shareBox(t, s, "f1", "n1", "k1")
	shareBox(t, s, "f1", "n2", "k2")
	until := t0.Add(24 * time.Hour)
	if err := s.ClaimName(ctx, "n1", "alice", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseName(ctx, "n1", until); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimName(ctx, "n2", "alice", until.Add(-time.Second)); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("before until = %v", err)
	}
	if err := s.ClaimName(ctx, "n2", "alice", until.Add(time.Second)); err != nil {
		t.Fatalf("after until = %v", err)
	}
	names, err := s.ListNames(ctx)
	if err != nil || len(names) != 1 || names[0].Name != "alice" || names[0].NodeID != "n2" ||
		names[0].FleetID != "f1" || !names[0].ClaimedAt.Equal(until.Add(time.Second)) {
		t.Fatalf("ListNames = %+v, %v", names, err)
	}
}

func TestDeletedFleetQuarantinesItsNames(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	shareBox(t, s, "f1", "n1", "k1")
	shareBox(t, s, "f2", "n2", "k2")
	if err := s.ClaimName(ctx, "n1", "alice", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFleet(ctx, "f1"); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimName(ctx, "n2", "alice", time.Now()); !errors.Is(err, ErrQuarantined) {
		t.Fatalf("after fleet delete = %v, want ErrQuarantined", err)
	}
}

func TestBanReleasesTheHolder(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	shareBox(t, s, "f1", "n1", "k1")
	if err := s.ClaimName(ctx, "n1", "alice", t0); err != nil {
		t.Fatal(err)
	}
	if err := s.BanName(ctx, "alice", t0); err != nil {
		t.Fatal(err)
	}
	if ref, _ := s.BoxByKey(ctx, "k1"); ref.Name != "" {
		t.Fatalf("holder keeps %q", ref.Name)
	}
	if b, err := s.BannedNames(ctx); err != nil || len(b) != 1 || b[0] != "alice" {
		t.Fatalf("BannedNames = %v, %v", b, err)
	}
	if err := s.UnbanName(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.BannedNames(ctx); len(b) != 0 {
		t.Fatalf("still banned: %v", b)
	}
}

func TestACMEValueExpires(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	exp := t0.Add(time.Minute)
	if err := s.SetACME(ctx, "alice", "v1", exp); err != nil {
		t.Fatal(err)
	}
	if err := s.SetACME(ctx, "alice", "v2", exp); err != nil { // replaces
		t.Fatal(err)
	}
	if v, ok, err := s.ACMEValue(ctx, "alice", t0); err != nil || !ok || v != "v2" {
		t.Fatalf("live = %q %v %v", v, ok, err)
	}
	if _, ok, err := s.ACMEValue(ctx, "alice", exp.Add(time.Second)); err != nil || ok {
		t.Fatalf("expired = %v %v", ok, err)
	}
	if err := s.DeleteACME(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.ACMEValue(ctx, "alice", t0); ok {
		t.Fatal("deleted value still served")
	}
}

func TestShareUsageIsSeparateFromDerp(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	if err := s.ApplyUsage(ctx, t0, []UsageSample{{"f1", "n1", 1, 2}}, []Cursor{{"c1", 1, 2}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.ApplyShareUsage(ctx, t0.Add(time.Duration(i)*10*time.Second), []UsageSample{{"f1", "n1", 10, 20}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ApplyShareUsage(ctx, t0.Add(time.Hour), []UsageSample{{"f1", "n1", 5, 6}}); err != nil {
		t.Fatal(err)
	}
	since := t0.Add(-time.Hour)
	if cur, _ := s.Cursors(ctx); len(cur) != 1 || cur["c1"] != (Cursor{"c1", 1, 2}) {
		t.Fatalf("cursors touched: %+v", cur)
	}
	if tot, _ := s.UsageTotals(ctx, since); len(tot) != 1 || tot[0].Rx != 1 || tot[0].Tx != 2 {
		t.Fatalf("derp totals touched: %+v", tot)
	}
	tot, err := s.ShareTotals(ctx, since)
	if err != nil || len(tot) != 1 || tot[0].Rx != 25 || tot[0].Tx != 46 {
		t.Fatalf("share totals = %+v, %v", tot, err)
	}
	min, err := s.ShareSeries(ctx, PerMinute, since)
	if err != nil || len(min) != 2 || min[0].Rx != 20 || min[1].Rx != 5 {
		t.Fatalf("share minutes = %+v, %v", min, err)
	}
	if hr, _ := s.ShareSeries(ctx, PerHour, since); len(hr) != 2 {
		t.Fatalf("share hours = %+v", hr)
	}
	if err := s.PruneUsage(ctx, t0.Add(24*time.Hour), t0.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if tot, _ := s.ShareTotals(ctx, since); len(tot) != 0 {
		t.Fatalf("share not pruned: %+v", tot)
	}
}
