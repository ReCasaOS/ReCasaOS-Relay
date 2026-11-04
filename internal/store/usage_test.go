package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openTmp(t *testing.T) Store { return open(t, filepath.Join(t.TempDir(), "relay.db")) }

func TestApplyUsageAddsToBuckets(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	at := time.Date(2026, 11, 4, 10, 5, 7, 0, time.UTC)
	for i := 0; i < 2; i++ {
		if err := s.ApplyUsage(ctx, at.Add(time.Duration(i)*10*time.Second), []UsageSample{{"f1", "n1", 10, 20}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	since := at.Add(-time.Hour)
	min, err := s.UsageSeries(ctx, PerMinute, since)
	if err != nil || len(min) != 1 || min[0].Rx != 20 || min[0].Tx != 40 || !min[0].At.Equal(at.Truncate(time.Minute)) {
		t.Fatalf("minute rows = %+v, %v", min, err)
	}
	if err := s.ApplyUsage(ctx, at.Add(time.Hour), []UsageSample{{"f1", "n1", 1, 2}}, nil); err != nil {
		t.Fatal(err)
	}
	hr, err := s.UsageSeries(ctx, PerHour, since)
	if err != nil || len(hr) != 2 || hr[0].Rx != 20 || hr[1].Rx != 1 || !hr[0].At.Equal(at.Truncate(time.Hour)) {
		t.Fatalf("hour rows = %+v, %v", hr, err)
	}
}

func TestApplyUsageReplacesCursors(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	at := time.Now()
	if err := s.ApplyUsage(ctx, at, nil, []Cursor{{"c1", 1, 2}, {"c2", 3, 4}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyUsage(ctx, at, nil, []Cursor{{"c2", 5, 6}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Cursors(ctx)
	if err != nil || len(got) != 1 || got["c2"] != (Cursor{"c2", 5, 6}) {
		t.Fatalf("cursors = %+v, %v", got, err)
	}
}

func TestApplyUsageIsAtomic(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	at := time.Now()
	if err := s.ApplyUsage(ctx, at, nil, []Cursor{{"c1", 1, 2}}); err != nil {
		t.Fatal(err)
	}
	err := s.ApplyUsage(ctx, at, []UsageSample{{"f1", "n1", 1, 1}, {"", "n1", 1, 1}}, []Cursor{{"c9", 9, 9}})
	if err == nil {
		t.Fatal("want constraint error")
	}
	got, _ := s.Cursors(ctx)
	if len(got) != 1 || got["c1"] != (Cursor{"c1", 1, 2}) {
		t.Fatalf("cursors changed: %+v", got)
	}
	if tot, _ := s.UsageTotals(ctx, time.Unix(0, 0)); len(tot) != 0 {
		t.Fatalf("usage leaked: %+v", tot)
	}
}

func TestUsageTotalsMonthBoundary(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	for _, at := range []time.Time{time.Date(2026, 11, 30, 23, 59, 0, 0, time.UTC), time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)} {
		if err := s.ApplyUsage(ctx, at, []UsageSample{{"f1", "n1", 5, 7}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	tot, err := s.UsageTotals(ctx, time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || len(tot) != 1 || tot[0] != (UsageTotal{"f1", "n1", 5, 7}) {
		t.Fatalf("totals = %+v, %v", tot, err)
	}
}

func TestDeletedFleetKeepsUsage(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	now := time.Now().UTC()
	if err := s.CreateFleet(ctx, fleet("f1", now)); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyUsage(ctx, now, []UsageSample{{"f1", "n1", 5, 7}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFleet(ctx, "f1"); err != nil {
		t.Fatal(err)
	}
	tot, err := s.UsageTotals(ctx, now.Add(-time.Hour))
	if err != nil || len(tot) != 1 || tot[0].Rx != 5 {
		t.Fatalf("totals = %+v, %v", tot, err)
	}
}

func TestPruneUsage(t *testing.T) {
	ctx := context.Background()
	s := openTmp(t)
	old := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cut := old.Add(48 * time.Hour)
	for _, at := range []time.Time{old, cut.Add(time.Minute)} {
		if err := s.ApplyUsage(ctx, at, []UsageSample{{"f1", "n1", 1, 1}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.PruneUsage(ctx, cut, cut); err != nil {
		t.Fatal(err)
	}
	for _, res := range []Resolution{PerMinute, PerHour} {
		pts, err := s.UsageSeries(ctx, res, old.Add(-time.Hour))
		if err != nil || len(pts) != 1 || !pts[0].At.Equal(cut.Add(time.Minute).Truncate(map[Resolution]time.Duration{PerMinute: time.Minute, PerHour: time.Hour}[res])) {
			t.Fatalf("res %d: %+v, %v", res, pts, err)
		}
	}
}
