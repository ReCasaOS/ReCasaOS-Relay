package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T, path string) Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func fleet(id string, online time.Time) Fleet {
	return Fleet{ID: id, SecretHash: "hash-" + id, HeadscaleUser: "u-" + id, CreatedAt: online, LastOnline: online}
}

func TestStateSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "relay.db")
	now := time.Now().UTC().Truncate(time.Second)

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFleet(ctx, fleet("f1", now)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordKey(ctx, "f1", "k1", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := open(t, path)
	got, err := s2.Fleet(ctx, "f1")
	if err != nil {
		t.Fatal(err)
	}
	if got.SecretHash != "hash-f1" || got.HeadscaleUser != "u-f1" || !got.CreatedAt.Equal(now) {
		t.Fatalf("fleet not preserved: %+v", got)
	}
}

func TestIdleFleets(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "relay.db"))
	now := time.Now().UTC()
	for id, age := range map[string]time.Duration{"old": 48 * time.Hour, "fresh": time.Hour, "touched": 72 * time.Hour} {
		if err := s.CreateFleet(ctx, fleet(id, now.Add(-age))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Touch(ctx, "touched", now); err != nil {
		t.Fatal(err)
	}
	ids, err := s.IdleFleets(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "old" {
		t.Fatalf("idle = %v, want [old]", ids)
	}
}

func TestNotFound(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "relay.db"))
	if _, err := s.Fleet(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Fleet: %v", err)
	}
	if err := s.Touch(ctx, "nope", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Touch: %v", err)
	}
	if err := s.RecordKey(ctx, "nope", "k", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RecordKey: %v", err)
	}
}

func TestDeleteTwiceIsNotAnError(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "relay.db"))
	if err := s.CreateFleet(ctx, fleet("f", time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordKey(ctx, "f", "k", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.DeleteFleet(ctx, "f"); err != nil {
			t.Fatalf("delete #%d: %v", i+1, err)
		}
	}
	if _, err := s.Fleet(ctx, "f"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("fleet still there: %v", err)
	}
	// keys are removed with the fleet: re-creating the fleet must not hit a stale key.
	if err := s.CreateFleet(ctx, fleet("f", time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordKey(ctx, "f", "k", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("stale key survived delete: %v", err)
	}
}

func TestCreateDuplicate(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "relay.db"))
	f := fleet("f", time.Now())
	if err := s.CreateFleet(ctx, f); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFleet(ctx, f); !errors.Is(err, ErrExists) {
		t.Fatalf("got %v, want ErrExists", err)
	}
}

func TestWALEnabled(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "relay.db")).(*sqlStore)
	var mode string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode = %q, %v", mode, err)
	}
}
