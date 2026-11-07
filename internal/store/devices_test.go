package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestDeviceCodeSingleUse(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "r.db"))
	now := time.Now().UTC()
	if err := s.CreateFleet(ctx, fleet("f1", now)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDeviceCode(ctx, "f1", "h1", now.Add(time.Hour), now, 5); err != nil {
		t.Fatal(err)
	}
	if got, err := s.TakeDeviceCode(ctx, "h1", now); err != nil || got != "f1" {
		t.Fatalf("take = %q, %v", got, err)
	}
	if _, err := s.TakeDeviceCode(ctx, "h1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second take = %v, want ErrNotFound", err)
	}
}

func TestDeviceCodeExpires(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "r.db"))
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	s.CreateFleet(ctx, fleet("f1", now))
	if err := s.CreateDeviceCode(ctx, "f1", "h1", exp, now, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeDeviceCode(ctx, "h1", exp); !errors.Is(err, ErrNotFound) {
		t.Fatalf("take at expiry = %v, want ErrNotFound", err)
	}
	// the expired row was deleted: even an earlier clock no longer finds it
	if _, err := s.TakeDeviceCode(ctx, "h1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("take after expired take = %v, want ErrNotFound", err)
	}
}

func TestDeviceCodePendingLimit(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "r.db"))
	now := time.Now().UTC()
	exp := now.Add(time.Hour)
	s.CreateFleet(ctx, fleet("f1", now))
	for i := 0; i < 5; i++ {
		if err := s.CreateDeviceCode(ctx, "f1", string(rune('a'+i)), exp, now, 5); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	if err := s.CreateDeviceCode(ctx, "f1", "x", exp, now, 5); !errors.Is(err, ErrTooManyCodes) {
		t.Fatalf("6th = %v, want ErrTooManyCodes", err)
	}
	if err := s.CreateDeviceCode(ctx, "f1", "x", exp.Add(time.Hour), exp, 5); err != nil {
		t.Fatalf("6th after expiry: %v", err)
	}
}

func TestDeviceCodeSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "r.db")
	now := time.Now().UTC()
	s := open(t, path)
	s.CreateFleet(ctx, fleet("f1", now))
	if err := s.CreateDeviceCode(ctx, "f1", "h1", now.Add(time.Hour), now, 5); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = open(t, path)
	if got, err := s.TakeDeviceCode(ctx, "h1", now); err != nil || got != "f1" {
		t.Fatalf("take = %q, %v", got, err)
	}
}

func TestDevicesCascade(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "r.db"))
	now := time.Now().UTC()
	s.CreateFleet(ctx, fleet("f1", now))
	if err := s.AddDevice(ctx, "f1", "n1", now); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateDeviceCode(ctx, "f1", "h1", now.Add(time.Hour), now, 5); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFleet(ctx, "f1"); err != nil {
		t.Fatal(err)
	}
	if ids, err := s.DeviceIDs(ctx, "f1"); err != nil || len(ids) != 0 {
		t.Fatalf("devices = %v, %v", ids, err)
	}
	if _, err := s.TakeDeviceCode(ctx, "h1", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("take = %v, want ErrNotFound", err)
	}
}

func TestAllDevices(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "r.db"))
	now := time.Now().UTC()
	s.CreateFleet(ctx, fleet("f1", now))
	s.CreateFleet(ctx, fleet("f2", now))
	s.AddDevice(ctx, "f1", "n1", now)
	s.AddDevice(ctx, "f2", "n2", now)
	s.AddDevice(ctx, "f2", "n2", now) // upsert, no error
	all, err := s.AllDevices(ctx)
	if err != nil || len(all) != 2 || all["n1"] != "f1" || all["n2"] != "f2" {
		t.Fatalf("all = %v, %v", all, err)
	}
	if ids, _ := s.DeviceIDs(ctx, "f2"); len(ids) != 1 || !ids["n2"] {
		t.Fatalf("f2 ids = %v", ids)
	}
	if err := s.DeleteDevice(ctx, "n1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDevice(ctx, "nope"); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.AllDevices(ctx); len(all) != 1 || all["n2"] != "f2" {
		t.Fatalf("after delete = %v", all)
	}
}
