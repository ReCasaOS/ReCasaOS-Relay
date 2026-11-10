package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func fleetFrom(id, origin, origin48 string, at time.Time) Fleet {
	f := fleet(id, at)
	f.Origin, f.Origin48 = origin, origin48
	return f
}

// A fleet keeps the network it was created from, so that the relay can count the fleets of one
// network: without that count, one network takes every place the relay has.
func TestCountFleetsFrom(t *testing.T) {
	ctx := context.Background()
	s := open(t, filepath.Join(t.TempDir(), "relay.db"))
	now := time.Now().UTC()
	for _, f := range []Fleet{
		fleetFrom("a", "2001:db8:1:1::/64", "2001:db8:1::/48", now),
		fleetFrom("b", "2001:db8:1:1::/64", "2001:db8:1::/48", now),
		fleetFrom("c", "2001:db8:1:2::/64", "2001:db8:1::/48", now),
		fleetFrom("d", "192.0.2.1", "192.0.2.1", now),
		fleet("made-before", now), // no origin: counts for no network
	} {
		if err := s.CreateFleet(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		origin, origin48 string
		here, wider      int
	}{
		{"2001:db8:1:1::/64", "2001:db8:1::/48", 2, 3},
		{"2001:db8:1:9::/64", "2001:db8:1::/48", 0, 3},
		{"192.0.2.1", "192.0.2.1", 1, 1},
		{"198.51.100.7", "198.51.100.7", 0, 0},
		{"", "", 0, 0},
	} {
		here, wider, err := s.CountFleetsFrom(ctx, c.origin, c.origin48)
		if err != nil || here != c.here || wider != c.wider {
			t.Errorf("CountFleetsFrom(%q, %q) = %d, %d, %v; want %d, %d", c.origin, c.origin48, here, wider, err, c.here, c.wider)
		}
	}

	if err := s.DeleteFleet(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if here, wider, err := s.CountFleetsFrom(ctx, "2001:db8:1:1::/64", "2001:db8:1::/48"); err != nil || here != 1 || wider != 2 {
		t.Errorf("after a deletion: %d, %d, %v; want 1, 2", here, wider, err)
	}
	if f, err := s.Fleet(ctx, "c"); err != nil || f.Origin != "2001:db8:1:2::/64" || f.Origin48 != "2001:db8:1::/48" {
		t.Errorf("the fleet read back: %+v, %v", f, err)
	}
}

// The database of a relay that ran before fleets had an origin opens as it is: its fleets stay,
// count for no network, and new ones are counted.
func TestOpenGivesAnOlderDatabaseTheOrigin(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "relay.db")
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	// every table of the schema, with the rows that point at a fleet, and fleets as it was
	if _, err := old.Exec(schema + `
		ALTER TABLE fleets DROP COLUMN origin;
		ALTER TABLE fleets DROP COLUMN origin48;
		INSERT INTO fleets VALUES ('old', 'hash-old', 'u-old', 1, 1);
		INSERT INTO keys VALUES ('old', 'key-1', 2);
		INSERT INTO devices VALUES ('node-1', 'old', 1);`); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	s := open(t, path)
	if f, err := s.Fleet(ctx, "old"); err != nil || f.HeadscaleUser != "u-old" || f.Origin != "" {
		t.Fatalf("the fleet of the older database: %+v, %v", f, err)
	}
	if devices, err := s.DeviceIDs(ctx, "old"); err != nil || !devices["node-1"] {
		t.Fatalf("the device of the older fleet: %v, %v", devices, err)
	}
	if err := s.CreateFleet(ctx, fleetFrom("new", "192.0.2.1", "192.0.2.1", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if here, _, err := s.CountFleetsFrom(ctx, "192.0.2.1", "192.0.2.1"); err != nil || here != 1 {
		t.Fatalf("CountFleetsFrom = %d, %v; want 1", here, err)
	}
	if n, err := s.CountFleets(ctx); err != nil || n != 2 {
		t.Fatalf("CountFleets = %d, %v; want 2", n, err)
	}

	// and it opens again: the column is added once
	s.Close()
	if again, err := Open(path); err != nil {
		t.Fatalf("second open: %v", err)
	} else {
		again.Close()
	}
}
