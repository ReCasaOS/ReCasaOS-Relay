// Package store persists fleets and their enrolment keys in a SQLite file.
// Only the SHA-256 hash of a fleet secret is ever stored.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // pure Go driver, no CGO
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrExists   = errors.New("store: already exists")
)

type Fleet struct {
	ID, SecretHash, HeadscaleUser string
	CreatedAt, LastOnline         time.Time
}

type Store interface {
	CreateFleet(ctx context.Context, f Fleet) error
	Fleet(ctx context.Context, id string) (Fleet, error)
	// DeleteFleet also removes the fleet's keys; deleting an unknown fleet is not an error.
	DeleteFleet(ctx context.Context, id string) error
	RecordKey(ctx context.Context, fleetID, keyID string, expires time.Time) error
	Touch(ctx context.Context, fleetID string, at time.Time) error
	// IdleFleets returns the IDs of fleets whose LastOnline is before the cut.
	IdleFleets(ctx context.Context, before time.Time) ([]string, error)
	// ListFleets returns every fleet ordered by id, without secret hashes (for building the access policy).
	ListFleets(ctx context.Context) ([]Fleet, error)
	CountFleets(ctx context.Context) (int, error)
	// ApplyUsage atomically adds samples to the minute and hour buckets of at (UTC),
	// then replaces the whole derper cursor table with cursors.
	ApplyUsage(ctx context.Context, at time.Time, samples []UsageSample, cursors []Cursor) error
	Cursors(ctx context.Context) (map[string]Cursor, error)
	// UsageTotals sums hour buckets >= since per fleet and node.
	UsageTotals(ctx context.Context, since time.Time) ([]UsageTotal, error)
	// UsageSeries returns buckets >= since, ordered by time.
	UsageSeries(ctx context.Context, res Resolution, since time.Time) ([]UsagePoint, error)
	PruneUsage(ctx context.Context, minutesBefore, hoursBefore time.Time) error
	Close() error
}

const schema = `
CREATE TABLE IF NOT EXISTS fleets (
	id TEXT PRIMARY KEY,
	secret_hash TEXT NOT NULL,
	headscale_user TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	last_online INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS keys (
	fleet_id TEXT NOT NULL REFERENCES fleets(id) ON DELETE CASCADE,
	key_id TEXT NOT NULL,
	expires INTEGER NOT NULL,
	PRIMARY KEY (fleet_id, key_id)
);
-- No foreign key to fleets: a deleted fleet's usage stays. Buckets are UTC unix seconds.
CREATE TABLE IF NOT EXISTS usage_minute (
	fleet_id TEXT NOT NULL, node_id TEXT NOT NULL, minute INTEGER NOT NULL,
	rx INTEGER NOT NULL, tx INTEGER NOT NULL,
	CHECK (fleet_id <> '' AND node_id <> ''),
	PRIMARY KEY (fleet_id, node_id, minute)
);
CREATE TABLE IF NOT EXISTS usage_hour (
	fleet_id TEXT NOT NULL, node_id TEXT NOT NULL, hour INTEGER NOT NULL,
	rx INTEGER NOT NULL, tx INTEGER NOT NULL,
	CHECK (fleet_id <> '' AND node_id <> ''),
	PRIMARY KEY (fleet_id, node_id, hour)
);
-- Time-range reads and pruning filter on the bucket alone, which the primary keys do not lead with.
CREATE INDEX IF NOT EXISTS usage_minute_minute ON usage_minute(minute);
CREATE INDEX IF NOT EXISTS usage_hour_hour ON usage_hour(hour);
CREATE TABLE IF NOT EXISTS derp_cursor (conn TEXT PRIMARY KEY, rx INTEGER NOT NULL, tx INTEGER NOT NULL);`

type sqlStore struct{ db *sql.DB }

// Open opens (creating if needed) the SQLite file at path in WAL mode and migrates the schema.
func Open(path string) (Store, error) {
	// Pragmas in the DSN apply to every connection the pool opens.
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1) // single writer; keeps SQLITE_BUSY out of the picture
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &sqlStore{db}, nil
}

func (s *sqlStore) Close() error { return s.db.Close() }

func ts(t time.Time) int64 { return t.UnixNano() }

func (s *sqlStore) CreateFleet(ctx context.Context, f Fleet) error {
	if f.LastOnline.IsZero() {
		f.LastOnline = f.CreatedAt
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO fleets (id, secret_hash, headscale_user, created_at, last_online)
		 VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`,
		f.ID, f.SecretHash, f.HeadscaleUser, ts(f.CreatedAt), ts(f.LastOnline))
	if err != nil {
		return fmt.Errorf("store: create fleet: %w", err)
	}
	return requireRow(res, ErrExists)
}

func (s *sqlStore) Fleet(ctx context.Context, id string) (Fleet, error) {
	var f Fleet
	var created, online int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, secret_hash, headscale_user, created_at, last_online FROM fleets WHERE id = ?`, id).
		Scan(&f.ID, &f.SecretHash, &f.HeadscaleUser, &created, &online)
	if errors.Is(err, sql.ErrNoRows) {
		return Fleet{}, ErrNotFound
	}
	if err != nil {
		return Fleet{}, fmt.Errorf("store: get fleet: %w", err)
	}
	f.CreatedAt, f.LastOnline = time.Unix(0, created).UTC(), time.Unix(0, online).UTC()
	return f, nil
}

func (s *sqlStore) DeleteFleet(ctx context.Context, id string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM fleets WHERE id = ?`, id); err != nil {
		return fmt.Errorf("store: delete fleet: %w", err)
	}
	return nil
}

func (s *sqlStore) RecordKey(ctx context.Context, fleetID, keyID string, expires time.Time) error {
	// INSERT..SELECT so an unknown fleet yields zero rows rather than a driver-specific FK error.
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO keys (fleet_id, key_id, expires)
		 SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM fleets WHERE id = ?)
		 ON CONFLICT(fleet_id, key_id) DO NOTHING`,
		fleetID, keyID, ts(expires), fleetID)
	if err != nil {
		return fmt.Errorf("store: record key: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: record key: %w", err)
	} else if n > 0 {
		return nil
	}
	// Zero rows: unknown fleet or duplicate key id.
	var fleetExists bool
	if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM fleets WHERE id = ?)`, fleetID).Scan(&fleetExists); err != nil {
		return fmt.Errorf("store: record key: %w", err)
	}
	if fleetExists {
		return ErrExists
	}
	return ErrNotFound
}

func (s *sqlStore) Touch(ctx context.Context, fleetID string, at time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE fleets SET last_online = ? WHERE id = ?`, ts(at), fleetID)
	if err != nil {
		return fmt.Errorf("store: touch: %w", err)
	}
	return requireRow(res, ErrNotFound)
}

func (s *sqlStore) IdleFleets(ctx context.Context, before time.Time) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM fleets WHERE last_online < ? ORDER BY id`, ts(before))
	if err != nil {
		return nil, fmt.Errorf("store: idle fleets: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: idle fleets: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func requireRow(res sql.Result, missing error) error {
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("store: %w", err)
	} else if n == 0 {
		return missing
	}
	return nil
}

func (s *sqlStore) ListFleets(ctx context.Context) ([]Fleet, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, headscale_user, created_at, last_online FROM fleets ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list fleets: %w", err)
	}
	defer rows.Close()
	var out []Fleet
	for rows.Next() {
		var f Fleet
		var created, online int64
		if err := rows.Scan(&f.ID, &f.HeadscaleUser, &created, &online); err != nil {
			return nil, fmt.Errorf("store: list fleets: %w", err)
		}
		f.CreatedAt, f.LastOnline = time.Unix(0, created).UTC(), time.Unix(0, online).UTC()
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *sqlStore) CountFleets(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM fleets`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count fleets: %w", err)
	}
	return n, nil
}

// Cursor is the last seen byte counters of one derper connection;
// Conn is "<key>|<connNum>|<connectedAt unix ns>".
type Cursor struct {
	Conn   string
	Rx, Tx int64
}

type UsageSample struct {
	FleetID, NodeID string
	Rx, Tx          int64
}

type UsagePoint struct {
	FleetID, NodeID string
	At              time.Time
	Rx, Tx          int64
}

type UsageTotal struct {
	FleetID, NodeID string
	Rx, Tx          int64
}

type Resolution int

const (
	PerMinute Resolution = iota
	PerHour
)

func (s *sqlStore) ApplyUsage(ctx context.Context, at time.Time, samples []UsageSample, cursors []Cursor) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: apply usage: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			err = fmt.Errorf("store: apply usage: %w", err)
		}
	}()
	at = at.UTC()
	for _, b := range []struct {
		table, col string
		t          time.Time
	}{{"usage_minute", "minute", at.Truncate(time.Minute)}, {"usage_hour", "hour", at.Truncate(time.Hour)}} {
		q := `INSERT INTO ` + b.table + ` (fleet_id, node_id, ` + b.col + `, rx, tx) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(fleet_id, node_id, ` + b.col + `) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx`
		for _, sm := range samples {
			if _, err = tx.ExecContext(ctx, q, sm.FleetID, sm.NodeID, b.t.Unix(), sm.Rx, sm.Tx); err != nil {
				return err
			}
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM derp_cursor`); err != nil {
		return err
	}
	for _, c := range cursors {
		if _, err = tx.ExecContext(ctx, `INSERT INTO derp_cursor (conn, rx, tx) VALUES (?, ?, ?)`, c.Conn, c.Rx, c.Tx); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *sqlStore) Cursors(ctx context.Context) (map[string]Cursor, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT conn, rx, tx FROM derp_cursor`)
	if err != nil {
		return nil, fmt.Errorf("store: cursors: %w", err)
	}
	defer rows.Close()
	out := map[string]Cursor{}
	for rows.Next() {
		var c Cursor
		if err := rows.Scan(&c.Conn, &c.Rx, &c.Tx); err != nil {
			return nil, fmt.Errorf("store: cursors: %w", err)
		}
		out[c.Conn] = c
	}
	return out, rows.Err()
}

func (s *sqlStore) UsageTotals(ctx context.Context, since time.Time) ([]UsageTotal, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT fleet_id, node_id, SUM(rx), SUM(tx) FROM usage_hour WHERE hour >= ? GROUP BY fleet_id, node_id ORDER BY fleet_id, node_id`,
		since.UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("store: usage totals: %w", err)
	}
	defer rows.Close()
	var out []UsageTotal
	for rows.Next() {
		var u UsageTotal
		if err := rows.Scan(&u.FleetID, &u.NodeID, &u.Rx, &u.Tx); err != nil {
			return nil, fmt.Errorf("store: usage totals: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *sqlStore) UsageSeries(ctx context.Context, res Resolution, since time.Time) ([]UsagePoint, error) {
	table, col := "usage_minute", "minute"
	if res == PerHour {
		table, col = "usage_hour", "hour"
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT fleet_id, node_id, `+col+`, rx, tx FROM `+table+` WHERE `+col+` >= ? ORDER BY `+col+`, fleet_id, node_id`,
		since.UTC().Unix())
	if err != nil {
		return nil, fmt.Errorf("store: usage series: %w", err)
	}
	defer rows.Close()
	var out []UsagePoint
	for rows.Next() {
		var p UsagePoint
		var at int64
		if err := rows.Scan(&p.FleetID, &p.NodeID, &at, &p.Rx, &p.Tx); err != nil {
			return nil, fmt.Errorf("store: usage series: %w", err)
		}
		p.At = time.Unix(at, 0).UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *sqlStore) PruneUsage(ctx context.Context, minutesBefore, hoursBefore time.Time) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM usage_minute WHERE minute < ?`, minutesBefore.UTC().Unix()); err != nil {
		return fmt.Errorf("store: prune usage: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM usage_hour WHERE hour < ?`, hoursBefore.UTC().Unix()); err != nil {
		return fmt.Errorf("store: prune usage: %w", err)
	}
	return nil
}
