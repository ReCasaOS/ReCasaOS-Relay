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
);`

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
	// INSERT..SELECT so an unknown fleet yields zero rows (-> ErrNotFound) rather than a driver-specific FK error.
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO keys (fleet_id, key_id, expires)
		 SELECT ?, ?, ? WHERE EXISTS (SELECT 1 FROM fleets WHERE id = ?)
		 ON CONFLICT(fleet_id, key_id) DO UPDATE SET expires = excluded.expires`,
		fleetID, keyID, ts(expires), fleetID)
	if err != nil {
		return fmt.Errorf("store: record key: %w", err)
	}
	return requireRow(res, ErrNotFound)
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
