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

	ErrTooManyCodes = errors.New("store: too many unused device codes")
	ErrBanned       = errors.New("store: name banned")
	ErrQuarantined  = errors.New("store: name quarantined")
)

// Quarantine is how long a released name stays unclaimable by other boxes: Let's Encrypt reuses
// a DNS-01 authorization for up to 30 days, so this outlasts a 90-day certificate issued on it.
// The share_names_quarantine trigger hard-codes the same value (10800000 s).
const Quarantine = 125 * 24 * time.Hour

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
	// CreateDeviceCode prunes the fleet's expired codes, then stores codeHash unless
	// maxPending unexpired codes already exist (ErrTooManyCodes).
	CreateDeviceCode(ctx context.Context, fleetID, codeHash string, expires, now time.Time, maxPending int) error
	// TakeDeviceCode consumes a code and returns its fleet; missing or expired is ErrNotFound.
	TakeDeviceCode(ctx context.Context, codeHash string, now time.Time) (fleetID string, err error)
	// AddDevice upserts a device (node id) into a fleet.
	AddDevice(ctx context.Context, fleetID, nodeID string, at time.Time) error
	DeviceIDs(ctx context.Context, fleetID string) (map[string]bool, error)
	// AllDevices maps node id to fleet id.
	AllDevices(ctx context.Context) (map[string]string, error)
	// DeleteDevice removes a device; an unknown id is not an error.
	DeleteDevice(ctx context.Context, nodeID string) error

	// SetBoxKey links key to a node once: the same key again is a no-op; ErrExists when the node
	// already has another key or key belongs to another node.
	SetBoxKey(ctx context.Context, fleetID, nodeID, key string, at time.Time) error
	DeleteBoxKey(ctx context.Context, nodeID string) error
	// BoxKeysOf maps node id to box key.
	BoxKeysOf(ctx context.Context, fleetID string) (map[string]string, error)
	// BoxByKey returns the box owning key (Name is empty when it has none); unknown key is ErrNotFound.
	BoxByKey(ctx context.Context, key string) (BoxRef, error)
	// ClaimName gives name to nodeID: ErrBanned, ErrQuarantined (until > at), ErrExists (held by
	// another node, or nodeID already holds a different name). Claiming one's own name is a no-op.
	ClaimName(ctx context.Context, nodeID, name string, at time.Time) error
	// ReleaseName frees the node's name and quarantines it until quarantineUntil; no name is not an error.
	ReleaseName(ctx context.Context, nodeID string, quarantineUntil time.Time) error
	ListNames(ctx context.Context) ([]NameRow, error)
	// BanName bans name and releases it from its holder.
	BanName(ctx context.Context, name string, at time.Time) error
	UnbanName(ctx context.Context, name string) error
	BannedNames(ctx context.Context) ([]string, error)
	SetACME(ctx context.Context, name, value string, expires time.Time) error
	// ACMEValue returns the TXT value unless it expired at or before now.
	ACMEValue(ctx context.Context, name string, now time.Time) (string, bool, error)
	DeleteACME(ctx context.Context, name string) error
	// ApplyShareUsage adds samples to the shared-traffic buckets only (no derper cursors).
	ApplyShareUsage(ctx context.Context, at time.Time, samples []UsageSample) error
	ShareTotals(ctx context.Context, since time.Time) ([]UsageTotal, error)
	ShareSeries(ctx context.Context, res Resolution, since time.Time) ([]UsagePoint, error)
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
CREATE TABLE IF NOT EXISTS device_codes (
	code_hash TEXT PRIMARY KEY,
	fleet_id TEXT NOT NULL REFERENCES fleets(id) ON DELETE CASCADE,
	expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS devices (
	node_id TEXT PRIMARY KEY,
	fleet_id TEXT NOT NULL REFERENCES fleets(id) ON DELETE CASCADE,
	added INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS derp_cursor (conn TEXT PRIMARY KEY, rx INTEGER NOT NULL, tx INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS box_keys (
	node_id TEXT PRIMARY KEY,
	fleet_id TEXT NOT NULL REFERENCES fleets(id) ON DELETE CASCADE,
	box_key TEXT NOT NULL UNIQUE,
	added INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS share_names (
	name TEXT PRIMARY KEY,
	node_id TEXT NOT NULL UNIQUE REFERENCES box_keys(node_id) ON DELETE CASCADE,
	fleet_id TEXT NOT NULL,
	claimed_at INTEGER NOT NULL
);
-- node_id: the releasing box, which may take its name back during the quarantine. The table and
-- trigger were changed in place, not migrated: no deployed database has the share tables yet.
CREATE TABLE IF NOT EXISTS share_quarantine (name TEXT PRIMARY KEY, until INTEGER NOT NULL, node_id TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS share_banned (name TEXT PRIMARY KEY, added INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS acme_txt (name TEXT PRIMARY KEY, value TEXT NOT NULL, expires INTEGER NOT NULL);
-- Any removal of a name (release, fleet or box deletion by cascade) quarantines it for 125 days (store.Quarantine).
CREATE TRIGGER IF NOT EXISTS share_names_quarantine BEFORE DELETE ON share_names
BEGIN
	INSERT OR REPLACE INTO share_quarantine (name, until, node_id) VALUES (OLD.name, (strftime('%s','now') + 10800000) * 1000000000, OLD.node_id);
END;
CREATE TABLE IF NOT EXISTS share_minute (
	fleet_id TEXT NOT NULL, node_id TEXT NOT NULL, minute INTEGER NOT NULL,
	rx INTEGER NOT NULL, tx INTEGER NOT NULL,
	CHECK (fleet_id <> '' AND node_id <> ''),
	PRIMARY KEY (fleet_id, node_id, minute)
);
CREATE TABLE IF NOT EXISTS share_hour (
	fleet_id TEXT NOT NULL, node_id TEXT NOT NULL, hour INTEGER NOT NULL,
	rx INTEGER NOT NULL, tx INTEGER NOT NULL,
	CHECK (fleet_id <> '' AND node_id <> ''),
	PRIMARY KEY (fleet_id, node_id, hour)
);
CREATE INDEX IF NOT EXISTS share_minute_minute ON share_minute(minute);
CREATE INDEX IF NOT EXISTS share_hour_hour ON share_hour(hour);`

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
	if err = addBuckets(ctx, tx, "usage_minute", "usage_hour", at, samples); err != nil {
		return err
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

// addBuckets adds samples to the minute and hour buckets of at (UTC) in the given table pair.
func addBuckets(ctx context.Context, tx *sql.Tx, minuteTable, hourTable string, at time.Time, samples []UsageSample) error {
	at = at.UTC()
	for _, b := range []struct {
		table, col string
		t          time.Time
	}{{minuteTable, "minute", at.Truncate(time.Minute)}, {hourTable, "hour", at.Truncate(time.Hour)}} {
		q := `INSERT INTO ` + b.table + ` (fleet_id, node_id, ` + b.col + `, rx, tx) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(fleet_id, node_id, ` + b.col + `) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx`
		for _, sm := range samples {
			if _, err := tx.ExecContext(ctx, q, sm.FleetID, sm.NodeID, b.t.Unix(), sm.Rx, sm.Tx); err != nil {
				return err
			}
		}
	}
	return nil
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
	return s.totals(ctx, "usage_hour", since)
}

func (s *sqlStore) ShareTotals(ctx context.Context, since time.Time) ([]UsageTotal, error) {
	return s.totals(ctx, "share_hour", since)
}

func (s *sqlStore) totals(ctx context.Context, table string, since time.Time) ([]UsageTotal, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT fleet_id, node_id, SUM(rx), SUM(tx) FROM `+table+` WHERE hour >= ? GROUP BY fleet_id, node_id ORDER BY fleet_id, node_id`,
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
	return s.series(ctx, "usage_minute", "usage_hour", res, since)
}

func (s *sqlStore) ShareSeries(ctx context.Context, res Resolution, since time.Time) ([]UsagePoint, error) {
	return s.series(ctx, "share_minute", "share_hour", res, since)
}

func (s *sqlStore) series(ctx context.Context, minuteTable, hourTable string, res Resolution, since time.Time) ([]UsagePoint, error) {
	table, col := minuteTable, "minute"
	if res == PerHour {
		table, col = hourTable, "hour"
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
	for _, q := range []struct {
		table, col string
		before     time.Time
	}{{"usage_minute", "minute", minutesBefore}, {"share_minute", "minute", minutesBefore},
		{"usage_hour", "hour", hoursBefore}, {"share_hour", "hour", hoursBefore}} {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM `+q.table+` WHERE `+q.col+` < ?`, q.before.UTC().Unix()); err != nil {
			return fmt.Errorf("store: prune usage: %w", err)
		}
	}
	return nil
}

func (s *sqlStore) CreateDeviceCode(ctx context.Context, fleetID, codeHash string, expires, now time.Time, maxPending int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: create device code: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM device_codes WHERE fleet_id = ? AND expires <= ?`, fleetID, ts(now)); err != nil {
		return fmt.Errorf("store: create device code: %w", err)
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM device_codes WHERE fleet_id = ?`, fleetID).Scan(&n); err != nil {
		return fmt.Errorf("store: create device code: %w", err)
	}
	if n >= maxPending {
		return ErrTooManyCodes
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO device_codes (code_hash, fleet_id, expires) VALUES (?, ?, ?)`,
		codeHash, fleetID, ts(expires)); err != nil {
		return fmt.Errorf("store: create device code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: create device code: %w", err)
	}
	return nil
}

func (s *sqlStore) TakeDeviceCode(ctx context.Context, codeHash string, now time.Time) (string, error) {
	var fleetID string
	var expires int64
	err := s.db.QueryRowContext(ctx, `DELETE FROM device_codes WHERE code_hash = ? RETURNING fleet_id, expires`, codeHash).Scan(&fleetID, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("store: take device code: %w", err)
	}
	if expires <= ts(now) {
		return "", ErrNotFound
	}
	return fleetID, nil
}

func (s *sqlStore) AddDevice(ctx context.Context, fleetID, nodeID string, at time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO devices (node_id, fleet_id, added) VALUES (?, ?, ?)
		 ON CONFLICT(node_id) DO UPDATE SET fleet_id = excluded.fleet_id, added = excluded.added`,
		nodeID, fleetID, ts(at))
	if err != nil {
		return fmt.Errorf("store: add device: %w", err)
	}
	return nil
}

func (s *sqlStore) DeviceIDs(ctx context.Context, fleetID string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id FROM devices WHERE fleet_id = ?`, fleetID)
	if err != nil {
		return nil, fmt.Errorf("store: device ids: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: device ids: %w", err)
		}
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: device ids: %w", err)
	}
	return out, nil
}

func (s *sqlStore) AllDevices(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, fleet_id FROM devices`)
	if err != nil {
		return nil, fmt.Errorf("store: all devices: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var node, fleet string
		if err := rows.Scan(&node, &fleet); err != nil {
			return nil, fmt.Errorf("store: all devices: %w", err)
		}
		out[node] = fleet
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: all devices: %w", err)
	}
	return out, nil
}

func (s *sqlStore) DeleteDevice(ctx context.Context, nodeID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM devices WHERE node_id = ?`, nodeID); err != nil {
		return fmt.Errorf("store: delete device: %w", err)
	}
	return nil
}

type BoxRef struct{ FleetID, NodeID, Name string }

type NameRow struct {
	Name, FleetID, NodeID string
	ClaimedAt             time.Time
}

func (s *sqlStore) SetBoxKey(ctx context.Context, fleetID, nodeID, key string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: set box key: %w", err)
	}
	defer tx.Rollback()
	// Linked once: a different key on a keyed node would let a fleet-secret holder take over the
	// node's name. Rotation goes through node removal, which quarantines the name.
	var taken bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM box_keys WHERE (box_key = ?) <> (node_id = ?))`, key, nodeID).Scan(&taken); err != nil {
		return fmt.Errorf("store: set box key: %w", err)
	}
	if taken {
		return ErrExists
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO box_keys (node_id, fleet_id, box_key, added) VALUES (?, ?, ?, ?) ON CONFLICT(node_id) DO NOTHING`,
		nodeID, fleetID, key, ts(at)); err != nil {
		return fmt.Errorf("store: set box key: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: set box key: %w", err)
	}
	return nil
}

func (s *sqlStore) DeleteBoxKey(ctx context.Context, nodeID string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM box_keys WHERE node_id = ?`, nodeID); err != nil {
		return fmt.Errorf("store: delete box key: %w", err)
	}
	return nil
}

func (s *sqlStore) BoxKeysOf(ctx context.Context, fleetID string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, box_key FROM box_keys WHERE fleet_id = ?`, fleetID)
	if err != nil {
		return nil, fmt.Errorf("store: box keys: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var node, key string
		if err := rows.Scan(&node, &key); err != nil {
			return nil, fmt.Errorf("store: box keys: %w", err)
		}
		out[node] = key
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: box keys: %w", err)
	}
	return out, nil
}

func (s *sqlStore) BoxByKey(ctx context.Context, key string) (BoxRef, error) {
	var r BoxRef
	err := s.db.QueryRowContext(ctx,
		`SELECT b.fleet_id, b.node_id, COALESCE(n.name, '') FROM box_keys b LEFT JOIN share_names n ON n.node_id = b.node_id WHERE b.box_key = ?`, key).
		Scan(&r.FleetID, &r.NodeID, &r.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return BoxRef{}, ErrNotFound
	}
	if err != nil {
		return BoxRef{}, fmt.Errorf("store: box by key: %w", err)
	}
	return r, nil
}

func (s *sqlStore) ClaimName(ctx context.Context, nodeID, name string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: claim name: %w", err)
	}
	defer tx.Rollback()
	var fleetID string
	if err := tx.QueryRowContext(ctx, `SELECT fleet_id FROM box_keys WHERE node_id = ?`, nodeID).Scan(&fleetID); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return fmt.Errorf("store: claim name: %w", err)
	}
	var own string
	switch err := tx.QueryRowContext(ctx, `SELECT name FROM share_names WHERE node_id = ?`, nodeID).Scan(&own); {
	case err == nil && own == name:
		return nil
	case err == nil:
		return ErrExists
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("store: claim name: %w", err)
	}
	var banned, held bool
	var until int64
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM share_banned WHERE name = ?)`, name).Scan(&banned); err != nil {
		return fmt.Errorf("store: claim name: %w", err)
	}
	if banned {
		return ErrBanned
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(until), 0) FROM share_quarantine WHERE name = ? AND node_id <> ?`, name, nodeID).Scan(&until); err != nil {
		return fmt.Errorf("store: claim name: %w", err)
	}
	if until > ts(at) {
		return ErrQuarantined
	}
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM share_names WHERE name = ?)`, name).Scan(&held); err != nil {
		return fmt.Errorf("store: claim name: %w", err)
	}
	if held {
		return ErrExists
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO share_names (name, node_id, fleet_id, claimed_at) VALUES (?, ?, ?, ?)`,
		name, nodeID, fleetID, ts(at)); err != nil {
		return fmt.Errorf("store: claim name: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: claim name: %w", err)
	}
	return nil
}

func (s *sqlStore) ReleaseName(ctx context.Context, nodeID string, quarantineUntil time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: release name: %w", err)
	}
	defer tx.Rollback()
	var name string
	// The delete trigger quarantines for Quarantine; the caller's date then overrides it.
	switch err := tx.QueryRowContext(ctx, `DELETE FROM share_names WHERE node_id = ? RETURNING name`, nodeID).Scan(&name); {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("store: release name: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO share_quarantine (name, until, node_id) VALUES (?, ?, ?)`, name, ts(quarantineUntil), nodeID); err != nil {
		return fmt.Errorf("store: release name: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: release name: %w", err)
	}
	return nil
}

func (s *sqlStore) ListNames(ctx context.Context) ([]NameRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, fleet_id, node_id, claimed_at FROM share_names ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: list names: %w", err)
	}
	defer rows.Close()
	var out []NameRow
	for rows.Next() {
		var n NameRow
		var at int64
		if err := rows.Scan(&n.Name, &n.FleetID, &n.NodeID, &at); err != nil {
			return nil, fmt.Errorf("store: list names: %w", err)
		}
		n.ClaimedAt = time.Unix(0, at).UTC()
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *sqlStore) BanName(ctx context.Context, name string, at time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: ban name: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO share_banned (name, added) VALUES (?, ?)`, name, ts(at)); err != nil {
		return fmt.Errorf("store: ban name: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM share_names WHERE name = ?`, name); err != nil {
		return fmt.Errorf("store: ban name: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: ban name: %w", err)
	}
	return nil
}

func (s *sqlStore) UnbanName(ctx context.Context, name string) error {
	// An unban is the operator undoing a revoke: lift the quarantine the revoke started too.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: unban name: %w", err)
	}
	defer tx.Rollback()
	for _, q := range []string{`DELETE FROM share_banned WHERE name = ?`, `DELETE FROM share_quarantine WHERE name = ?`} {
		if _, err := tx.ExecContext(ctx, q, name); err != nil {
			return fmt.Errorf("store: unban name: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: unban name: %w", err)
	}
	return nil
}

func (s *sqlStore) BannedNames(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM share_banned ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: banned names: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("store: banned names: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *sqlStore) SetACME(ctx context.Context, name, value string, expires time.Time) error {
	if _, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO acme_txt (name, value, expires) VALUES (?, ?, ?)`, name, value, ts(expires)); err != nil {
		return fmt.Errorf("store: set acme: %w", err)
	}
	return nil
}

func (s *sqlStore) ACMEValue(ctx context.Context, name string, now time.Time) (string, bool, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM acme_txt WHERE name = ? AND expires > ?`, name, ts(now)).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: acme value: %w", err)
	}
	return v, true, nil
}

func (s *sqlStore) DeleteACME(ctx context.Context, name string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM acme_txt WHERE name = ?`, name); err != nil {
		return fmt.Errorf("store: delete acme: %w", err)
	}
	return nil
}

func (s *sqlStore) ApplyShareUsage(ctx context.Context, at time.Time, samples []UsageSample) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: apply share usage: %w", err)
	}
	defer tx.Rollback()
	if err := addBuckets(ctx, tx, "share_minute", "share_hour", at, samples); err != nil {
		return fmt.Errorf("store: apply share usage: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: apply share usage: %w", err)
	}
	return nil
}
