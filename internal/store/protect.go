package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// protectSchema is run after schema by Open. until/last_end/share_bans_at are UnixNano, 0 = none.
const protectSchema = `
CREATE TABLE IF NOT EXISTS share_protection (
	node_id TEXT PRIMARY KEY REFERENCES box_keys(node_id) ON DELETE CASCADE,
	relay_filter INTEGER NOT NULL, share_bans INTEGER NOT NULL, share_bans_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS share_seen (
	key TEXT NOT NULL, node_id TEXT NOT NULL, at INTEGER NOT NULL,
	PRIMARY KEY (key, node_id)
);
CREATE TABLE IF NOT EXISTS share_reports (
	node_id TEXT NOT NULL, fleet_id TEXT NOT NULL, key TEXT NOT NULL, reason TEXT NOT NULL, app TEXT NOT NULL,
	since INTEGER NOT NULL, received INTEGER NOT NULL,
	PRIMARY KEY (node_id, key, since)
);
CREATE TABLE IF NOT EXISTS share_refusals (
	hour INTEGER NOT NULL, name TEXT NOT NULL, key TEXT NOT NULL, reason TEXT NOT NULL, source TEXT NOT NULL,
	count INTEGER NOT NULL,
	PRIMARY KEY (hour, name, key, reason, source)
);
CREATE TABLE IF NOT EXISTS community_bans (
	key TEXT PRIMARY KEY, kind TEXT NOT NULL, strike INTEGER NOT NULL, since INTEGER NOT NULL,
	until INTEGER NOT NULL, reasons TEXT NOT NULL, fleets INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS community_strikes (key TEXT PRIMARY KEY, strikes INTEGER NOT NULL, last_end INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS community_openers (
	key TEXT NOT NULL, since INTEGER NOT NULL, fleet_id TEXT NOT NULL,
	PRIMARY KEY (key, since, fleet_id)
);
CREATE TABLE IF NOT EXISTS share_allow (id INTEGER PRIMARY KEY, prefix TEXT NOT NULL, note TEXT NOT NULL, added INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS share_manual (
	id INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL, note TEXT NOT NULL,
	since INTEGER NOT NULL, until INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS share_suspended (name TEXT PRIMARY KEY, added INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS share_feeds (
	id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, url TEXT NOT NULL, auth_name TEXT NOT NULL, auth_value TEXT NOT NULL,
	format TEXT NOT NULL, "column" INTEGER NOT NULL, every_s INTEGER NOT NULL, max_entries INTEGER NOT NULL,
	enabled INTEGER NOT NULL, note TEXT NOT NULL, preset TEXT NOT NULL,
	last_try INTEGER NOT NULL, last_ok INTEGER NOT NULL, last_error TEXT NOT NULL, count INTEGER NOT NULL
);`

type Protection struct {
	RelayFilter, ShareBans bool
	ShareBansAt            time.Time
}

type Seen struct{ Key, NodeID string }

type Report struct {
	NodeID, FleetID, Key, Reason, App string
	Since                             time.Time
}

type Refusal struct {
	Hour                      time.Time
	Name, Key, Reason, Source string
	Count                     int64
}

type CommunityBan struct {
	Key, Kind    string
	Strike       int
	Since, Until time.Time // Until zero = permanent
	Reasons      string
	Fleets       int
}

type AllowEntry struct {
	ID           int64
	Prefix, Note string
	Added        time.Time
}

// ManualBan.Kind is one of address range asn country; Until zero = permanent.
type ManualBan struct {
	ID                int64
	Kind, Value, Note string
	Since, Until      time.Time
}

type Feed struct {
	ID                                     int64
	Name, URL, AuthName, AuthValue, Format string
	Column, EverySec, MaxEntries           int
	Enabled                                bool
	Note, Preset                           string
	LastTry, LastOK                        time.Time
	LastError                              string
	Count                                  int
}

// tz stores a zero time as 0 (none) and anything else as UnixNano; fromTs is its inverse.
func tz(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return ts(t)
}

func fromTs(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// exec runs one statement, wrapping its error with what.
func (s *sqlStore) exec(ctx context.Context, what, q string, args ...any) error {
	if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("store: %s: %w", what, err)
	}
	return nil
}

// insertID runs an INSERT and returns the new row id; a UNIQUE violation is ErrExists.
func (s *sqlStore) insertID(ctx context.Context, what, q string, args ...any) (int64, error) {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrExists
		}
		return 0, fmt.Errorf("store: %s: %w", what, err)
	}
	return res.LastInsertId()
}

func (s *sqlStore) GetProtection(ctx context.Context, nodeID string) (Protection, bool, error) {
	var p Protection
	var rf, sb, at int64
	err := s.db.QueryRowContext(ctx, `SELECT relay_filter, share_bans, share_bans_at FROM share_protection WHERE node_id = ?`, nodeID).Scan(&rf, &sb, &at)
	if err == sql.ErrNoRows {
		return p, false, nil
	}
	if err != nil {
		return p, false, fmt.Errorf("store: get protection: %w", err)
	}
	return Protection{rf != 0, sb != 0, fromTs(at)}, true, nil
}

func (s *sqlStore) SetProtection(ctx context.Context, nodeID string, p Protection) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: set protection: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO share_protection (node_id, relay_filter, share_bans, share_bans_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(node_id) DO UPDATE SET relay_filter = excluded.relay_filter, share_bans = excluded.share_bans, share_bans_at = excluded.share_bans_at`,
		nodeID, b2i(p.RelayFilter), b2i(p.ShareBans), tz(p.ShareBansAt)); err != nil {
		return fmt.Errorf("store: set protection: %w", err)
	}
	if !p.ShareBans {
		if _, err = tx.ExecContext(ctx, `DELETE FROM share_reports WHERE node_id = ?`, nodeID); err != nil {
			return fmt.Errorf("store: set protection: %w", err)
		}
	}
	return tx.Commit()
}

func (s *sqlStore) ProtectedNames(ctx context.Context) (map[string]Protection, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT n.name, p.relay_filter, p.share_bans, p.share_bans_at FROM share_names n JOIN share_protection p ON p.node_id = n.node_id`)
	if err != nil {
		return nil, fmt.Errorf("store: protected names: %w", err)
	}
	defer rows.Close()
	out := map[string]Protection{}
	for rows.Next() {
		var name string
		var rf, sb, at int64
		if err := rows.Scan(&name, &rf, &sb, &at); err != nil {
			return nil, fmt.Errorf("store: protected names: %w", err)
		}
		out[name] = Protection{rf != 0, sb != 0, fromTs(at)}
	}
	return out, rows.Err()
}

// batch runs q once per item in one transaction.
func batch[T any](ctx context.Context, s *sqlStore, what, q string, items []T, args func(T) []any) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: %s: %w", what, err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	for _, it := range items {
		if _, err = tx.ExecContext(ctx, q, args(it)...); err != nil {
			return fmt.Errorf("store: %s: %w", what, err)
		}
	}
	return tx.Commit()
}

// RecordSeen keeps one row per (key, node): the latest accepted time.
func (s *sqlStore) RecordSeen(ctx context.Context, at time.Time, seen []Seen) error {
	return batch(ctx, s, "record seen",
		`INSERT INTO share_seen (key, node_id, at) VALUES (?, ?, ?) ON CONFLICT(key, node_id) DO UPDATE SET at = MAX(at, excluded.at)`,
		seen, func(v Seen) []any { return []any{v.Key, v.NodeID, ts(at)} })
}

func (s *sqlStore) SeenBetween(ctx context.Context, key, nodeID string, from, to time.Time) (bool, error) {
	var ok bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM share_seen WHERE key = ? AND node_id = ? AND at >= ? AND at <= ?)`,
		key, nodeID, tz(from), ts(to)).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("store: seen between: %w", err)
	}
	return ok, nil
}

func (s *sqlStore) AddReport(ctx context.Context, r Report, at time.Time) error {
	return s.exec(ctx, "add report",
		`INSERT OR IGNORE INTO share_reports (node_id, fleet_id, key, reason, app, since, received) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.NodeID, r.FleetID, r.Key, r.Reason, r.App, ts(r.Since), ts(at))
}

// ReportsSince returns the reports whose since is at or after t.
func (s *sqlStore) ReportsSince(ctx context.Context, t time.Time) ([]Report, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT node_id, fleet_id, key, reason, app, since FROM share_reports WHERE since >= ? ORDER BY since, node_id, key`, tz(t))
	if err != nil {
		return nil, fmt.Errorf("store: reports: %w", err)
	}
	defer rows.Close()
	var out []Report
	for rows.Next() {
		var r Report
		var since int64
		if err := rows.Scan(&r.NodeID, &r.FleetID, &r.Key, &r.Reason, &r.App, &since); err != nil {
			return nil, fmt.Errorf("store: reports: %w", err)
		}
		r.Since = fromTs(since)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *sqlStore) AddRefusals(ctx context.Context, rs []Refusal) error {
	return batch(ctx, s, "add refusals",
		`INSERT INTO share_refusals (hour, name, key, reason, source, count) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(hour, name, key, reason, source) DO UPDATE SET count = count + excluded.count`,
		rs, func(r Refusal) []any { return []any{ts(r.Hour), r.Name, r.Key, r.Reason, r.Source, r.Count} })
}

func (s *sqlStore) scanRefusals(rows *sql.Rows, err error) ([]Refusal, error) {
	if err != nil {
		return nil, fmt.Errorf("store: refusals: %w", err)
	}
	defer rows.Close()
	var out []Refusal
	for rows.Next() {
		var r Refusal
		var hour int64
		if err := rows.Scan(&hour, &r.Name, &r.Key, &r.Reason, &r.Source, &r.Count); err != nil {
			return nil, fmt.Errorf("store: refusals: %w", err)
		}
		r.Hour = fromTs(hour)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *sqlStore) RefusalsOf(ctx context.Context, name string, since time.Time, limit int) ([]Refusal, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT hour, name, key, reason, source, count FROM share_refusals WHERE name = ? AND hour >= ? ORDER BY hour DESC, key, reason, source LIMIT ?`,
		name, tz(since), limit)
	return s.scanRefusals(rows, err)
}

func (s *sqlStore) RefusalTotals(ctx context.Context, since time.Time) ([]Refusal, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT hour, '', '', reason, source, SUM(count) FROM share_refusals WHERE hour >= ? GROUP BY hour, reason, source ORDER BY hour DESC, reason, source`, tz(since))
	return s.scanRefusals(rows, err)
}

func (s *sqlStore) bans(ctx context.Context, where string, args ...any) ([]CommunityBan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, kind, strike, since, until, reasons, fleets FROM community_bans WHERE `+where+` ORDER BY key`, args...)
	if err != nil {
		return nil, fmt.Errorf("store: community bans: %w", err)
	}
	defer rows.Close()
	var out []CommunityBan
	for rows.Next() {
		var b CommunityBan
		var since, until int64
		if err := rows.Scan(&b.Key, &b.Kind, &b.Strike, &since, &until, &b.Reasons, &b.Fleets); err != nil {
			return nil, fmt.Errorf("store: community bans: %w", err)
		}
		b.Since, b.Until = fromTs(since), fromTs(until)
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *sqlStore) ActiveBans(ctx context.Context, now time.Time) ([]CommunityBan, error) {
	return s.bans(ctx, `until = 0 OR until > ?`, ts(now))
}

func (s *sqlStore) PermanentBans(ctx context.Context) ([]CommunityBan, error) {
	return s.bans(ctx, `until = 0`)
}

func (s *sqlStore) Strikes(ctx context.Context, key string) (int, time.Time, error) {
	var n int
	var last int64
	err := s.db.QueryRowContext(ctx, `SELECT strikes, last_end FROM community_strikes WHERE key = ?`, key).Scan(&n, &last)
	if err != nil && err != sql.ErrNoRows {
		return 0, time.Time{}, fmt.Errorf("store: strikes: %w", err)
	}
	return n, fromTs(last), nil
}

// OpenBan opens (or replaces) the ban on b.Key, records its strike (last_end 0 while it runs)
// and the fleets whose reports opened it.
func (s *sqlStore) OpenBan(ctx context.Context, b CommunityBan, openers []string) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: open ban: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	stmts := []struct {
		q    string
		args []any
	}{
		{`INSERT OR REPLACE INTO community_bans (key, kind, strike, since, until, reasons, fleets) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			[]any{b.Key, b.Kind, b.Strike, ts(b.Since), tz(b.Until), b.Reasons, b.Fleets}},
		{`INSERT OR REPLACE INTO community_strikes (key, strikes, last_end) VALUES (?, ?, 0)`, []any{b.Key, b.Strike}},
	}
	for _, f := range openers {
		stmts = append(stmts, struct {
			q    string
			args []any
		}{`INSERT OR IGNORE INTO community_openers (key, since, fleet_id) VALUES (?, ?, ?)`, []any{b.Key, ts(b.Since), f}})
	}
	for _, st := range stmts {
		if _, err = tx.ExecContext(ctx, st.q, st.args...); err != nil {
			return fmt.Errorf("store: open ban: %w", err)
		}
	}
	return tx.Commit()
}

// endBans moves the end of the bans matching where into community_strikes and deletes them.
func (s *sqlStore) endBans(ctx context.Context, what, where string, args ...any) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: %s: %w", what, err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()
	// A ban lifted early ends now, not at its scheduled until: the caller binds it as the first arg.
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO community_strikes (key, strikes, last_end) SELECT key, strike, CASE WHEN until = 0 OR until > ?1 THEN ?1 ELSE until END FROM community_bans WHERE `+where+`
		 ON CONFLICT(key) DO UPDATE SET last_end = excluded.last_end`, args...); err != nil {
		return fmt.Errorf("store: %s: %w", what, err)
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM community_bans WHERE `+where, args...); err != nil {
		return fmt.Errorf("store: %s: %w", what, err)
	}
	return tx.Commit()
}

func (s *sqlStore) LiftBan(ctx context.Context, key string, now time.Time) error {
	return s.endBans(ctx, "lift ban", `key = ?2`, ts(now), key)
}

func (s *sqlStore) EndExpired(ctx context.Context, now time.Time) error {
	return s.endBans(ctx, "end expired", `until <> 0 AND until <= ?1`, ts(now))
}

// ContributedSince counts the bans opened at or after t by reports of fleetID.
func (s *sqlStore) ContributedSince(ctx context.Context, fleetID string, t time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM community_openers WHERE fleet_id = ? AND since >= ?`, fleetID, tz(t)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: contributed: %w", err)
	}
	return n, nil
}

func (s *sqlStore) AddAllow(ctx context.Context, e AllowEntry) (int64, error) {
	return s.insertID(ctx, "add allow", `INSERT INTO share_allow (prefix, note, added) VALUES (?, ?, ?)`, e.Prefix, e.Note, ts(e.Added))
}

func (s *sqlStore) DeleteAllow(ctx context.Context, id int64) error {
	return s.exec(ctx, "delete allow", `DELETE FROM share_allow WHERE id = ?`, id)
}

func (s *sqlStore) AllowList(ctx context.Context) ([]AllowEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, prefix, note, added FROM share_allow ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: allow list: %w", err)
	}
	defer rows.Close()
	var out []AllowEntry
	for rows.Next() {
		var e AllowEntry
		var added int64
		if err := rows.Scan(&e.ID, &e.Prefix, &e.Note, &added); err != nil {
			return nil, fmt.Errorf("store: allow list: %w", err)
		}
		e.Added = fromTs(added)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *sqlStore) AddManual(ctx context.Context, m ManualBan) (int64, error) {
	return s.insertID(ctx, "add manual", `INSERT INTO share_manual (kind, value, note, since, until) VALUES (?, ?, ?, ?, ?)`,
		m.Kind, m.Value, m.Note, ts(m.Since), tz(m.Until))
}

func (s *sqlStore) DeleteManual(ctx context.Context, id int64) error {
	return s.exec(ctx, "delete manual", `DELETE FROM share_manual WHERE id = ?`, id)
}

// ManualBans returns the bans in force at now.
func (s *sqlStore) ManualBans(ctx context.Context, now time.Time) ([]ManualBan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, kind, value, note, since, until FROM share_manual WHERE until = 0 OR until > ? ORDER BY id`, ts(now))
	if err != nil {
		return nil, fmt.Errorf("store: manual bans: %w", err)
	}
	defer rows.Close()
	var out []ManualBan
	for rows.Next() {
		var m ManualBan
		var since, until int64
		if err := rows.Scan(&m.ID, &m.Kind, &m.Value, &m.Note, &since, &until); err != nil {
			return nil, fmt.Errorf("store: manual bans: %w", err)
		}
		m.Since, m.Until = fromTs(since), fromTs(until)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *sqlStore) SuspendName(ctx context.Context, name string, at time.Time) error {
	return s.exec(ctx, "suspend name", `INSERT OR IGNORE INTO share_suspended (name, added) VALUES (?, ?)`, name, ts(at))
}

func (s *sqlStore) ResumeName(ctx context.Context, name string) error {
	return s.exec(ctx, "resume name", `DELETE FROM share_suspended WHERE name = ?`, name)
}

func (s *sqlStore) SuspendedNames(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM share_suspended ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store: suspended names: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("store: suspended names: %w", err)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *sqlStore) AddFeed(ctx context.Context, f Feed) (int64, error) {
	return s.insertID(ctx, "add feed",
		`INSERT INTO share_feeds (name, url, auth_name, auth_value, format, "column", every_s, max_entries, enabled, note, preset, last_try, last_ok, last_error, count)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, '', 0)`,
		f.Name, f.URL, f.AuthName, f.AuthValue, f.Format, f.Column, f.EverySec, f.MaxEntries, b2i(f.Enabled), f.Note, f.Preset)
}

// UpdateFeed rewrites the settings of feed f.ID; the fetch state (last_*, count) is left alone.
func (s *sqlStore) UpdateFeed(ctx context.Context, f Feed) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE share_feeds SET name = ?, url = ?, auth_name = ?, auth_value = ?, format = ?, "column" = ?, every_s = ?, max_entries = ?, enabled = ?, note = ?, preset = ? WHERE id = ?`,
		f.Name, f.URL, f.AuthName, f.AuthValue, f.Format, f.Column, f.EverySec, f.MaxEntries, b2i(f.Enabled), f.Note, f.Preset, f.ID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return ErrExists
		}
		return fmt.Errorf("store: update feed: %w", err)
	}
	return requireRow(res, ErrNotFound)
}

func (s *sqlStore) DeleteFeed(ctx context.Context, id int64) error {
	return s.exec(ctx, "delete feed", `DELETE FROM share_feeds WHERE id = ?`, id)
}

func (s *sqlStore) Feeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, url, auth_name, auth_value, format, "column", every_s, max_entries, enabled, note, preset, last_try, last_ok, last_error, count FROM share_feeds ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: feeds: %w", err)
	}
	defer rows.Close()
	var out []Feed
	for rows.Next() {
		var f Feed
		var en, try, ok int64
		if err := rows.Scan(&f.ID, &f.Name, &f.URL, &f.AuthName, &f.AuthValue, &f.Format, &f.Column, &f.EverySec, &f.MaxEntries, &en, &f.Note, &f.Preset, &try, &ok, &f.LastError, &f.Count); err != nil {
			return nil, fmt.Errorf("store: feeds: %w", err)
		}
		f.Enabled, f.LastTry, f.LastOK = en != 0, fromTs(try), fromTs(ok)
		out = append(out, f)
	}
	return out, rows.Err()
}

// FeedResult records a fetch attempt at at: errText "" is a success (last_ok, count, error cleared).
func (s *sqlStore) FeedResult(ctx context.Context, id int64, at time.Time, count int, errText string) error {
	if errText == "" {
		return s.exec(ctx, "feed result", `UPDATE share_feeds SET last_try = ?1, last_ok = ?1, count = ?2, last_error = '' WHERE id = ?3`, ts(at), count, id)
	}
	return s.exec(ctx, "feed result", `UPDATE share_feeds SET last_try = ?, last_error = ? WHERE id = ?`, ts(at), errText, id)
}

// FleetEligible: the fleet was created at or before createdBefore and holds at least one share name.
func (s *sqlStore) FleetEligible(ctx context.Context, fleetID string, createdBefore time.Time) (bool, error) {
	var ok bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM fleets f WHERE f.id = ? AND f.created_at <= ? AND EXISTS (SELECT 1 FROM share_names n WHERE n.fleet_id = f.id))`,
		fleetID, ts(createdBefore)).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("store: fleet eligible: %w", err)
	}
	return ok, nil
}

// PruneProtection applies the retention of the contract: accepted connections 24 h, reports 30
// days, refusal counters 7 days, strikes 30 days after their ban ended (a ban in force keeps
// its strikes: last_end 0), openers 32 days (enough for "contributed this month").
func (s *sqlStore) PruneProtection(ctx context.Context, now time.Time) error {
	day := 24 * time.Hour
	for _, q := range []struct {
		sql string
		cut time.Time
	}{
		{`DELETE FROM share_seen WHERE at < ?`, now.Add(-day)},
		{`DELETE FROM share_reports WHERE received < ?`, now.Add(-30 * day)},
		{`DELETE FROM share_refusals WHERE hour < ?`, now.Add(-7 * day)},
		{`DELETE FROM community_strikes WHERE last_end <> 0 AND last_end < ?`, now.Add(-30 * day)},
		{`DELETE FROM community_openers WHERE since < ?`, now.Add(-32 * day)},
	} {
		if err := s.exec(ctx, "prune protection", q.sql, ts(q.cut)); err != nil {
			return err
		}
	}
	return nil
}
