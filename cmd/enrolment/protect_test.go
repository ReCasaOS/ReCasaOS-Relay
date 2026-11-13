package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/journal"
	"github.com/ReCasaOS/recasaos-relay/internal/journal/journaltest"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// A tick that replaces a feed copy makes the next poll see it at once, not after maxAge.
func TestProtectionTickInvalidatesOnChange(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("198.51.100.9\n")) }))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := newProtection(st, path, true, 1000, time.Hour, nil)
	p.geo.BaseURL = "http://127.0.0.1:1/" // no DB-IP download in tests
	if _, err := st.AddFeed(ctx, store.Feed{Name: "L", URL: srv.URL, Format: "text", EverySec: 3600, MaxEntries: 10, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if body, _, _ := p.compiler.Current(ctx); strings.Contains(string(body), "198.51.100.9") {
		t.Fatal("feed in the snapshot before any download")
	}
	p.safeTick(ctx)
	if body, _, _ := p.compiler.Current(ctx); !strings.Contains(string(body), `"L":["198.51.100.9/32"]`) {
		t.Fatalf("downloaded feed missing: %s", body)
	}
	if got := p.feeds.Dir; got != filepath.Join(filepath.Dir(path), "feeds") {
		t.Fatalf("feeds dir %q", got)
	}
	if got := p.geo.Dir; got != filepath.Join(filepath.Dir(path), "geo") {
		t.Fatalf("geo dir %q", got)
	}
	if p.feeds.TotalMax != 1000 || p.engine.MinFleetAge != time.Hour {
		t.Fatalf("settings not passed: %d %v", p.feeds.TotalMax, p.engine.MinFleetAge)
	}
}

// With sharing off (or turned off later) nothing is filtered or downloaded, but the retention of
// what sharing left in relay.db still runs: accepted connections go after 24 h, ended bans end.
func TestRetentionRunsWithoutSharing(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := newProtection(st, path, false, 1000, time.Hour, nil)
	if p.feeds != nil || p.geo != nil || p.compiler != nil || p.engine != nil {
		t.Fatalf("protection built without sharing: %+v", p)
	}
	now := time.Now()
	const key = "203.0.113.7/32"
	if err := st.RecordSeen(ctx, now.Add(-25*time.Hour), []store.Seen{{Key: key, NodeID: "7"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.OpenBan(ctx, store.CommunityBan{Key: key, Kind: "address", Strike: 1, Since: now.Add(-2 * time.Hour), Until: now.Add(-time.Hour), Reasons: "scan", Fleets: 2}, nil); err != nil {
		t.Fatal(err)
	}
	p.safeTick(ctx)
	if seen, _ := st.SeenBetween(ctx, key, "7", now.Add(-48*time.Hour), now); seen {
		t.Fatal("accepted connection older than 24 h kept")
	}
	if _, lastEnd, _ := st.Strikes(ctx, key); lastEnd.IsZero() {
		t.Fatal("expired ban not ended")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "geo")); !os.IsNotExist(err) {
		t.Fatalf("geo dir touched without sharing: %v", err)
	}
}

func TestProtectionTickSurvivesPanic(t *testing.T) {
	(&protection{}).safeTick(context.Background()) // nil collaborators panic inside
}

func journalProtection(t *testing.T) (*protection, store.Store, func() []journal.Entry) {
	t.Helper()
	jw, read := journaltest.New(t, "enrolment")
	path := filepath.Join(t.TempDir(), "relay.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	p := newProtection(st, path, true, 1000, time.Hour, jw)
	p.geo.BaseURL = "http://127.0.0.1:1/"
	return p, st, read
}

func TestJournalBanOpen(t *testing.T) {
	ctx := context.Background()
	p, st, read := journalProtection(t)
	now := time.Now()
	for _, f := range []string{"fa", "fb"} {
		if err := st.CreateFleet(ctx, store.Fleet{ID: f, CreatedAt: now.Add(-30 * 24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := st.AddReport(ctx, store.Report{NodeID: "n" + f, FleetID: f, Key: "203.0.113.7/32", Reason: "scan", App: "x", Since: now}, now); err != nil {
			t.Fatal(err)
		}
	}
	p.safeTick(ctx)
	var found bool
	for _, e := range read() {
		if e.Event == "ban_open" {
			found = true
			if e.Src != "relay" || e.Svc != "enrolment" || e.IP != "203.0.113.7/32" || !strings.Contains(e.Msg, "2 fleets · 24 h") {
				t.Fatalf("%+v", e)
			}
		}
	}
	if !found {
		t.Fatal("no ban_open line")
	}
}

func TestJournalFeedFailHasNoKey(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer srv.Close()
	p, st, read := journalProtection(t)
	p.feeds.Client = srv.Client()
	if _, err := st.AddFeed(ctx, store.Feed{Name: "Keyed", URL: srv.URL + "/list?apikey=SECRETKEY", Format: "text", EverySec: 3600, MaxEntries: 10, Enabled: true,
		AuthName: "X-Key", AuthValue: "HEADERSECRET"}); err != nil {
		t.Fatal(err)
	}
	p.safeTick(ctx)
	var found bool
	for _, e := range read() {
		for _, s := range []string{"SECRETKEY", "HEADERSECRET", srv.URL} {
			if strings.Contains(e.Msg, s) {
				t.Fatalf("leak %q in %+v", s, e)
			}
		}
		if e.Event == "feed_fail" {
			found = true
			if !strings.Contains(e.Msg, "Keyed") {
				t.Fatalf("%+v", e)
			}
		}
	}
	if !found {
		t.Fatal("no feed_fail line")
	}
}
