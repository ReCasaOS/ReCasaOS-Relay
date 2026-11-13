package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	p := newProtection(st, path, 1000, time.Hour)
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

func TestProtectionTickSurvivesPanic(t *testing.T) {
	(&protection{}).safeTick(context.Background()) // nil collaborators panic inside
}
