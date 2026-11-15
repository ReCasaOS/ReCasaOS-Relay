package main

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/autoban"
	"github.com/ReCasaOS/recasaos-relay/internal/journal"
	"github.com/ReCasaOS/recasaos-relay/internal/journal/journaltest"
	"github.com/ReCasaOS/recasaos-relay/internal/protect"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

type abEnv struct {
	ab   *autoBan
	st   store.Store
	read func() []journal.Entry
	t0   time.Time
}

func newAutoBanEnv(t *testing.T) abEnv {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	jw, read := journaltest.New(t, "enrolment")
	t0 := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return t0 }
	return abEnv{st: st, read: read, t0: t0, ab: &autoBan{
		det:      autoban.New(autoban.Config{}, now),
		store:    st,
		compiler: &protect.Compiler{Store: st, Now: now},
		journal:  jw,
		now:      now,
	}}
}

func (e abEnv) bans(t *testing.T) []store.ManualBan {
	t.Helper()
	b, err := e.st.ManualBans(context.Background(), e.t0)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func trap(ip string) journal.Entry {
	return journal.Entry{IP: ip, Path: "/.env", Status: 404}
}

func TestAutoBanTrapBansAndJournals(t *testing.T) {
	e := newAutoBanEnv(t)
	e.ab.Front(trap("203.0.113.7"))
	b := e.bans(t)
	if len(b) != 1 || b[0].Value != "203.0.113.7" || b[0].Note != "auto · trap · /.env" {
		t.Fatalf("bans %+v", b)
	}
	j := e.read()
	if len(j) != 1 || j[0].Event != "ban_auto" || j[0].Src != "relay" || j[0].IP != "203.0.113.7/32" || j[0].Msg != "trap · /.env · 24 h" {
		t.Fatalf("journal %+v", j)
	}
}

func TestAutoBanSkipsAllowedAndPrivate(t *testing.T) {
	e := newAutoBanEnv(t)
	if _, err := e.st.AddAllow(context.Background(), store.AllowEntry{Prefix: "203.0.113.0/24", Added: e.t0}); err != nil {
		t.Fatal(err)
	}
	e.ab.Front(trap("203.0.113.7"))
	e.ab.Front(trap("192.168.1.5"))
	e.ab.Front(trap(""))
	if b := e.bans(t); len(b) != 0 {
		t.Fatalf("bans %+v", b)
	}
	if j := e.read(); len(j) != 0 {
		t.Fatalf("journal %+v", j)
	}
}

func TestAutoBanSecondTrapWritesNoSecondLine(t *testing.T) {
	e := newAutoBanEnv(t)
	e.ab.Front(trap("203.0.113.7"))
	e.ab.Front(trap("203.0.113.7"))
	if len(e.bans(t)) != 1 || len(e.read()) != 1 {
		t.Fatal("a second ban or journal line was written")
	}
}

func TestAutoBanBoxExemptsTrap(t *testing.T) {
	e := newAutoBanEnv(t)
	e.ab.Box("203.0.113.7")
	e.ab.Front(trap("203.0.113.7"))
	if len(e.bans(t)) != 0 {
		t.Fatal("a box address was banned")
	}
}

func TestAutoBanUnknownNames(t *testing.T) {
	ctx := context.Background()
	e := newAutoBanEnv(t)
	for i := 0; i < 10; i++ {
		e.ab.Unknown(ctx, "203.0.113.8", fmt.Sprintf("Guess%d", i))
	}
	b := e.bans(t)
	if len(b) != 1 || b[0].Value != "203.0.113.8" {
		t.Fatalf("bans %+v", b)
	}
	if j := e.read(); len(j) != 1 || j[0].Event != "ban_auto" {
		t.Fatalf("journal %+v", j)
	}
}

func TestAutoBanClaimedNamesAreNotGuesses(t *testing.T) {
	ctx := context.Background()
	e := newAutoBanEnv(t)
	var names []string
	for i := 0; i < 10; i++ {
		names = append(names, fmt.Sprintf("mine%d", i))
	}
	claimAll(t, e.st, names)
	for _, n := range names {
		e.ab.Unknown(ctx, "203.0.113.8", n)
	}
	if len(e.bans(t)) != 0 {
		t.Fatal("claimed names counted as guesses")
	}
}

// claimAll gives each name to its own box of one fleet.
func claimAll(t *testing.T, st store.Store, names []string) {
	t.Helper()
	ctx := context.Background()
	at := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	if err := st.CreateFleet(ctx, store.Fleet{ID: "f1", SecretHash: "h", HeadscaleUser: "u", CreatedAt: at, LastOnline: at}); err != nil {
		t.Fatal(err)
	}
	for i, n := range names {
		node := fmt.Sprintf("n%d", i)
		if err := st.SetBoxKey(ctx, "f1", node, "key"+node, at); err != nil {
			t.Fatal(err)
		}
		if err := st.ClaimName(ctx, node, n, at); err != nil {
			t.Fatal(err)
		}
	}
}
