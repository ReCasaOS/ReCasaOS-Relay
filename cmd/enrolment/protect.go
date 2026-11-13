package main

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/community"
	"github.com/ReCasaOS/recasaos-relay/internal/feeds"
	"github.com/ReCasaOS/recasaos-relay/internal/geo"
	"github.com/ReCasaOS/recasaos-relay/internal/protect"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// protection is the relay-side filter: feed copies, DB-IP, the community list and the snapshot
// `share` polls. One instance serves the HTTP handlers, /admin and the loop.
type protection struct {
	store    store.Store
	feeds    *feeds.Fetcher
	geo      *geo.DB
	compiler *protect.Compiler
	engine   *community.Engine
}

// newProtection keeps its files next to the store: <data>/feeds/ and <data>/geo/. Without sharing
// it holds the store only: nothing is filtered or downloaded, but the loop still applies the
// retention to what sharing left in relay.db (sharing may have been turned off).
func newProtection(st store.Store, storePath string, sharing bool, maxEntries int, minFleetAge time.Duration) *protection {
	if !sharing {
		return &protection{store: st}
	}
	data := filepath.Dir(storePath)
	g := &geo.DB{Dir: filepath.Join(data, "geo")}
	f := &feeds.Fetcher{Store: st, Dir: filepath.Join(data, "feeds"), TotalMax: maxEntries}
	c := &protect.Compiler{Store: st, Feeds: f, Geo: g}
	e := &community.Engine{Store: st, Allowed: c.Allowed, MinFleetAge: minFleetAge}
	return &protection{store: st, feeds: f, geo: g, compiler: c, engine: e}
}

// run ticks at once (to open the DB-IP files, with sharing), then every `every` until ctx is done; it returns
// only once the tick in flight has, so the store is never closed under it.
func (p *protection) run(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for ctx.Err() == nil {
		p.safeTick(ctx)
		select {
		case <-ctx.Done():
		case <-t.C:
		}
	}
}

// safeTick is tick that logs a panic instead of killing the service: the next tick tries again.
func (p *protection) safeTick(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("protection: tick panicked (the next tick retries): %v", r)
		}
	}()
	p.tick(ctx)
}

// tick refreshes the due feeds, opens and ends community bans, checks DB-IP and applies the
// retention. Each step that changed something invalidates the snapshot at once, so a new ban does
// not wait for a DB-IP download. Without sharing only the retention runs. Errors are logged,
// never fatal; none carries an address or a URL (feed errors are kept in the feed's last_error).
func (p *protection) tick(ctx context.Context) {
	if p.compiler == nil {
		if err := p.store.EndExpired(ctx, time.Now()); err != nil {
			log.Printf("protection: community list: %v", err)
		}
	} else {
		if p.feeds.Tick(ctx) {
			p.compiler.Invalidate()
		}
		opened, err := p.engine.Tick(ctx)
		if err != nil {
			log.Printf("protection: community list: %v", err)
		}
		if opened {
			p.compiler.Invalidate()
		}
		changed, err := p.geo.Tick(ctx)
		if err != nil {
			log.Printf("protection: DB-IP update: %v", err)
		}
		if changed {
			p.compiler.Invalidate()
		}
	}
	if err := p.store.PruneProtection(ctx, time.Now()); err != nil {
		log.Printf("protection: retention: %v", err)
	}
}
