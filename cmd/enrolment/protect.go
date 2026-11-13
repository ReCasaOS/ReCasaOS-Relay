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

// newProtection keeps its files next to the store: <data>/feeds/ and <data>/geo/.
func newProtection(st store.Store, storePath string, maxEntries int, minFleetAge time.Duration) *protection {
	data := filepath.Dir(storePath)
	g := &geo.DB{Dir: filepath.Join(data, "geo")}
	f := &feeds.Fetcher{Store: st, Dir: filepath.Join(data, "feeds"), TotalMax: maxEntries}
	c := &protect.Compiler{Store: st, Feeds: f, Geo: g}
	e := &community.Engine{Store: st, Allowed: c.Allowed, MinFleetAge: minFleetAge}
	return &protection{store: st, feeds: f, geo: g, compiler: c, engine: e}
}

// run ticks at once (to open the DB-IP files), then every `every` until ctx is done; it returns
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
// retention, then has the snapshot rebuilt if any of it changed. Errors are logged, never fatal;
// none carries an address or a URL (feed errors are kept in the feed's last_error instead).
func (p *protection) tick(ctx context.Context) {
	changed := p.feeds.Tick(ctx)
	opened, err := p.engine.Tick(ctx)
	if err != nil {
		log.Printf("protection: community list: %v", err)
	}
	geoChanged, err := p.geo.Tick(ctx)
	if err != nil {
		log.Printf("protection: DB-IP update: %v", err)
	}
	if err := p.store.PruneProtection(ctx, time.Now()); err != nil {
		log.Printf("protection: retention: %v", err)
	}
	if changed || opened || geoChanged {
		p.compiler.Invalidate()
	}
}
