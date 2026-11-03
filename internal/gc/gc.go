// Package gc is the janitor: it notices which fleets still have a machine online, deletes the ones
// that have been idle too long and prunes the pre-auth keys Headscale never removes.
package gc

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// Deps are the janitor's collaborators. Remover carries the store, the Headscale client, the policy
// writer and the per-fleet locks: share the one the HTTP handlers use, so a deletion here cannot
// interleave with a request for the same fleet.
type Deps struct {
	Remover   *fleets.Remover
	IdleAfter time.Duration    // a fleet with no online node for longer than this is deleted
	Now       func() time.Time // default time.Now
}

// Run runs a tick every `every` until ctx is done, then returns. A tick in progress is not
// abandoned: Run returns only once it has returned (ctx cancels its Headscale calls, so that is soon).
func Run(ctx context.Context, d Deps, every time.Duration) {
	if d.Now == nil {
		d.Now = time.Now
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if ctx.Err() == nil {
				Tick(ctx, d)
			}
		}
	}
}

// Tick does one pass. A failure for one fleet is logged and does not stop the pass.
func Tick(ctx context.Context, d Deps) {
	if d.Now == nil {
		d.Now = time.Now
	}
	st, hs := d.Remover.Store, d.Remover.Headscale
	now := d.Now()

	all, err := st.ListFleets(ctx)
	if err != nil {
		log.Printf("gc: list fleets: %v", err)
		return
	}
	users := make(map[string]bool, len(all))
	checked := make(map[string]bool, len(all)) // fleets whose nodes were read in this pass
	online := map[string]bool{}                // fleets with an online node in this pass, touched or not
	for _, f := range all {
		users[f.HeadscaleUser] = true
		nodes, err := hs.ListNodes(ctx, f.HeadscaleUser)
		if err != nil {
			log.Printf("gc: fleet %s: list nodes: %v", f.ID, err)
			continue
		}
		checked[f.ID] = true
		for _, n := range nodes {
			if n.Online {
				online[f.ID] = true // even if Touch fails below: the row is stale, the fleet is not idle
				if err := st.Touch(ctx, f.ID, now); err != nil && !errors.Is(err, store.ErrNotFound) {
					log.Printf("gc: fleet %s: touch: %v", f.ID, err)
				}
				break
			}
		}
	}

	cutoff := now.Add(-d.IdleAfter)
	idle, err := st.IdleFleets(ctx, cutoff)
	if err != nil {
		log.Printf("gc: idle fleets: %v", err)
	}
	for _, id := range idle {
		// Never delete on a guess: a fleet whose nodes could not be read this pass may well be online.
		if !checked[id] || online[id] {
			continue
		}
		f, err := st.Fleet(ctx, id)
		if err != nil {
			log.Printf("gc: fleet %s: %v", id, err)
			continue
		}
		// Decided again under the fleet's lock: this pass's view may be minutes old.
		rctx, cancel := context.WithTimeout(ctx, fleets.RemoveTimeout)
		removed, err := d.Remover.RemoveIfIdle(rctx, f, cutoff)
		cancel()
		if err != nil {
			log.Printf("gc: fleet %s: delete: %v", id, err)
			continue
		}
		if !removed {
			continue // active again since it was read
		}
		delete(users, f.HeadscaleUser) // its keys went with it
		log.Printf("gc: fleet %s deleted after %s idle", id, d.IdleAfter)
	}

	pruneKeys(ctx, d, users, now)

	// Last, so it also repairs a policy edited by hand and one a failed delete left behind.
	if d.Remover.Policy != nil {
		if err := d.Remover.Policy.Sync(ctx); err != nil {
			log.Printf("gc: policy sync: %v", err)
		}
	}
}

// pruneKeys deletes the used and the expired pre-auth keys of the fleets in users. Headscale keeps
// them forever and lists every user's keys on each quota check. A used key's node has already
// registered; an unused unexpired one is still a promise to a box and stays.
func pruneKeys(ctx context.Context, d Deps, users map[string]bool, now time.Time) {
	hs := d.Remover.Headscale
	keys, err := hs.ListAllPreAuthKeys(ctx)
	if err != nil {
		log.Printf("gc: list pre-auth keys: %v", err)
		return
	}
	for _, k := range keys {
		if !users[k.User] {
			continue // not a fleet's: not ours to touch
		}
		if k.Used || (!k.Expiration.IsZero() && !k.Expiration.After(now)) {
			if err := hs.DeletePreAuthKey(ctx, k.ID); err != nil {
				log.Printf("gc: delete pre-auth key %s: %v", k.ID, err)
			}
		}
	}
}
