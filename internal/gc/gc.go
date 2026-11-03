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
	IdleAfter time.Duration // a fleet with no online node for longer than this is deleted
	// JoinKeyTTL: a fleet with no node at all, older than twice this and holding no pending join
	// key, is deleted whatever IdleAfter says (key requests keep its row fresh). Zero: no such rule.
	JoinKeyTTL time.Duration
	Now        func() time.Time // default time.Now
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
				safeTick(ctx, d)
			}
		}
	}
}

// safeTick is Tick that logs a panic instead of killing the service: the next tick tries again.
func safeTick(ctx context.Context, d Deps) {
	defer func() {
		if p := recover(); p != nil {
			log.Printf("gc: tick panicked (the next tick retries): %v", p)
		}
	}()
	Tick(ctx, d)
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
	empty := map[string]bool{}                 // fleets read with no node at all
	online := map[string]bool{}                // fleets with an online node in this pass, touched or not
	for _, f := range all {
		users[f.HeadscaleUser] = true
		nodes, err := hs.ListNodes(ctx, f.HeadscaleUser)
		if err != nil {
			log.Printf("gc: fleet %s: list nodes: %v", f.ID, err)
			continue
		}
		checked[f.ID] = true
		empty[f.ID] = len(nodes) == 0
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

	pending, keysRead := pruneKeys(ctx, d, users, now)
	if keysRead && d.JoinKeyTTL > 0 {
		removeEmpty(ctx, d, all, users, empty, pending, now)
	}

	// Last, so it also repairs a policy edited by hand and one a failed delete left behind.
	if d.Remover.Policy != nil {
		if err := d.Remover.Policy.Sync(ctx); err != nil {
			log.Printf("gc: policy sync: %v", err)
		}
	}
}

// removeEmpty deletes the fleets that never got a node, or lost them all, and are older than two
// join-key lifetimes, unless they hold a pending key (a box may be joining). Without this rule an
// owner asking for a key now and then would keep an empty fleet alive forever, since each key
// request refreshes the row the idle rule reads.
func removeEmpty(ctx context.Context, d Deps, all []store.Fleet, users, empty, pending map[string]bool, now time.Time) {
	createdBefore := now.Add(-2 * d.JoinKeyTTL)
	for _, f := range all {
		// users: not deleted by the idle rule in this pass; pending: read after now, so a key asked
		// for later shows as a row touched after now, which RemoveIfEmpty checks under the lock.
		if !empty[f.ID] || !users[f.HeadscaleUser] || pending[f.HeadscaleUser] || !f.CreatedAt.Before(createdBefore) {
			continue
		}
		cur, err := d.Remover.Store.Fleet(ctx, f.ID)
		if err != nil {
			log.Printf("gc: fleet %s: %v", f.ID, err)
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, fleets.RemoveTimeout)
		removed, err := d.Remover.RemoveIfEmpty(rctx, cur, now)
		cancel()
		if err != nil {
			log.Printf("gc: fleet %s: delete: %v", f.ID, err)
			continue
		}
		if removed {
			log.Printf("gc: fleet %s deleted: no node %s after creation and no pending join key", f.ID, 2*d.JoinKeyTTL)
		}
	}
}

// pruneKeys deletes the used and the expired pre-auth keys of the fleets in users. Headscale keeps
// them forever and lists every user's keys on each quota check. A used key's node has already
// registered; an unused unexpired one is still a promise to a box and stays. It returns the users
// holding such a pending key; ok is false if the keys could not be listed.
func pruneKeys(ctx context.Context, d Deps, users map[string]bool, now time.Time) (pending map[string]bool, ok bool) {
	hs := d.Remover.Headscale
	keys, err := hs.ListAllPreAuthKeys(ctx)
	if err != nil {
		log.Printf("gc: list pre-auth keys: %v", err)
		return nil, false
	}
	pending = map[string]bool{}
	for _, k := range keys {
		if !users[k.User] {
			continue // not a fleet's: not ours to touch
		}
		if k.Used || (!k.Expiration.IsZero() && !k.Expiration.After(now)) {
			if err := hs.DeletePreAuthKey(ctx, k.ID); err != nil {
				log.Printf("gc: delete pre-auth key %s: %v", k.ID, err)
			}
		} else {
			pending[k.User] = true
		}
	}
	return pending, true
}
