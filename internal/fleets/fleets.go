// Package fleets holds what the HTTP handlers and the idle-fleet janitor share: the per-fleet lock
// and the one routine that removes a fleet.
package fleets

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// RemoveTimeout bounds one Remove: each node costs a few Headscale calls and a fleet may hold many.
const RemoveTimeout = 40 * time.Second

// Locks is a set of per-key mutexes whose entries exist only while held or awaited, so the map
// stays as small as the number of requests in flight. The zero value is ready to use.
type Locks struct {
	mu sync.Mutex
	m  map[string]*lockEntry
}

type lockEntry struct {
	sem  chan struct{} // capacity 1: a token in it means held
	refs int
}

// Lock waits for the key's lock or ctx; the returned func releases it.
func (k *Locks) Lock(ctx context.Context, key string) (func(), error) {
	k.mu.Lock()
	if k.m == nil {
		k.m = map[string]*lockEntry{}
	}
	e := k.m[key]
	if e == nil {
		e = &lockEntry{sem: make(chan struct{}, 1)}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()
	release := func() {
		k.mu.Lock()
		if e.refs--; e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
	select {
	case e.sem <- struct{}{}:
		return func() { <-e.sem; release() }, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}

// Syncer rebuilds the access policy from the fleets in the store (policy.Writer).
type Syncer interface {
	Sync(ctx context.Context) error
}

// Remover deletes fleets. The HTTP DELETE and the janitor use the same one, and the same Locks as
// the key endpoint, so a deletion never interleaves with a key request for that fleet.
type Remover struct {
	Store     store.Store
	Headscale headscale.API
	Policy    Syncer // nil: the policy is not touched
	Locks     *Locks
}

// Remove deletes the fleet from Headscale and the store while holding the fleet's lock.
//
// The order matters because Headscale refuses to delete a user that still owns nodes and because a
// failure must leave something to retry with: nodes (by id: hostnames are not unique), then the
// user, then any pre-auth key still listed for it, then the store row (the secret the client retries
// with) last. Any failure before the row is gone returns an error and keeps the row; every step
// accepts "already gone", so a retry resumes where the last attempt stopped. A failing policy sync
// does not undo a deletion that is complete (the row is gone, and a policy still naming a deleted
// user lets nobody through); it is logged and the janitor's next tick pushes the policy again.
func (r *Remover) Remove(ctx context.Context, f store.Fleet) error {
	_, err := r.remove(ctx, f, nil)
	return err
}

// RemoveIfIdle is Remove for the janitor: under the lock it first checks again that the fleet is
// still idle, and does nothing (removed false, no error) if its row was touched since idleBefore or
// if any of its nodes is online right now. The janitor's own reading of the fleet may be a whole
// pass old, and a key request, which waits for this lock, counts as activity.
func (r *Remover) RemoveIfIdle(ctx context.Context, f store.Fleet, idleBefore time.Time) (removed bool, err error) {
	return r.remove(ctx, f, &idleBefore)
}

func (r *Remover) remove(ctx context.Context, f store.Fleet, idleBefore *time.Time) (bool, error) {
	unlock, err := r.Locks.Lock(ctx, f.ID)
	if err != nil {
		return false, err
	}
	defer unlock()

	if idleBefore != nil {
		cur, err := r.Store.Fleet(ctx, f.ID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil // deleted meanwhile
		}
		if err != nil {
			return false, fmt.Errorf("re-read fleet: %w", err)
		}
		if !cur.LastOnline.Before(*idleBefore) {
			return false, nil
		}
	}
	nodes, err := r.Headscale.ListNodes(ctx, f.HeadscaleUser)
	if err != nil {
		return false, fmt.Errorf("list nodes: %w", err)
	}
	if idleBefore != nil {
		for _, n := range nodes {
			if n.Online {
				return false, nil
			}
		}
	}
	for _, n := range nodes {
		if err := r.Headscale.DeleteNodeByID(ctx, n.ID); err != nil {
			return false, fmt.Errorf("delete node: %w", err)
		}
	}
	if err := r.Headscale.DeleteUser(ctx, f.HeadscaleUser); err != nil {
		return false, fmt.Errorf("delete user: %w", err)
	}
	// Headscale drops a user's keys with the user (checked live); this catches any it did not.
	keys, err := r.Headscale.ListPreAuthKeys(ctx, f.HeadscaleUser)
	if err != nil {
		return false, fmt.Errorf("list keys: %w", err)
	}
	for _, k := range keys {
		if err := r.Headscale.DeletePreAuthKey(ctx, k.ID); err != nil {
			return false, fmt.Errorf("delete key: %w", err)
		}
	}
	if err := r.Store.DeleteFleet(ctx, f.ID); err != nil {
		return false, fmt.Errorf("delete fleet row: %w", err)
	}
	if r.Policy != nil {
		if err := r.Policy.Sync(ctx); err != nil {
			log.Printf("fleet %s removed, policy sync failed (the next janitor tick retries): %v", f.ID, err)
		}
	}
	return true, nil
}
