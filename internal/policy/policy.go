// Package policy builds and pushes the Headscale access policy that keeps fleets apart.
//
// Each fleet is a Headscale user. The policy defines one group per user holding exactly that user,
// and one rule per group: accept group -> same group, all ports. Nothing else: no wildcard, no
// autogroup, no rule naming two groups. With no rule matching, Headscale denies, so two fleets
// never see each other. Zero fleets give an explicit empty "acls" list: a missing policy (Headscale
// starts with none) or one without "acls" would allow everything.
//
// Syntax checked against headscale/headscale:v0.29.7 (PUT /api/v1/policy, then GET): users in a
// group are written "<name>@" (without the "@" the policy is refused), "group:<name>:*" is a valid
// destination, `{"groups":{},"acls":[]}` is accepted and read back unchanged, a group used by a
// rule but not defined is refused, and a group member that is not an existing user is accepted.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// userRE is the name of a fleet's Headscale user: "f-" and the 32 hex digits of the fleet id.
// Nothing else may reach the policy text.
var userRE = regexp.MustCompile(`^f-[0-9a-f]{32}$`)

type rule struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
}

type document struct {
	Groups map[string][]string `json:"groups"`
	ACLs   []rule              `json:"acls"`
}

// Build returns the policy for these fleet users: sorted, duplicates merged, byte-for-byte the same
// for the same set. An invalid user name is an error and no policy is produced.
func Build(fleetUsers []string) ([]byte, error) {
	users := make([]string, 0, len(fleetUsers))
	for _, u := range fleetUsers {
		if !userRE.MatchString(u) {
			return nil, fmt.Errorf("policy: invalid fleet user name %q", u)
		}
		users = append(users, u)
	}
	sort.Strings(users)
	doc := document{Groups: map[string][]string{}, ACLs: []rule{}} // non-nil: "{}" and "[]", never null
	for i, u := range users {
		if i > 0 && users[i-1] == u {
			continue
		}
		g := "group:" + u
		doc.Groups[g] = []string{u + "@"}
		doc.ACLs = append(doc.ACLs, rule{Action: "accept", Src: []string{g}, Dst: []string{g + ":*"}})
	}
	return json.Marshal(doc) // map keys are emitted sorted
}

// FleetLister is the part of store.Store the writer needs.
type FleetLister interface {
	ListFleets(ctx context.Context) ([]store.Fleet, error)
}

// Writer rebuilds the policy from every fleet in the store and pushes it to Headscale. The mutex
// covers list, build and push, so concurrent creates and deletes cannot push an older list after a
// newer one.
type Writer struct {
	mu     sync.Mutex
	fleets FleetLister
	hs     headscale.API
}

func NewWriter(fleets FleetLister, hs headscale.API) *Writer {
	return &Writer{fleets: fleets, hs: hs}
}

// Sync pushes the policy for the fleets currently in the store. Call it after every fleet creation
// or deletion (once the store row is inserted or removed).
func (w *Writer) Sync(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	fleets, err := w.fleets.ListFleets(ctx)
	if err != nil {
		return fmt.Errorf("policy: list fleets: %w", err)
	}
	users := make([]string, 0, len(fleets))
	for _, f := range fleets {
		users = append(users, f.HeadscaleUser)
	}
	p, err := Build(users)
	if err != nil {
		return err
	}
	if err := w.hs.SetPolicy(ctx, p); err != nil {
		return fmt.Errorf("policy: push: %w", err)
	}
	return nil
}

// hookTimeout bounds one Sync from the create-fleet hook (the handler itself allows 20 s overall).
const hookTimeout = 10 * time.Second

// Hook is the server.Deps.PolicyHook: it ignores the users it is given and rebuilds from all fleets.
func (w *Writer) Hook(_ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), hookTimeout)
	defer cancel()
	return w.Sync(ctx)
}

// SyncWithRetry is Sync with up to attempts tries, waiting base, 2*base, ... (at most 8*base)
// between them, for a Headscale that is still starting. The last error is returned.
func (w *Writer) SyncWithRetry(ctx context.Context, attempts int, base time.Duration) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = w.Sync(ctx); err == nil {
			return nil
		}
		if i == attempts-1 {
			break
		}
		select {
		case <-time.After(base << min(i, 3)):
		case <-ctx.Done():
			return fmt.Errorf("%w (last error: %v)", ctx.Err(), err)
		}
	}
	return err
}
