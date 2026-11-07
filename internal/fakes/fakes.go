// Package fakes holds in-memory stand-ins for Headscale, the policy writer and the store, with one
// shared call log, for tests of the code that deletes fleets.
package fakes

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// Log records operations in the order they happen.
type Log struct {
	mu    sync.Mutex
	calls []string
}

func (l *Log) Add(s string) {
	l.mu.Lock()
	l.calls = append(l.calls, s)
	l.mu.Unlock()
}

func (l *Log) Calls() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

func (l *Log) String() string { return strings.Join(l.Calls(), ",") }

func (l *Log) Reset() {
	l.mu.Lock()
	l.calls = nil
	l.mu.Unlock()
}

// HS behaves like Headscale where it matters here: a user that still owns nodes cannot be deleted,
// deleting a user drops its keys, and unknown nodes, keys and users are accepted silently.
// Operations are logged as: nodes, node:<id> (DeleteNodeByID), nodes-named:<host> (DeleteNode), user, keys, key:<id>, create-key, policy.
type HS struct {
	headscale.API // anything not overridden panics: the code under test must not call it
	Log           *Log
	Now           func() time.Time

	mu    sync.Mutex
	users map[string]bool
	nodes map[string][]headscale.Node
	keys  []headscale.PreAuthKey
	fail  map[string]error
	left  map[string]int // remaining failures for an op failing a limited number of times
	nextK int
	nextN int

	// Hook, when set, runs at the start of the named operation, outside any lock; a test uses it to
	// block an operation. The op names are those of the log, without the argument.
	Hook func(op string)
	// KeepKeysOnUserDelete makes DeleteUser leave the user's keys behind, as if Headscale did not cascade.
	KeepKeysOnUserDelete bool
	// Expired lists auth ids RegisterNode answers ErrAuthRequestNotFound for.
	Expired map[string]bool
	// RegisterHostname, when set, is the hostname RegisterNode gives the node (default device-<n>).
	RegisterHostname string
}

func NewHS(log *Log, now func() time.Time) *HS {
	return &HS{Log: log, Now: now, users: map[string]bool{}, nodes: map[string][]headscale.Node{}, fail: map[string]error{}, left: map[string]int{}}
}

// Fail makes the named operation return err until Heal.
func (h *HS) Fail(op string, err error) { h.mu.Lock(); h.fail[op] = err; h.mu.Unlock() }
func (h *HS) Heal(op string)            { h.mu.Lock(); delete(h.fail, op); delete(h.left, op); h.mu.Unlock() }

// FailTimes makes the next n calls of the named operation return err, then heals it.
func (h *HS) FailTimes(op string, err error, n int) {
	h.mu.Lock()
	h.fail[op], h.left[op] = err, n
	h.mu.Unlock()
}

func (h *HS) enter(op, entry string) error {
	if h.Hook != nil {
		h.Hook(op)
	}
	h.Log.Add(entry)
	h.mu.Lock()
	defer h.mu.Unlock()
	err := h.fail[op]
	if n, limited := h.left[op]; limited {
		if n--; n <= 0 {
			delete(h.fail, op)
			delete(h.left, op)
		} else {
			h.left[op] = n
		}
	}
	return err
}

// AddUser registers a user (as CreateUser would).
func (h *HS) AddUser(u string) { h.mu.Lock(); h.users[u] = true; h.mu.Unlock() }

// AddNode adds a node and returns its id. Like Headscale, it allows several nodes of one user to
// share a hostname.
func (h *HS) AddNode(user, host string, online bool) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.users[user] = true
	h.nextN++
	id := strconv.Itoa(h.nextN)
	h.nodes[user] = append(h.nodes[user], headscale.Node{ID: id, Hostname: host, Online: online, User: user})
	return id
}

// SetOnline changes the online flag of every node of the user with that hostname.
func (h *HS) SetOnline(user, host string, online bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.nodes[user] {
		if h.nodes[user][i].Hostname == host {
			h.nodes[user][i].Online = online
		}
	}
}

// SetNodeInfo fills the richer fields the admin page shows (addresses, last seen, key expiry) for
// every node of the user with that hostname.
func (h *HS) SetNodeInfo(user, host string, ips []string, lastSeen, expiry time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.nodes[user] {
		if h.nodes[user][i].Hostname == host {
			h.nodes[user][i].IPs = ips
			if len(ips) > 0 {
				h.nodes[user][i].IP = ips[0]
			}
			h.nodes[user][i].LastSeen = lastSeen
			h.nodes[user][i].Expiry = expiry
		}
	}
}

// SetNodeKey sets the node key of every node of the user with that hostname.
func (h *HS) SetNodeKey(user, host, nodeKey string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range h.nodes[user] {
		if h.nodes[user][i].Hostname == host {
			h.nodes[user][i].NodeKey = nodeKey
		}
	}
}

// AddKey adds a key owned by user and returns its id.
func (h *HS) AddKey(user string, used bool, exp time.Time) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.users[user] = true
	h.nextK++
	id := strconv.Itoa(h.nextK)
	h.keys = append(h.keys, headscale.PreAuthKey{ID: id, User: user, Used: used, Expiration: exp})
	return id
}

func (h *HS) HasUser(u string) bool  { h.mu.Lock(); defer h.mu.Unlock(); return h.users[u] }
func (h *HS) NodeCount(u string) int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.nodes[u]) }
func (h *HS) Keys() []headscale.PreAuthKey {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]headscale.PreAuthKey(nil), h.keys...)
}

func (h *HS) ListNodes(_ context.Context, user string) ([]headscale.Node, error) {
	if err := h.enter("nodes", "nodes"); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]headscale.Node(nil), h.nodes[user]...), nil
}

// RegisterNode adds a node to the user, as approving a web login does (log: register:<user>).
func (h *HS) RegisterNode(_ context.Context, user, authID string) (headscale.Node, error) {
	if err := h.enter("register", "register:"+user); err != nil {
		return headscale.Node{}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.Expired[authID] {
		return headscale.Node{}, headscale.ErrAuthRequestNotFound
	}
	h.users[user] = true
	h.nextN++
	n := headscale.Node{ID: strconv.Itoa(h.nextN), Hostname: "device-" + strconv.Itoa(h.nextN), User: user}
	if h.RegisterHostname != "" {
		n.Hostname = h.RegisterHostname
	}
	h.nodes[user] = append(h.nodes[user], n)
	return n, nil
}

// ListAllNodes returns every user's nodes, users in name order.
func (h *HS) ListAllNodes(_ context.Context) ([]headscale.Node, error) {
	if err := h.enter("nodes-all", "nodes-all"); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	users := make([]string, 0, len(h.nodes))
	for u := range h.nodes {
		users = append(users, u)
	}
	sort.Strings(users)
	var out []headscale.Node
	for _, u := range users {
		out = append(out, h.nodes[u]...)
	}
	return out, nil
}

// DeleteNode removes every node of the user with that hostname.
func (h *HS) DeleteNode(_ context.Context, user, host string) error {
	if err := h.enter("nodes-named", "nodes-named:"+host); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var keep []headscale.Node
	for _, n := range h.nodes[user] {
		if n.Hostname != host {
			keep = append(keep, n)
		}
	}
	h.nodes[user] = keep
	return nil
}

// DeleteNodeByID removes exactly the node with that id.
func (h *HS) DeleteNodeByID(_ context.Context, id string) error {
	if err := h.enter("node", "node:"+id); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for u, ns := range h.nodes {
		var keep []headscale.Node
		for _, n := range ns {
			if n.ID != id {
				keep = append(keep, n)
			}
		}
		h.nodes[u] = keep
	}
	return nil
}

func (h *HS) DeleteUser(_ context.Context, user string) error {
	if err := h.enter("user", "user"); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.nodes[user]) > 0 {
		return errors.New("user not empty: node(s) found")
	}
	delete(h.users, user)
	delete(h.nodes, user)
	if h.KeepKeysOnUserDelete {
		return nil
	}
	var keep []headscale.PreAuthKey
	for _, k := range h.keys {
		if k.User != user {
			keep = append(keep, k)
		}
	}
	h.keys = keep
	return nil
}

func (h *HS) ListPreAuthKeys(_ context.Context, user string) ([]headscale.PreAuthKey, error) {
	if err := h.enter("keys", "keys"); err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []headscale.PreAuthKey
	for _, k := range h.keys {
		if k.User == user {
			out = append(out, k)
		}
	}
	return out, nil
}

func (h *HS) ListAllPreAuthKeys(context.Context) ([]headscale.PreAuthKey, error) {
	if err := h.enter("allkeys", "allkeys"); err != nil {
		return nil, err
	}
	return h.Keys(), nil
}

func (h *HS) DeletePreAuthKey(_ context.Context, id string) error {
	if err := h.enter("key", "key:"+id); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var keep []headscale.PreAuthKey
	for _, k := range h.keys {
		if k.ID != id {
			keep = append(keep, k)
		}
	}
	h.keys = keep
	return nil
}

func (h *HS) CreatePreAuthKey(_ context.Context, user string, ttl time.Duration) (string, error) {
	if err := h.enter("create-key", "create-key"); err != nil {
		return "", err
	}
	h.AddKey(user, false, h.Now().Add(ttl))
	return "hskey-auth-secret", nil
}

// Store logs DeleteFleet ("row") and can be made to fail it.
type Store struct {
	store.Store
	Log *Log

	// OnFleet, when set, runs after each Fleet lookup has read its row, so a test can change the
	// fleet between that read and whatever the caller does next.
	OnFleet func(id string)

	mu       sync.Mutex
	err      error
	touchErr error
}

func (s *Store) FailDelete(err error) { s.mu.Lock(); s.err = err; s.mu.Unlock() }

// FailTouch makes Touch return err (nil: works again).
func (s *Store) FailTouch(err error) { s.mu.Lock(); s.touchErr = err; s.mu.Unlock() }

func (s *Store) Touch(ctx context.Context, id string, at time.Time) error {
	s.mu.Lock()
	err := s.touchErr
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.Store.Touch(ctx, id, at)
}

func (s *Store) Fleet(ctx context.Context, id string) (store.Fleet, error) {
	f, err := s.Store.Fleet(ctx, id)
	if s.OnFleet != nil {
		s.OnFleet(id)
	}
	return f, err
}

func (s *Store) DeleteFleet(ctx context.Context, id string) error {
	s.Log.Add("row")
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.Store.DeleteFleet(ctx, id)
}

// Syncer is a policy writer that only logs ("sync").
type Syncer struct {
	Log *Log

	mu  sync.Mutex
	err error
}

func (s *Syncer) Fail(err error) { s.mu.Lock(); s.err = err; s.mu.Unlock() }

func (s *Syncer) Sync(context.Context) error {
	s.Log.Add("sync")
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}
