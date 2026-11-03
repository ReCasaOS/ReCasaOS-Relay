// Package headscale is a small client for the Headscale admin REST API (/api/v1).
//
// Request and response shapes were checked against a live headscale/headscale:v0.29.7 (the
// image pinned in compose.yaml) and its /swagger/v1/openapiv2.json:
//
//   - Auth: "Authorization: Bearer <API key>"; a missing or bad key gives 401 "Unauthorized".
//   - POST /api/v1/user {"name"} -> 200 {"user":{"id":"1","name":...}}; a duplicate name gives
//     500 {"code":13,"message":"...UNIQUE constraint failed..."}.
//   - GET /api/v1/user?name=N -> 200 {"users":[...]} ([] when unknown). Ids are decimal strings.
//   - DELETE /api/v1/user/{id} -> 200 {}; unknown id -> 500 "user not found"; non-numeric -> 400.
//     Deleting by name is not possible, so names are resolved to ids first.
//   - POST /api/v1/preauthkey {"user":"<id>","reusable":false,"ephemeral":false,"expiration":RFC3339}
//     -> 200 {"preAuthKey":{"key":"hskey-auth-...","used":false,"expiration":...}}.
//   - GET /api/v1/node?user=N -> 200 {"nodes":[...]}; an unknown user gives 500 "user not found".
//   - PUT /api/v1/policy {"policy":"<json text>"} -> 200 {"policy":...,"updatedAt":...}; invalid
//     policy -> 500 {"message":"setting policy: parsing policy: ..."}. Mode "database" starts with
//     no policy (GET gives 500 "acl policy not found" until the first PUT).
//   - GET /api/v1/preauthkey -> 200 {"preAuthKeys":[{"user":{"id","name"},"id":"1","key":"hskey-auth-xxxx-***",
//     "reusable":false,"ephemeral":false,"used":false,"expiration":RFC3339,...}]}. It takes NO
//     parameter (the swagger lists none and ?user= was seen to be ignored): it returns the keys of
//     every user, with the key text masked, so the caller filters by user.name.
//
// Verified later against real tailscaled nodes (e2e/isolation_test.go): "used" turns true once a
// key registers a node (a fresh key lists used=false); deleting a user without nodes also deletes
// its pre-auth keys; deleting a user that still owns nodes is refused (500 "user not empty:
// node(s) found") and keeps the keys; after the nodes are deleted the user and its keys go.
//
// Checked live in Task 7: DELETE /api/v1/preauthkey?id=N -> 200 {} (id is a query parameter, a
// decimal string; an unknown id is also 200 {}; non-numeric -> 400); keys list their "id"; deleting
// a user removes its keys even when none was deleted first.
//
// Not exercised live: that a second registration with a used key is refused (Headscale's own
// semantics for reusable=false) and DELETE /api/v1/node/{id} for an unknown id (expected 404
// {"code":5,"message":"node not found"}).
package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Node is a machine of a fleet, as the dashboard shows it.
type Node struct {
	Hostname, IP string
	Online       bool
}

// PreAuthKey is a join key as Headscale lists it (the key text itself is masked there).
type PreAuthKey struct {
	ID   string // Headscale's numeric id, a decimal string
	User string // name of the owning user
	Used bool
	// Expiration is the zero time for a key that never expires.
	Expiration time.Time
}

// API is what the enrolment service needs from Headscale.
type API interface {
	CreateUser(ctx context.Context, name string) error
	// DeleteUser removes the user; an unknown user is not an error.
	DeleteUser(ctx context.Context, name string) error
	// CreatePreAuthKey returns a single-use key for the user, valid for ttl.
	CreatePreAuthKey(ctx context.Context, user string, ttl time.Duration) (key string, err error)
	// ListPreAuthKeys returns the user's pre-auth keys, used and expired ones included.
	ListPreAuthKeys(ctx context.Context, user string) ([]PreAuthKey, error)
	// ListAllPreAuthKeys returns every user's keys in one request (Headscale cannot filter).
	ListAllPreAuthKeys(ctx context.Context) ([]PreAuthKey, error)
	// DeletePreAuthKey removes a key by id; an unknown id is not an error.
	DeletePreAuthKey(ctx context.Context, id string) error
	ListNodes(ctx context.Context, user string) ([]Node, error)
	// DeleteNode removes the user's node with that hostname; an unknown node is not an error.
	DeleteNode(ctx context.Context, user, hostname string) error
	SetPolicy(ctx context.Context, policyJSON []byte) error
}

// ErrUserNotFound is returned when an operation needs a Headscale user that does not exist.
var ErrUserNotFound = errors.New("headscale: user not found")

// APIError is a non-2xx answer from Headscale. Message is Headscale's own text; the API key is
// never part of it.
type APIError struct {
	Method, Path string
	Status       int
	Message      string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("headscale: %s %s: %d %s", e.Method, e.Path, e.Status, e.Message)
}

// Client implements API over HTTP.
type Client struct {
	baseURL, apiKey string
	hc              *http.Client
	now             func() time.Time
	maxBody         int64 // largest accepted response
}

// New returns a client for the Headscale at baseURL (e.g. http://headscale:8080). A nil hc gets a
// client with a 15 s timeout.
func New(baseURL, apiKey string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, hc: hc, now: time.Now, maxBody: 32 << 20}
}

var _ API = (*Client)(nil)

// do sends a JSON request and decodes a 2xx JSON answer into out (when non-nil).
func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// net/http errors carry the URL (no credentials: the key is in a header) and the cause.
		return fmt.Errorf("headscale: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	// Generous: the pre-auth key list covers every fleet and grows with the number of keys ever issued.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return fmt.Errorf("headscale: %s %s: %w", method, path, err)
	}
	if int64(len(raw)) > c.maxBody {
		return fmt.Errorf("headscale: %s %s: response too large (over %d bytes)", method, path, c.maxBody)
	}
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(raw))
		var e struct{ Message string }
		if json.Unmarshal(raw, &e) == nil && e.Message != "" {
			msg = e.Message
		}
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Message: msg}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("headscale: %s %s: bad response: %w", method, path, err)
		}
	}
	return nil
}

type hsUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// userID resolves a user name to Headscale's numeric id; ok is false when there is no such user.
func (c *Client) userID(ctx context.Context, name string) (id string, ok bool, err error) {
	var res struct{ Users []hsUser }
	if err := c.do(ctx, http.MethodGet, "/api/v1/user", url.Values{"name": {name}}, nil, &res); err != nil {
		return "", false, err
	}
	for _, u := range res.Users {
		if u.Name == name { // exact match, whatever the server's filter does
			return u.ID, true, nil
		}
	}
	return "", false, nil
}

func (c *Client) CreateUser(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodPost, "/api/v1/user", nil, map[string]string{"name": name}, nil)
}

func (c *Client) DeleteUser(ctx context.Context, name string) error {
	id, ok, err := c.userID(ctx, name)
	if err != nil || !ok {
		return err
	}
	return c.do(ctx, http.MethodDelete, "/api/v1/user/"+url.PathEscape(id), nil, nil, nil)
}

func (c *Client) CreatePreAuthKey(ctx context.Context, user string, ttl time.Duration) (string, error) {
	id, ok, err := c.userID(ctx, user)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", ErrUserNotFound
	}
	req := struct {
		User       string `json:"user"`
		Reusable   bool   `json:"reusable"`
		Ephemeral  bool   `json:"ephemeral"`
		Expiration string `json:"expiration"`
	}{User: id, Expiration: c.now().Add(ttl).UTC().Format(time.RFC3339)}
	var res struct {
		PreAuthKey struct{ Key string } `json:"preAuthKey"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/preauthkey", nil, req, &res); err != nil {
		return "", err
	}
	if res.PreAuthKey.Key == "" {
		return "", errors.New("headscale: pre-auth key missing from response")
	}
	return res.PreAuthKey.Key, nil
}

func (c *Client) ListAllPreAuthKeys(ctx context.Context) ([]PreAuthKey, error) {
	var res struct {
		PreAuthKeys []struct {
			ID         string
			User       hsUser
			Used       bool
			Expiration time.Time // absent or null: stays zero
		}
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/preauthkey", nil, nil, &res); err != nil {
		return nil, err
	}
	out := make([]PreAuthKey, 0, len(res.PreAuthKeys))
	for _, k := range res.PreAuthKeys {
		out = append(out, PreAuthKey{ID: k.ID, User: k.User.Name, Used: k.Used, Expiration: k.Expiration})
	}
	return out, nil
}

func (c *Client) ListPreAuthKeys(ctx context.Context, user string) ([]PreAuthKey, error) {
	all, err := c.ListAllPreAuthKeys(ctx)
	if err != nil {
		return nil, err
	}
	var out []PreAuthKey
	for _, k := range all {
		if k.User == user { // the endpoint lists every user's keys
			out = append(out, k)
		}
	}
	return out, nil
}

func (c *Client) DeletePreAuthKey(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/preauthkey", url.Values{"id": {id}}, nil, nil)
}

type hsNode struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	IPAddresses []string `json:"ipAddresses"`
	Online      bool     `json:"online"`
	User        hsUser   `json:"user"`
}

// nodes lists the user's nodes with their ids. An unknown user has none.
func (c *Client) nodes(ctx context.Context, user string) ([]hsNode, error) {
	if _, ok, err := c.userID(ctx, user); err != nil || !ok {
		return nil, err // Headscale answers 500 "user not found" to a node list of an unknown user
	}
	var res struct{ Nodes []hsNode }
	if err := c.do(ctx, http.MethodGet, "/api/v1/node", url.Values{"user": {user}}, nil, &res); err != nil {
		return nil, err
	}
	var own []hsNode
	for _, n := range res.Nodes {
		if n.User.Name == "" || n.User.Name == user { // never hand out another fleet's node
			own = append(own, n)
		}
	}
	return own, nil
}

func (c *Client) ListNodes(ctx context.Context, user string) ([]Node, error) {
	ns, err := c.nodes(ctx, user)
	if err != nil {
		return nil, err
	}
	out := make([]Node, 0, len(ns))
	for _, n := range ns {
		node := Node{Hostname: n.Name, Online: n.Online}
		if len(n.IPAddresses) > 0 {
			node.IP = n.IPAddresses[0]
		}
		out = append(out, node)
	}
	return out, nil
}

func (c *Client) DeleteNode(ctx context.Context, user, hostname string) error {
	ns, err := c.nodes(ctx, user)
	if err != nil {
		return err
	}
	for _, n := range ns {
		if n.Name == hostname {
			return c.do(ctx, http.MethodDelete, "/api/v1/node/"+url.PathEscape(n.ID), nil, nil, nil)
		}
	}
	return nil
}

func (c *Client) SetPolicy(ctx context.Context, policyJSON []byte) error {
	return c.do(ctx, http.MethodPut, "/api/v1/policy", nil, map[string]string{"policy": string(policyJSON)}, nil)
}
