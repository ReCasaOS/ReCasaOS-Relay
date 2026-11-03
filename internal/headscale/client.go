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
//
// Not exercised live (no node could be registered): the fields of a real node in the node list
// (taken from the OpenAPI definition v1Node: id, name, ipAddresses, online, user.name) and
// DELETE /api/v1/node/{id} (unknown id -> 404 {"code":5,"message":"node not found"}). Headscale
// is also expected to refuse deleting a user that still owns nodes; delete the nodes first.
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

// API is what the enrolment service needs from Headscale.
type API interface {
	CreateUser(ctx context.Context, name string) error
	// DeleteUser removes the user; an unknown user is not an error.
	DeleteUser(ctx context.Context, name string) error
	// CreatePreAuthKey returns a single-use key for the user, valid for ttl.
	CreatePreAuthKey(ctx context.Context, user string, ttl time.Duration) (key string, err error)
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
}

// New returns a client for the Headscale at baseURL (e.g. http://headscale:8080). A nil hc gets a
// client with a 15 s timeout.
func New(baseURL, apiKey string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), apiKey: apiKey, hc: hc, now: time.Now}
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("headscale: %s %s: %w", method, path, err)
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
