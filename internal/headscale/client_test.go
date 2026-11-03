package headscale

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fake is a Headscale v0.29.7 stand-in. Response shapes mirror what the real server returned
// (see the package comment); the test asserts the requests the client sends.
type fake struct {
	mu    sync.Mutex
	calls []string // "METHOD path?query body"
	reply map[string]reply
}

type reply struct {
	status int
	body   string
}

func newFake(t *testing.T, replies map[string]reply) (*Client, *fake) {
	t.Helper()
	f := &fake{reply: replies}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-api-key" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.Path
		f.mu.Lock()
		f.calls = append(f.calls, strings.TrimSpace(key+"?"+r.URL.RawQuery+" "+string(body)))
		rep, ok := f.reply[key]
		f.mu.Unlock()
		if !ok {
			t.Errorf("unexpected request %s", key)
			rep = reply{500, `{"code":2,"message":"unexpected"}`}
		}
		w.WriteHeader(rep.status)
		io.WriteString(w, rep.body)
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, "test-api-key", srv.Client())
	c.now = func() time.Time { return time.Date(2026, 11, 3, 16, 0, 0, 0, time.UTC) }
	return c, f
}

func (f *fake) want(t *testing.T, calls ...string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.calls, "\n") != strings.Join(calls, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(f.calls, "\n"), strings.Join(calls, "\n"))
	}
}

const (
	userJSON = `{"id":"7", "name":"f-abc", "createdAt":"2026-11-03T16:30:06.240231500Z", "displayName":"", "email":"", "providerId":"", "provider":"", "profilePicUrl":""}`
	noUsers  = `{"users":[]}`
)

func oneUser(name string) string {
	return `{"users":[` + strings.Replace(userJSON, "f-abc", name, 1) + `]}`
}

var ctx = context.Background()

func TestCreateUser(t *testing.T) {
	c, f := newFake(t, map[string]reply{"POST /api/v1/user": {200, `{"user":` + userJSON + `}`}})
	if err := c.CreateUser(ctx, "f-abc"); err != nil {
		t.Fatal(err)
	}
	f.want(t, `POST /api/v1/user? {"name":"f-abc"}`)
}

func TestCreateUserDuplicateIsAnError(t *testing.T) {
	c, _ := newFake(t, map[string]reply{"POST /api/v1/user": {500, `{"code":13, "message":"creating user: UNIQUE constraint failed: users.name (2067)", "details":[]}`}})
	err := c.CreateUser(ctx, "f-abc")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 500 {
		t.Fatalf("got %v", err)
	}
}

func TestDeleteUserResolvesNameToID(t *testing.T) {
	c, f := newFake(t, map[string]reply{
		"GET /api/v1/user":      {200, oneUser("f-abc")},
		"DELETE /api/v1/user/7": {200, `{}`},
	})
	if err := c.DeleteUser(ctx, "f-abc"); err != nil {
		t.Fatal(err)
	}
	f.want(t, `GET /api/v1/user?name=f-abc`, `DELETE /api/v1/user/7?`)
}

func TestDeleteUserUnknownIsNotAnError(t *testing.T) {
	c, f := newFake(t, map[string]reply{"GET /api/v1/user": {200, noUsers}})
	if err := c.DeleteUser(ctx, "f-abc"); err != nil {
		t.Fatal(err)
	}
	f.want(t, `GET /api/v1/user?name=f-abc`)
}

func TestUserLookupIgnoresNonExactMatches(t *testing.T) {
	c, f := newFake(t, map[string]reply{"GET /api/v1/user": {200, oneUser("f-abcd")}})
	if err := c.DeleteUser(ctx, "f-abc"); err != nil {
		t.Fatal(err)
	}
	f.want(t, `GET /api/v1/user?name=f-abc`) // no DELETE: f-abcd is another fleet
}

func TestCreatePreAuthKey(t *testing.T) {
	c, f := newFake(t, map[string]reply{
		"GET /api/v1/user":        {200, oneUser("f-abc")},
		"POST /api/v1/preauthkey": {200, `{"preAuthKey":{"user":` + userJSON + `, "id":"1", "key":"hskey-auth-xyz", "reusable":false, "ephemeral":false, "used":false, "expiration":"2026-11-04T16:00:00Z", "createdAt":"2026-11-03T16:30:11.303516100Z", "aclTags":[]}}`},
	})
	key, err := c.CreatePreAuthKey(ctx, "f-abc", 24*time.Hour)
	if err != nil || key != "hskey-auth-xyz" {
		t.Fatalf("got %q, %v", key, err)
	}
	f.want(t, `GET /api/v1/user?name=f-abc`,
		`POST /api/v1/preauthkey? {"user":"7","reusable":false,"ephemeral":false,"expiration":"2026-11-04T16:00:00Z"}`)
}

func TestCreatePreAuthKeyUnknownUser(t *testing.T) {
	c, _ := newFake(t, map[string]reply{"GET /api/v1/user": {200, noUsers}})
	if _, err := c.CreatePreAuthKey(ctx, "f-abc", time.Hour); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got %v", err)
	}
}

// Shape taken from the live v0.29.7 answer: the endpoint takes no filter and lists every user's
// keys, and the key text is masked.
const preAuthKeysJSON = `{"preAuthKeys":[
 {"user":` + userJSON + `, "id":"1", "key":"hskey-auth-aaaa-***", "reusable":false, "ephemeral":false, "used":false, "expiration":"2026-11-04T17:04:09Z", "createdAt":"2026-11-03T17:04:10.571593400Z", "aclTags":[]},
 {"user":` + userJSON + `, "id":"2", "key":"hskey-auth-bbbb-***", "reusable":false, "ephemeral":false, "used":true, "expiration":"2020-01-01T00:00:00Z", "createdAt":"2026-11-03T17:04:11.433705600Z", "aclTags":[]},
 {"user":{"id":"9","name":"f-other"}, "id":"3", "key":"hskey-auth-cccc-***", "reusable":true, "ephemeral":false, "used":false, "expiration":"2030-01-01T00:00:00Z", "aclTags":[]}]}`

func TestListPreAuthKeysFiltersByUser(t *testing.T) {
	c, f := newFake(t, map[string]reply{"GET /api/v1/preauthkey": {200, preAuthKeysJSON}})
	got, err := c.ListPreAuthKeys(ctx, "f-abc")
	if err != nil {
		t.Fatal(err)
	}
	want := []PreAuthKey{
		{ID: "1", User: "f-abc", Used: false, Expiration: time.Date(2026, 11, 4, 17, 4, 9, 0, time.UTC)},
		{ID: "2", User: "f-abc", Used: true, Expiration: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	f.want(t, `GET /api/v1/preauthkey?`) // no filter parameter exists: filtering is ours
}

func TestListAllPreAuthKeys(t *testing.T) {
	c, f := newFake(t, map[string]reply{"GET /api/v1/preauthkey": {200, preAuthKeysJSON}})
	got, err := c.ListAllPreAuthKeys(ctx)
	if err != nil || len(got) != 3 || got[2].ID != "3" || got[2].User != "f-other" {
		t.Fatalf("got %+v, %v", got, err)
	}
	f.want(t, `GET /api/v1/preauthkey?`)
}

// Verified live on v0.29.7: DELETE /api/v1/preauthkey?id=N -> 200 {}; an unknown id is also 200 {}.
func TestDeletePreAuthKey(t *testing.T) {
	c, f := newFake(t, map[string]reply{"DELETE /api/v1/preauthkey": {200, `{}`}})
	if err := c.DeletePreAuthKey(ctx, "12"); err != nil {
		t.Fatal(err)
	}
	f.want(t, `DELETE /api/v1/preauthkey?id=12`)
}

func TestResponseTooLargeIsAnExplicitError(t *testing.T) {
	c, _ := newFake(t, map[string]reply{"GET /api/v1/preauthkey": {200, `{"preAuthKeys":[` + strings.Repeat(`{"id":"1"},`, 20) + `{"id":"2"}]}`}})
	c.maxBody = 100
	_, err := c.ListAllPreAuthKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "response too large") {
		t.Fatalf("got %v", err)
	}
	c.maxBody = 1 << 20 // the same answer fits under a larger cap: the limit is the cause
	if _, err := c.ListAllPreAuthKeys(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestListPreAuthKeysEmpty(t *testing.T) {
	c, _ := newFake(t, map[string]reply{"GET /api/v1/preauthkey": {200, `{}`}})
	got, err := c.ListPreAuthKeys(ctx, "f-abc")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

const nodesJSON = `{"nodes":[
 {"id":"3","name":"box-a","givenName":"box-a","user":` + userJSON + `,"ipAddresses":["100.64.0.1","fd7a:115c:a1e0::1"],"online":true},
 {"id":"4","name":"box-b","givenName":"box-b-2","user":` + userJSON + `,"ipAddresses":[],"online":false},
 {"id":"5","name":"intruder","user":{"id":"9","name":"f-other"},"ipAddresses":["100.64.0.9"],"online":true}]}`

func TestListNodes(t *testing.T) {
	c, f := newFake(t, map[string]reply{
		"GET /api/v1/user": {200, oneUser("f-abc")},
		"GET /api/v1/node": {200, nodesJSON},
	})
	got, err := c.ListNodes(ctx, "f-abc")
	if err != nil {
		t.Fatal(err)
	}
	want := []Node{{"3", "box-a", "100.64.0.1", true}, {"4", "box-b", "", false}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	f.want(t, `GET /api/v1/user?name=f-abc`, `GET /api/v1/node?user=f-abc`)
}

func TestListNodesUnknownUserIsEmpty(t *testing.T) {
	c, _ := newFake(t, map[string]reply{"GET /api/v1/user": {200, noUsers}})
	got, err := c.ListNodes(ctx, "f-abc")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestDeleteNode(t *testing.T) {
	c, f := newFake(t, map[string]reply{
		"GET /api/v1/user":      {200, oneUser("f-abc")},
		"GET /api/v1/node":      {200, nodesJSON},
		"DELETE /api/v1/node/4": {200, `{}`},
	})
	if err := c.DeleteNode(ctx, "f-abc", "box-b"); err != nil {
		t.Fatal(err)
	}
	f.want(t, `GET /api/v1/user?name=f-abc`, `GET /api/v1/node?user=f-abc`, `DELETE /api/v1/node/4?`)
}

// Live on v0.29.7: two nodes of one user registered with the same hostname both come back with
// "name":"dup" (ids 1 and 2); only givenName differs ("dup", "dup-1").
const dupNodesJSON = `{"nodes":[
 {"id":"1","name":"dup","givenName":"dup","user":` + userJSON + `,"ipAddresses":["100.64.0.1"],"online":true},
 {"id":"2","name":"dup","givenName":"dup-1","user":` + userJSON + `,"ipAddresses":["100.64.0.2"],"online":true},
 {"id":"3","name":"other","givenName":"other","user":` + userJSON + `,"ipAddresses":[],"online":false}]}`

func TestDeleteNodeRemovesEveryNodeWithThatHostname(t *testing.T) {
	c, f := newFake(t, map[string]reply{
		"GET /api/v1/user":      {200, oneUser("f-abc")},
		"GET /api/v1/node":      {200, dupNodesJSON},
		"DELETE /api/v1/node/1": {200, `{}`},
		"DELETE /api/v1/node/2": {200, `{}`},
	})
	if err := c.DeleteNode(ctx, "f-abc", "dup"); err != nil {
		t.Fatal(err)
	}
	f.want(t, `GET /api/v1/user?name=f-abc`, `GET /api/v1/node?user=f-abc`, `DELETE /api/v1/node/1?`, `DELETE /api/v1/node/2?`)
}

func TestListNodesKeepsDuplicateHostnamesApartByID(t *testing.T) {
	c, _ := newFake(t, map[string]reply{
		"GET /api/v1/user": {200, oneUser("f-abc")},
		"GET /api/v1/node": {200, dupNodesJSON},
	})
	got, err := c.ListNodes(ctx, "f-abc")
	if err != nil || len(got) != 3 || got[0].ID != "1" || got[1].ID != "2" || got[0].Hostname != "dup" || got[1].Hostname != "dup" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestDeleteNodeByID(t *testing.T) {
	c, f := newFake(t, map[string]reply{"DELETE /api/v1/node/4": {200, `{}`}})
	if err := c.DeleteNodeByID(ctx, "4"); err != nil {
		t.Fatal(err)
	}
	f.want(t, `DELETE /api/v1/node/4?`)
}

func TestDeleteNodeByIDUnknownIsNotAnError(t *testing.T) {
	c, _ := newFake(t, map[string]reply{"DELETE /api/v1/node/99": {404, `{"code":5,"message":"node not found","details":[]}`}})
	if err := c.DeleteNodeByID(ctx, "99"); err != nil {
		t.Fatal(err)
	}
	c, _ = newFake(t, map[string]reply{"DELETE /api/v1/node/99": {500, `{"code":13,"message":"boom"}`}})
	if err := c.DeleteNodeByID(ctx, "99"); err == nil {
		t.Fatal("a 500 must stay an error")
	}
}

func TestDeleteNodeUnknownIsNotAnError(t *testing.T) {
	c, f := newFake(t, map[string]reply{
		"GET /api/v1/user": {200, oneUser("f-abc")},
		"GET /api/v1/node": {200, nodesJSON},
	})
	if err := c.DeleteNode(ctx, "f-abc", "ghost"); err != nil {
		t.Fatal(err)
	}
	f.want(t, `GET /api/v1/user?name=f-abc`, `GET /api/v1/node?user=f-abc`)
}

func TestSetPolicy(t *testing.T) {
	c, f := newFake(t, map[string]reply{"PUT /api/v1/policy": {200, `{"policy":"{\"acls\":[]}", "updatedAt":"2026-11-03T16:30:14.160336900Z"}`}})
	if err := c.SetPolicy(ctx, []byte(`{"acls":[]}`)); err != nil {
		t.Fatal(err)
	}
	var body struct{ Policy string }
	_ = json.Unmarshal([]byte(strings.SplitN(f.calls[0], " ", 3)[2]), &body)
	if body.Policy != `{"acls":[]}` {
		t.Fatalf("policy sent as %q", body.Policy)
	}
}

func TestSetPolicyRejectedByServer(t *testing.T) {
	c, _ := newFake(t, map[string]reply{"PUT /api/v1/policy": {500, `{"code":2, "message":"setting policy: parsing policy: parsing HuJSON: invalid literal: nope", "details":[]}`}})
	err := c.SetPolicy(ctx, []byte(`{nope`))
	var ae *APIError
	if !errors.As(err, &ae) || !strings.Contains(ae.Message, "parsing policy") {
		t.Fatalf("got %v", err)
	}
}

func TestBadAPIKeyAndNoSecretInErrors(t *testing.T) {
	c, _ := newFake(t, nil)
	c.apiKey = "wrong-key-123"
	err := c.CreateUser(ctx, "f-abc")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 401 {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "wrong-key-123") {
		t.Fatalf("api key leaked in error: %v", err)
	}
}

func TestUnreachableServer(t *testing.T) {
	c := New("http://127.0.0.1:1", "k", nil)
	if err := c.CreateUser(ctx, "f-abc"); err == nil {
		t.Fatal("want error")
	}
}
