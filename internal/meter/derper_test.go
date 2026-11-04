package meter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const testDebugKey = "s3cret-debug-key"

func TestDerperClientsFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/clients.json")
	if err != nil {
		t.Fatal(err)
	}
	var want struct {
		Clients []struct {
			Key              string
			ConnNum          int64
			ConnectedAt      time.Time
			RxBytes, TxBytes int64
		}
	}
	if err := json.Unmarshal(body, &want); err != nil || len(want.Clients) == 0 {
		t.Fatalf("fixture: %v", err)
	}
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		if r.URL.Path != "/debug/clients/" {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	}))
	defer srv.Close()

	conns, err := NewDerper(srv.URL, testDebugKey, srv.Client()).Clients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != len(want.Clients) {
		t.Fatalf("got %d conns, want %d", len(conns), len(want.Clients))
	}
	for i, w := range want.Clients {
		c := conns[i]
		if c.Key != w.Key || c.ConnNum != w.ConnNum || !c.ConnectedAt.Equal(w.ConnectedAt) || c.Rx != w.RxBytes || c.Tx != w.TxBytes {
			t.Errorf("conn %d = %+v, want %+v", i, c, w)
		}
	}
	for _, p := range []string{"all=1", "format=json", "limit=1000", "debugkey=" + testDebugKey} {
		if !strings.Contains(gotQuery, p) {
			t.Errorf("query %q lacks %q", gotQuery, p)
		}
	}

	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "debug access denied", http.StatusForbidden)
	}))
	defer denied.Close()
	if _, err := NewDerper(denied.URL, testDebugKey, denied.Client()).Clients(context.Background()); err == nil || strings.Contains(err.Error(), testDebugKey) {
		t.Fatalf("403: err = %v", err)
	}

	// A transport error is where net/http puts the whole URL, key included, in the message.
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	if _, err := NewDerper(gone.URL, testDebugKey, nil).Clients(context.Background()); err == nil || strings.Contains(err.Error(), testDebugKey) {
		t.Fatalf("unreachable: err = %v", err)
	}
}

func TestDerperPaginates(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		n, base := 1000, 0
		if r.URL.Query().Get("after") != "" {
			n, base = 3, 1000
		}
		var cl []map[string]any
		for i := 0; i < n; i++ {
			cl = append(cl, map[string]any{"key": fmt.Sprintf("nodekey:%064x", base+i), "connNum": base + i, "connectedAt": time.Unix(1, 0), "rxBytes": 1, "txBytes": 2})
		}
		json.NewEncoder(w).Encode(map[string]any{"clients": cl})
	}))
	defer srv.Close()

	conns, err := NewDerper(srv.URL, testDebugKey, srv.Client()).Clients(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(conns) != 1003 || len(queries) != 2 {
		t.Fatalf("got %d conns in %d requests, want 1003 in 2", len(conns), len(queries))
	}
	q := queries[1]
	if !strings.Contains(q, "after="+fmt.Sprintf("nodekey%%3A%064x", 999)) || !strings.Contains(q, "afterconn=999") {
		t.Fatalf("second request query = %q", q)
	}
}
