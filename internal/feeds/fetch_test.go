package feeds

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

type env struct {
	st  store.Store
	f   *Fetcher
	now time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/r.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{st: st, now: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
	e.f = &Fetcher{Store: st, Dir: filepath.Join(t.TempDir(), "feeds"), Now: func() time.Time { return e.now }, TotalMax: 1000}
	return e
}

func (e *env) add(t *testing.T, f store.Feed) int64 {
	t.Helper()
	if f.Name == "" {
		f.Name = "f"
	}
	if f.Format == "" {
		f.Format = "text"
	}
	if f.EverySec == 0 {
		f.EverySec = 3600
	}
	if f.MaxEntries == 0 {
		f.MaxEntries = 100
	}
	f.Enabled = true
	id, err := e.st.AddFeed(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) feed(t *testing.T, id int64) store.Feed {
	t.Helper()
	fs, _ := e.st.Feeds(context.Background())
	for _, f := range fs {
		if f.ID == id {
			return f
		}
	}
	t.Fatal("no feed")
	return store.Feed{}
}

func TestFeedHTMLPageKeepsLastCopy(t *testing.T) {
	body := "1.1.1.1\n2.2.2.2\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer srv.Close()
	e := newEnv(t)
	id := e.add(t, store.Feed{URL: srv.URL})
	if err := e.f.Refresh(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	body = "<html><body>captcha</body></html>"
	if err := e.f.Refresh(context.Background(), id); err == nil {
		t.Fatal("want error")
	}
	f := e.feed(t, id)
	if !strings.Contains(f.LastError, ErrEmpty.Error()) || f.Count != 2 {
		t.Fatalf("%+v", f)
	}
	got, err := e.f.Load(id)
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestFeed500KeepsLastCopy(t *testing.T) {
	code := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		w.Write([]byte("1.1.1.1\n"))
	}))
	defer srv.Close()
	e := newEnv(t)
	id := e.add(t, store.Feed{URL: srv.URL})
	if err := e.f.Refresh(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	code = 500
	if err := e.f.Refresh(context.Background(), id); err == nil {
		t.Fatal("want error")
	}
	f := e.feed(t, id)
	if !strings.Contains(f.LastError, "500") || f.Count != 1 {
		t.Fatalf("%+v", f)
	}
	if got, err := e.f.Load(id); err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestFeedNotDueIsSkipped(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("1.1.1.1\n")) }))
	defer srv.Close()
	e := newEnv(t)
	id := e.add(t, store.Feed{URL: srv.URL, EverySec: 3600})
	e.st.FeedResult(context.Background(), id, e.now.Add(-10*time.Minute), 0, "boom")
	e.f.Tick(context.Background())
	if hits.Load() != 0 {
		t.Fatal("requested a feed that is not due")
	}
	e.now = e.now.Add(51 * time.Minute)
	e.f.Tick(context.Background())
	if hits.Load() != 1 {
		t.Fatalf("hits %d", hits.Load())
	}
}

// Tick reports whether a copy was replaced: the snapshot is rebuilt only then.
func TestTickReportsReplacedCopy(t *testing.T) {
	code := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
		w.Write([]byte("1.1.1.1\n"))
	}))
	defer srv.Close()
	e := newEnv(t)
	e.add(t, store.Feed{URL: srv.URL, EverySec: 3600})
	if !e.f.Tick(context.Background()) {
		t.Fatal("first download: no change reported")
	}
	if e.f.Tick(context.Background()) {
		t.Fatal("not due, yet changed")
	}
	code = 500
	e.now = e.now.Add(time.Hour)
	if e.f.Tick(context.Background()) {
		t.Fatal("failed download reported a change")
	}
}

func TestFailureSetsLastTry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	e := newEnv(t)
	id := e.add(t, store.Feed{URL: srv.URL})
	e.f.Tick(context.Background())
	if f := e.feed(t, id); !f.LastTry.Equal(e.now) {
		t.Fatalf("last_try %v", f.LastTry)
	}
}

func TestTotalCapRefusesWholeFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("1.1.1.1\n2.2.2.2\n")) }))
	defer srv.Close()
	e := newEnv(t)
	e.f.TotalMax = 10
	other := e.add(t, store.Feed{Name: "other", URL: srv.URL})
	e.st.FeedResult(context.Background(), other, e.now, 9, "")
	id := e.add(t, store.Feed{URL: srv.URL})
	err := e.f.Refresh(context.Background(), id)
	if err == nil || !strings.Contains(err.Error(), "total cap reached") {
		t.Fatalf("err = %v", err)
	}
	if _, serr := os.Stat(filepath.Join(e.f.Dir, "2.txt")); serr == nil {
		t.Fatal("file written")
	}
}

func TestAuthHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone(); w.Write([]byte("1.1.1.1\n")) }))
	defer srv.Close()
	e := newEnv(t)
	id := e.add(t, store.Feed{URL: srv.URL, AuthName: "Key", AuthValue: "k", Preset: "abuseipdb"})
	if err := e.f.Refresh(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if got.Get("Key") != "k" || got.Get("Accept") != "text/plain" || got.Get("User-Agent") != "recasaos-relay" {
		t.Fatalf("%v", got)
	}
	id = e.add(t, store.Feed{Name: "cs", URL: srv.URL, AuthName: "Authorization-Basic", AuthValue: "user:pw", Preset: "crowdsec"})
	if err := e.f.Refresh(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pw")); got.Get("Authorization") != want {
		t.Fatalf("%v", got)
	}
}

func TestErrorsDoNotLeakAuthOrURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL + "/x?apikey=SECRET"
	srv.Close() // connection refused
	e := newEnv(t)
	id := e.add(t, store.Feed{URL: url, AuthName: "Key", AuthValue: "SECRET"})
	err := e.f.Refresh(context.Background(), id)
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(e.feed(t, id).LastError, "SECRET") {
		t.Fatalf("err = %v", err)
	}
}

func TestForgetRemovesCopy(t *testing.T) {
	e := newEnv(t)
	if err := e.f.Forget(7); err != nil {
		t.Fatalf("missing copy: %v", err)
	}
	if err := os.MkdirAll(e.f.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(e.f.Dir, "7.txt")
	if err := os.WriteFile(p, []byte("192.0.2.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.f.Forget(7); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("copy still there: %v", err)
	}
}

// A redirect may only lead to https, and the feed's own header never follows it to another host.
func TestRedirectsStayHTTPSAndKeepAuthOnHost(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { plainHits.Add(1); w.Write([]byte("1.1.1.1\n")) }))
	defer plain.Close()
	var got http.Header
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone(); w.Write([]byte("1.1.1.1\n")) }))
	defer other.Close()
	var target string
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+"/list?apikey=SECRET", http.StatusFound)
	}))
	defer src.Close()
	e := newEnv(t)
	e.f.Client = src.Client() // trusts every httptest TLS server

	target = plain.URL
	id := e.add(t, store.Feed{Name: "down", URL: src.URL, AuthName: "Key", AuthValue: "SECRET"})
	err := e.f.Refresh(context.Background(), id)
	if err == nil || plainHits.Load() != 0 || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("redirect to http: err %v, %d plain hits", err, plainHits.Load())
	}

	target = other.URL
	for _, f := range []store.Feed{
		{Name: "key", URL: src.URL + "/list?key=SECRET", AuthName: "Key", AuthValue: "SECRET"},
		{Name: "basic", URL: src.URL + "/list?key=SECRET", AuthName: "Authorization-Basic", AuthValue: "user:SECRET"},
	} {
		got = nil
		if err := e.f.Refresh(context.Background(), e.add(t, f)); err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		if got == nil || got.Get("Key") != "" || got.Get("Authorization") != "" || got.Get("Referer") != "" {
			t.Fatalf("%s: the other host got %v", f.Name, got)
		}
	}
}
