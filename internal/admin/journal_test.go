package admin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/journal"
)

// appendLines adds raw journal lines to dir/name.
func appendLines(t *testing.T, dir, name string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		t.Fatal(err)
	}
}

// journalFixture is the spec's example: enrolment and front files in one dir, share's in another.
func journalFixture(t *testing.T) *journal.Reader {
	d1, d2 := t.TempDir(), t.TempDir()
	appendLines(t, d2, "share-2026-11-04.jsonl",
		`{"time":"2026-11-04T09:00:00.000Z","src":"share","svc":"share","ip":"203.0.113.99","host":"old.box.example","act":"pass"}`,
		`{"time":"2026-11-04T11:42:07.000Z","src":"share","svc":"share","ip":"203.0.113.7","host":"jellyfin.mabox.box.example","act":"pass"}`,
		`{"time":"2026-11-04T11:42:07.500Z","src":"share","svc":"share","ip":"198.51.100.20","host":"nextcloud.autre.box.example","act":"cut","reason":"external","source":"FireHOL level 1"}`,
		`{"time":"2026-11-04T11:43:31.000Z","src":"share","svc":"share","ip":"203.0.113.7","host":"jellyfin.mabox.box.example","act":"close","ms":84000,"in":210000,"out":12400000}`)
	appendLines(t, d1, "front-2026-11-04.jsonl",
		`{"time":"2026-11-04T11:42:08.000Z","src":"front","svc":"front","ip":"192.0.2.10","host":"relay.example","method":"POST","path":"/v1/share/bans","status":204,"ms":12}`)
	appendLines(t, d1, "enrolment-2026-11-04.jsonl",
		`{"time":"2026-11-04T11:42:10.000Z","src":"relay","svc":"enrolment","ip":"203.0.113.50","event":"ban_open","msg":"community ban opened"}`,
		`{"time":"2026-11-04T11:44:02.000Z","src":"log","svc":"enrolment","msg":"list AbuseIPDB: download refused (429)"}`)
	return &journal.Reader{Dirs: []string{d1, d2}}
}

func (e env) withJournal(t *testing.T, r *journal.Reader) env {
	return e.withDeps(t, func(d *Deps) { d.JournalReader = r })
}

func get(t *testing.T, e env, path string) string {
	t.Helper()
	w := e.do("GET", path, token, nil)
	if w.Code != 200 {
		t.Fatalf("GET %s: %d %s", path, w.Code, w.Body)
	}
	return w.Body.String()
}

func TestJournalPageShowsMergedLines(t *testing.T) {
	e := setup(t).withJournal(t, journalFixture(t))
	body := get(t, e, "/admin/journal")
	order := []string{"list AbuseIPDB: download refused (429)", "closed · 84 s · ↓ 12.4 MB ↑ 210.0 kB", "ban_open · community ban opened",
		"POST /v1/share/bans · 204 · 12 ms", "cut · external · FireHOL level 1", "passed"}
	last := -1
	for _, s := range order {
		i := strings.Index(body, s)
		if i < 0 {
			t.Fatalf("page lacks %q", s)
		}
		if i < last {
			t.Errorf("%q is out of order (newest first)", s)
		}
		last = i
	}
	if strings.Contains(body, "old.box.example") {
		t.Error("a line older than the last hour is shown")
	}
	if n := strings.Count(body, `class="ln `); n != 6 {
		t.Errorf("%d lines, want 6", n)
	}
	if !strings.Contains(body, `id="feed" data-live`) {
		t.Error("the last hour is not live")
	}
	for _, p := range []string{"/admin/", "/admin/protection"} {
		if !strings.Contains(get(t, e, p), `href="/admin/journal"`) {
			t.Errorf("%s has no Journal link", p)
		}
	}
}

func TestJournalFilters(t *testing.T) {
	e := setup(t).withJournal(t, journalFixture(t))
	for _, c := range []struct {
		query     string
		want, not []string
	}{
		{"src=front", []string{"/v1/share/bans"}, []string{"AbuseIPDB", "passed", "ban_open"}},
		{"src=share&src=relay", []string{"passed", "ban_open"}, []string{"AbuseIPDB", "/v1/share/bans"}},
		{"q=198.51", []string{"FireHOL"}, []string{"jellyfin", "AbuseIPDB"}},
		{"problems=1", []string{"FireHOL", "AbuseIPDB"}, []string{"passed", "/v1/share/bans"}},
		{"range=6h", []string{"old.box.example", "AbuseIPDB"}, nil},
		{"src=bogus", []string{"passed", "AbuseIPDB"}, nil}, // an unknown source is ignored
	} {
		body := get(t, e, "/admin/journal?"+c.query)
		for _, s := range c.want {
			if !strings.Contains(body, s) {
				t.Errorf("%s: page lacks %q", c.query, s)
			}
		}
		for _, s := range c.not {
			if strings.Contains(body, s) {
				t.Errorf("%s: page shows %q", c.query, s)
			}
		}
	}
	if body := get(t, e, "/admin/journal?range=6h"); strings.Contains(body, `id="feed" data-live`) {
		t.Error("live outside the last hour")
	}
	if w := e.do("GET", "/admin/journal?q="+strings.Repeat("a", 201), token, nil); w.Code != 400 {
		t.Errorf("an overlong search: %d", w.Code)
	}
}

var olderHref = regexp.MustCompile(`id="older" href="([^"]*)"`)

// lines writes n share lines 100 ms apart ending 10 min before t0, hosts h000…, every line the same length.
func lines(n int) []string {
	out := make([]string, n)
	for i := range out {
		at := t0.Add(-10*time.Minute - time.Duration(n-1-i)*100*time.Millisecond).UTC().Format("2006-01-02T15:04:05.000Z")
		out[i] = fmt.Sprintf(`{"time":"%s","src":"share","svc":"share","ip":"203.0.113.7","host":"h%03d.box.example","act":"pass"}`, at, i)
	}
	return out
}

func TestJournalOlder(t *testing.T) {
	dir := t.TempDir()
	appendLines(t, dir, "share-2026-11-04.jsonl", lines(250)...)
	e := setup(t).withJournal(t, &journal.Reader{Dirs: []string{dir}})
	body := get(t, e, "/admin/journal")
	if n := strings.Count(body, `class="ln `); n != 200 {
		t.Fatalf("first page: %d lines", n)
	}
	if !strings.Contains(body, "h249.") || !strings.Contains(body, "h050.") || strings.Contains(body, "h049.") {
		t.Fatal("first page is not the newest 200")
	}
	m := olderHref.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no Older link")
	}
	body = get(t, e, "/admin/journal"+html.UnescapeString(m[1]))
	if n := strings.Count(body, `class="ln `); n != 50 || !strings.Contains(body, "h049.") || !strings.Contains(body, "h000.") {
		t.Fatalf("second page: %d lines", n)
	}
	if olderHref.MatchString(body) || strings.Contains(body, `id="feed" data-live`) {
		t.Error("the last page offers Older, or is live")
	}
}

func TestJournalPartialSearch(t *testing.T) {
	all := lines(300)
	size := int64(len(all[0]) + 1)
	dir := t.TempDir()
	appendLines(t, dir, "share-2026-11-04.jsonl", all...)
	const empty = "The search stopped before finding anything: narrow the period or the filters."
	for _, c := range []struct {
		name, query     string
		budget          int64
		lines           int
		older, searchOn bool
		emptyNote       bool
	}{
		{"nothing found", "?q=nomatch", 1, 0, false, true, true},
		{"some found", "", 10*size + size/2, 10, false, true, false},
		{"full page", "", 200*size + size/2, 200, true, false, false}, // stopped only on the read-ahead: not incomplete
	} {
		e := setup(t).withJournal(t, &journal.Reader{Dirs: []string{dir}, MaxBytes: c.budget})
		body := get(t, e, "/admin/journal"+c.query)
		if n := strings.Count(body, `class="ln `); n != c.lines {
			t.Errorf("%s: %d lines, want %d", c.name, n, c.lines)
		}
		if got := olderHref.MatchString(body); got != c.older {
			t.Errorf("%s: Older offered %v", c.name, got)
		}
		if got := strings.Contains(body, ">Search on<"); got != c.searchOn {
			t.Errorf("%s: Search on offered %v", c.name, got)
		}
		if got := strings.Contains(body, empty); got != c.emptyNote {
			t.Errorf("%s: empty note %v", c.name, got)
		}
	}
}

func TestJournalNeedsAuth(t *testing.T) {
	e := setup(t).withJournal(t, journalFixture(t))
	for _, p := range []string{"/admin/journal", "/admin/journal/stream"} {
		if w := e.do("GET", p, "", nil); w.Code != 401 {
			t.Errorf("%s without the token: %d", p, w.Code)
		}
		if w := e.do("GET", p, "wrong", nil); w.Code != 401 {
			t.Errorf("%s with a wrong token: %d", p, w.Code)
		}
	}
}

func TestJournalOff(t *testing.T) {
	e := setup(t) // no reader
	if body := get(t, e, "/admin/journal"); !strings.Contains(body, "LOG_READ_DIRS") {
		t.Error("the page does not say the journal is off")
	}
	if w := e.do("GET", "/admin/journal/stream", token, nil); w.Code != 404 {
		t.Errorf("stream without a reader: %d", w.Code)
	}
}

func TestJournalEscapesHTML(t *testing.T) {
	dir := t.TempDir()
	appendLines(t, dir, "share-2026-11-04.jsonl",
		`{"time":"2026-11-04T11:50:00.000Z","src":"share","ip":"203.0.113.7","host":"<script>alert(1)</script>","act":"cut","reason":"<b>x</b>"}`)
	body := get(t, setup(t).withJournal(t, &journal.Reader{Dirs: []string{dir}}), "/admin/journal")
	if strings.Contains(body, "<script>alert") || strings.Contains(body, "<b>x") {
		t.Fatal("entry text reached the page unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Fatal("the escaped host is missing")
	}
}

// stream opens the journal stream on a real server and returns its lines as they come.
func stream(t *testing.T, srv *httptest.Server, query string) <-chan string {
	t.Helper()
	req, _ := http.NewRequest("GET", srv.URL+"/admin/journal/stream"+query, nil)
	req.SetBasicAuth("admin", token)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	out := make(chan string, 4096)
	go func() {
		defer close(out)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			out <- sc.Text()
		}
	}()
	return out
}

func shareLine(host string) string {
	return fmt.Sprintf(`{"time":"%s","src":"share","svc":"share","ip":"203.0.113.7","host":"%s","act":"pass"}`,
		time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), host)
}

// probe appends a line until the stream shows it: Follow takes what exists at its first pass as old.
func probe(t *testing.T, dir string, lines <-chan string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		appendLines(t, dir, "share-x.jsonl", shareLine("probe.example"))
		wait := time.After(100 * time.Millisecond)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatal("stream closed")
				}
				if strings.HasPrefix(l, "data:") && strings.Contains(l, "probe.example") {
					return
				}
				continue
			case <-wait:
			case <-deadline:
				t.Fatal("no line came through the stream")
			}
			break
		}
	}
}

func TestJournalStreamSendsNewLines(t *testing.T) {
	defer func(d time.Duration) { streamHeartbeat = d }(streamHeartbeat)
	streamHeartbeat = 100 * time.Millisecond
	dir := t.TempDir()
	e := setup(t).withJournal(t, &journal.Reader{Dirs: []string{dir}})
	srv := httptest.NewUnstartedServer(e.h)
	// The relay's server has both timeouts: a stream must outlive them.
	srv.Config.ReadTimeout, srv.Config.WriteTimeout = 300*time.Millisecond, 300*time.Millisecond
	srv.Start()
	t.Cleanup(srv.Close) // after the stream's body is closed (cleanups run last first)
	got := stream(t, srv, "?src=share&range=6h&before=2026-11-04T00:00:00.000Z")
	time.Sleep(time.Second)
	heartbeat := false
	deadline := time.After(5 * time.Second)
	for {
		appendLines(t, dir, "front-x.jsonl", strings.Replace(strings.Replace(shareLine("front.example"), `"share"`, `"front"`, 2), `"act":"pass"`, `"status":200`, 1))
		appendLines(t, dir, "share-x.jsonl", shareLine("visitor.example"))
		select {
		case <-deadline:
			t.Fatal("no line came through the stream")
		case <-time.After(100 * time.Millisecond):
		}
	drain:
		for {
			select {
			case l, ok := <-got:
				if !ok {
					t.Fatal("stream closed")
				}
				heartbeat = heartbeat || strings.HasPrefix(l, ":")
				if !strings.HasPrefix(l, "data:") {
					continue
				}
				var line struct {
					journal.Entry
					Text string `json:"text"`
				}
				if err := json.Unmarshal([]byte(strings.TrimPrefix(l, "data:")), &line); err != nil {
					t.Fatalf("%q: %v", l, err)
				}
				if line.Host != "visitor.example" || line.Text != "passed" {
					t.Fatalf("got %+v, want the share line only", line)
				}
				if !heartbeat {
					t.Error("no heartbeat comment")
				}
				return
			default:
				break drain
			}
		}
	}
}

func TestJournalStreamRateLimit(t *testing.T) {
	dir := t.TempDir()
	e := setup(t).withJournal(t, &journal.Reader{Dirs: []string{dir}})
	srv := httptest.NewServer(e.h)
	t.Cleanup(srv.Close) // after the stream's body is closed (cleanups run last first)
	got := stream(t, srv, "")
	probe(t, dir, got)
	burst := make([]string, 1000)
	for i := range burst {
		burst[i] = shareLine(fmt.Sprintf("b%04d.example", i))
	}
	appendLines(t, dir, "share-x.jsonl", burst...)
	var first time.Time
	sent, inFirstSecond, dropped := 0, 0, 0
	deadline := time.After(5 * time.Second)
	for sent+dropped < 1000 {
		select {
		case <-deadline:
			t.Fatalf("sent %d, dropped %d: not all 1000 accounted for", sent, dropped)
		case l := <-got:
			switch {
			case strings.HasPrefix(l, `data: {"dropped":`):
				var d struct{ Dropped int }
				json.Unmarshal([]byte(strings.TrimPrefix(l, "data:")), &d)
				dropped += d.Dropped
			case strings.HasPrefix(l, "data:"):
				if first.IsZero() {
					first = time.Now()
				}
				sent++
				if time.Since(first) < time.Second {
					inFirstSecond++
				}
			}
		}
	}
	if inFirstSecond > 200 || dropped == 0 {
		t.Fatalf("%d lines in the first second, %d dropped", inFirstSecond, dropped)
	}
}
