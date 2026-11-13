package journal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func at(ms int) time.Time        { return noon.Add(time.Duration(ms) * time.Millisecond) }
func stampOf(t time.Time) string { return t.UTC().Format(timeLayout) }

// appendLines appends raw lines (each followed by \n) to name.
func appendLines(t *testing.T, name string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

func jsonLine(e Entry) string {
	b, _ := json.Marshal(e)
	return string(b)
}

func caddyLineAt(ts time.Time, ip, method, uri string, status int) string {
	return fmt.Sprintf(`{"level":"info","ts":%.3f,"logger":"http.log.access","msg":"handled request",`+
		`"request":{"remote_ip":"172.29.0.10","remote_port":"41000","client_ip":%q,"proto":"HTTP/1.1","method":%q,`+
		`"host":"relay.example.org","uri":%q,"headers":{"Authorization":["Bearer s3cr3t-t0ken"],"Cookie":["sid=c00kie"]}},`+
		`"bytes_read":42,"user_id":"","duration":0.012,"size":120,"status":%d,"resp_headers":{"Set-Cookie":["sid=c00kie"]}}`,
		float64(ts.UnixMilli())/1000, ip, method, uri, status)
}

func page(t *testing.T, r *Reader, q Query, before time.Time, n int) ([]Entry, bool, bool) {
	t.Helper()
	es, more, partial, _, err := r.Page(context.Background(), q, before, n)
	if err != nil {
		t.Fatal(err)
	}
	return es, more, partial
}

func times(es []Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Time)
	}
	return out
}

func stamps(ms ...int) []string {
	var out []string
	for _, m := range ms {
		out = append(out, stampOf(at(m)))
	}
	return out
}

func setChunk(t *testing.T, n int) {
	old := readChunk
	readChunk = n
	t.Cleanup(func() { readChunk = old })
}

func TestPageMergesWriters(t *testing.T) {
	share, enrol, front := t.TempDir(), t.TempDir(), t.TempDir()
	appendLines(t, filepath.Join(share, "share-2026-11-13.jsonl"),
		jsonLine(Entry{Time: stampOf(at(0)), Src: "share", Svc: "share", Act: "pass", IP: "198.51.100.1", Host: "nas.example.org"}),
		jsonLine(Entry{Time: stampOf(at(3)), Src: "share", Svc: "share", Act: "close", Ms: 5}),
		`{"time":"2026-11-13T12:00:00.004Z","src":"sha`, // a partial line left by a full disk
		`not json at all`,
		jsonLine(Entry{Time: stampOf(at(6)), Src: "share", Svc: "share", Act: "pass"}))
	appendLines(t, filepath.Join(enrol, "enrolment-2026-11-13.jsonl"),
		jsonLine(Entry{Time: stampOf(at(1)), Src: "relay", Svc: "enrolment", Event: "ban_open"}),
		jsonLine(Entry{Time: stampOf(at(4)), Src: "log", Svc: "enrolment", Msg: "tunnel up"}))
	appendLines(t, filepath.Join(front, "front.log"),
		caddyLineAt(at(2), "203.0.113.7", "GET", "/a", 200),
		caddyLineAt(at(5), "203.0.113.8", "PUT", "/v1/share/protection", 200))
	// The live line being written has no newline yet.
	f, _ := os.OpenFile(filepath.Join(front, "front.log"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"level":"info","ts":`)
	f.Close()

	for _, chunk := range []int{3, 7, 64 << 10} {
		t.Run(fmt.Sprint("chunk ", chunk), func(t *testing.T) {
			setChunk(t, chunk)
			r := &Reader{Dirs: []string{share, enrol, front, filepath.Join(front, "missing")}}
			es, more, partial := page(t, r, Query{}, time.Time{}, 10)
			if want := stamps(6, 5, 4, 3, 2, 1, 0); !slices.Equal(times(es), want) || more || partial {
				t.Fatalf("got %v more=%v partial=%v, want %v", times(es), more, partial, want)
			}
			if c := es[1]; c.Src != "front" || c.Svc != "front" || c.IP != "203.0.113.8" || c.Host != "relay.example.org" ||
				c.Method != "PUT" || c.Path != "/v1/share/protection" || c.Status != 200 || c.Ms != 12 || c.In != 42 || c.Out != 120 {
				t.Fatalf("caddy entry %+v", c)
			}
			es, more, _ = page(t, r, Query{}, time.Time{}, 3)
			if want := stamps(6, 5, 4); !slices.Equal(times(es), want) || !more {
				t.Fatalf("n=3: got %v more=%v", times(es), more)
			}
		})
	}
}

func TestPageFilters(t *testing.T) {
	share, enrol, front := t.TempDir(), t.TempDir(), t.TempDir()
	appendLines(t, filepath.Join(share, "share-2026-11-13.jsonl"),
		jsonLine(Entry{Time: stampOf(at(0)), Src: "share", Act: "pass", IP: "203.0.113.7", Host: "nas.example.org"}),
		jsonLine(Entry{Time: stampOf(at(1)), Src: "share", Act: "cut", IP: "198.51.100.9", Reason: "abuse", Source: "spamhaus"}))
	appendLines(t, filepath.Join(enrol, "enrolment-2026-11-13.jsonl"),
		jsonLine(Entry{Time: stampOf(at(2)), Src: "log", Msg: "feed failed"}),
		jsonLine(Entry{Time: stampOf(at(3)), Src: "relay", Event: "feed_ok", Msg: "ok"}))
	// Caddy's lines as enrolment's ingest writes them: our format, src front.
	appendLines(t, filepath.Join(enrol, "front-2026-11-13.jsonl"),
		jsonLine(Entry{Time: stampOf(at(6)), Src: "front", Svc: "front", IP: "192.0.2.6", Path: "/ingested", Status: 200}))
	appendLines(t, filepath.Join(front, "front.log"),
		caddyLineAt(at(4), "192.0.2.4", "GET", "/ok", 200),
		caddyLineAt(at(5), "192.0.2.5", "GET", "/missing", 404))
	r := &Reader{Dirs: []string{share, enrol, front}}
	for _, c := range []struct {
		name string
		q    Query
		want []string
	}{
		{"src front", Query{Src: []string{"front"}}, stamps(6, 5, 4)},
		{"src share+relay", Query{Src: []string{"share", "relay"}}, stamps(3, 1, 0)},
		{"text source", Query{Text: "SPAMHAUS"}, stamps(1)},
		{"text path", Query{Text: "missing"}, stamps(5)},
		{"text host", Query{Text: "NAS.Example"}, stamps(0)},
		{"text event", Query{Text: "feed_ok"}, stamps(3)},
		{"text ip", Query{Text: "198.51.100"}, stamps(1)},
		{"text never searches headers", Query{Text: "s3cr3t"}, nil},
		{"problems", Query{Problems: true}, stamps(5, 2, 1)},
		{"problems share", Query{Problems: true, Src: []string{"share"}}, stamps(1)},
		{"from to", Query{From: at(2), To: at(4)}, stamps(4, 3, 2)},
	} {
		t.Run(c.name, func(t *testing.T) {
			es, _, _ := page(t, r, c.q, time.Time{}, 100)
			if !slices.Equal(times(es), c.want) {
				t.Fatalf("got %v, want %v", times(es), c.want)
			}
		})
	}
}

func TestPageBefore(t *testing.T) {
	share, front := t.TempDir(), t.TempDir()
	appendLines(t, filepath.Join(share, "share-2026-11-12.jsonl"),
		jsonLine(Entry{Time: stampOf(noon.Add(-24 * time.Hour)), Src: "share"}))
	var want []string
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			appendLines(t, filepath.Join(share, "share-2026-11-13.jsonl"), jsonLine(Entry{Time: stampOf(at(i)), Src: "share"}))
		} else {
			appendLines(t, filepath.Join(front, "front.log"), caddyLineAt(at(i), "192.0.2.1", "GET", "/", 200))
		}
		want = append([]string{stampOf(at(i))}, want...)
	}
	want = append(want, stampOf(noon.Add(-24*time.Hour)))
	setChunk(t, 50)
	r := &Reader{Dirs: []string{share, front}}
	var got []string
	before := time.Time{}
	for pages := 0; ; pages++ {
		es, more, partial := page(t, r, Query{}, before, 6)
		if partial || pages > 10 {
			t.Fatalf("partial=%v after %d pages", partial, pages)
		}
		got = append(got, times(es)...)
		if !more {
			break
		}
		before, _ = time.Parse(timeLayout, es[len(es)-1].Time)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestPageStopsAtBudget(t *testing.T) {
	big := t.TempDir()
	var lines []string
	for i := 0; i < 20000; i++ {
		lines = append(lines, jsonLine(Entry{Time: stampOf(at(i)), Src: "share", Act: "pass", IP: "203.0.113.7", Host: "nas.example.org"}))
	}
	appendLines(t, filepath.Join(big, "share-2026-11-13.jsonl"), lines...)

	t.Run("bytes", func(t *testing.T) {
		r := &Reader{Dirs: []string{big}, MaxBytes: 64 << 10}
		es, more, partial := page(t, r, Query{}, time.Time{}, 1000)
		if !partial || !more || len(es) == 0 || len(es) >= 20000 || es[0].Time != stampOf(at(19999)) {
			t.Fatalf("partial=%v more=%v len=%d first=%v", partial, more, len(es), es[0].Time)
		}
		for i := 1; i < len(es); i++ {
			if es[i].Time >= es[i-1].Time {
				t.Fatalf("not newest first at %d", i)
			}
		}
	})
	t.Run("time", func(t *testing.T) {
		c := newClock(noon)
		r := &Reader{Dirs: []string{big}, Now: func() time.Time { c.set(c.now().Add(time.Second)); return c.now() }}
		_, more, partial := page(t, r, Query{Text: "no such text"}, time.Time{}, 1000)
		if !partial || !more {
			t.Fatalf("partial=%v more=%v", partial, more)
		}
	})
	t.Run("before deep in a large file", func(t *testing.T) {
		r := &Reader{Dirs: []string{big}, MaxBytes: 256 << 10}
		es, _, partial := page(t, r, Query{}, at(100), 50)
		if partial || len(es) != 50 || es[0].Time != stampOf(at(99)) || es[49].Time != stampOf(at(50)) {
			t.Fatalf("partial=%v len=%d", partial, len(es))
		}
		es, _, partial = page(t, r, Query{To: at(100)}, time.Time{}, 1)
		if partial || len(es) != 1 || es[0].Time != stampOf(at(100)) {
			t.Fatalf("To: partial=%v %v", partial, times(es))
		}
	})
	t.Run("files outside From are not read", func(t *testing.T) {
		dir := t.TempDir()
		appendLines(t, filepath.Join(dir, "share-2026-11-12.jsonl"), lines...)
		appendLines(t, filepath.Join(dir, "front-2026-11-12T23-00-00.000.log"), lines...)
		old := noon.Add(-13 * time.Hour)
		os.Chtimes(filepath.Join(dir, "front-2026-11-12T23-00-00.000.log"), old, old)
		appendLines(t, filepath.Join(dir, "share-2026-11-13.jsonl"), jsonLine(Entry{Time: stampOf(at(1)), Src: "share"}))
		r := &Reader{Dirs: []string{dir}, MaxBytes: 64 << 10}
		es, _, partial := page(t, r, Query{From: noon.Add(-time.Hour)}, time.Time{}, 10)
		if partial || !slices.Equal(times(es), stamps(1)) {
			t.Fatalf("partial=%v %v", partial, times(es))
		}
	})
}

func TestFollowSeesNewLinesAndNewDayFile(t *testing.T) {
	old := followEvery
	followEvery = 10 * time.Millisecond
	t.Cleanup(func() { followEvery = old })
	share, front := t.TempDir(), t.TempDir()
	day1 := filepath.Join(share, "share-2026-11-13.jsonl")
	day2 := filepath.Join(share, "share-2026-11-14.jsonl")
	frontLog := filepath.Join(front, "front.log")
	appendLines(t, day1, jsonLine(Entry{Time: stampOf(at(0)), Src: "share", Msg: "old"}))
	appendLines(t, frontLog, caddyLineAt(at(0), "192.0.2.1", "GET", "/old", 200))

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan Entry, 100)
	done := make(chan struct{})
	go func() {
		(&Reader{Dirs: []string{share, front}}).Follow(ctx, Query{Src: []string{"share", "front"}}, out)
		close(done)
	}()
	defer func() { cancel(); <-done }()

	recv := func(want string) {
		t.Helper()
		select {
		case e := <-out:
			if got := e.Msg + e.Path; got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no %q", want)
		}
	}
	// Probe until Follow has taken its first look; lines before it are not sent.
	for i := 0; ; i++ {
		p := fmt.Sprint("probe", i)
		appendLines(t, day1, jsonLine(Entry{Time: stampOf(at(1)), Src: "share", Msg: p}))
		select {
		case e := <-out:
			if !strings.HasPrefix(e.Msg, "probe") {
				t.Fatalf("sent a line written before Follow: %+v", e)
			}
		case <-time.After(50 * time.Millisecond):
			continue
		}
		break
	}
	for len(out) > 0 { // late probes
		<-out
	}
	time.Sleep(30 * time.Millisecond)
	for len(out) > 0 {
		<-out
	}

	appendLines(t, day1, jsonLine(Entry{Time: stampOf(at(2)), Src: "share", Msg: "new"}),
		jsonLine(Entry{Time: stampOf(at(2)), Src: "relay", Msg: "filtered out"}))
	recv("new")
	appendLines(t, day2, jsonLine(Entry{Time: stampOf(at(3)), Src: "share", Msg: "day two " + strings.Repeat("x", 200)}))
	recv("day two " + strings.Repeat("x", 200))

	// Caddy rolls: the current file is renamed and a new one started.
	appendLines(t, frontLog, caddyLineAt(at(4), "192.0.2.1", "GET", "/before-roll", 200))
	if err := os.Rename(frontLog, filepath.Join(front, "front-2026-11-13T12-00-00.004.log")); err != nil {
		t.Fatal(err)
	}
	appendLines(t, frontLog, caddyLineAt(at(5), "192.0.2.1", "GET", "/after-roll", 200))
	var got []string
	for i := 0; i < 2; i++ {
		select {
		case e := <-out:
			got = append(got, e.Path)
		case <-time.After(5 * time.Second):
			t.Fatalf("roll: got only %v", got)
		}
	}
	if slices.Sort(got); !slices.Equal(got, []string{"/after-roll", "/before-roll"}) {
		t.Fatalf("roll: got %v", got)
	}

	// The writer starts a file over: shorter than what Follow has read.
	if err := os.Truncate(day2, 0); err != nil {
		t.Fatal(err)
	}
	appendLines(t, day2, jsonLine(Entry{Time: stampOf(at(6)), Src: "share", Msg: "t"}))
	recv("t")

	time.Sleep(100 * time.Millisecond)
	if len(out) > 0 {
		t.Fatalf("extra line sent: %+v", <-out)
	}
}

func TestCaddyLineDropsHeaders(t *testing.T) {
	line := `{"level":"info","ts":1763030400.123,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"172.29.0.10","remote_port":"41000","client_ip":"203.0.113.7","proto":"HTTP/1.1","method":"PUT","host":"relay.example.org","uri":"/v1/share/protection","headers":{"Authorization":["Bearer s3cr3t-t0ken"],"Cookie":["sid=c00kie"],"X-Box-Signature":["s1gn"]}},"bytes_read":42,"user_id":"","duration":0.0126,"size":120,"status":200,"resp_headers":{"Set-Cookie":["sid=c00kie"]}}`
	e, ok := ParseCaddy([]byte(line))
	if !ok {
		t.Fatal("not parsed")
	}
	want := Entry{Time: "2025-11-13T10:40:00.123Z", Src: "front", Svc: "front", IP: "203.0.113.7", Host: "relay.example.org",
		Method: "PUT", Path: "/v1/share/protection", Status: 200, Ms: 13, In: 42, Out: 120}
	if e != want {
		t.Fatalf("got %+v\nwant %+v", e, want)
	}
	b, _ := json.Marshal(e)
	for _, secret := range []string{"s3cr3t", "Authorization", "c00kie", "s1gn", "172.29.0.10"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("%q in %s", secret, b)
		}
	}
	for _, bad := range []string{`{}`, `{"ts":1763030400}`, `{"request":{"method":"GET"}}`, `{"ts":`, ``} {
		if _, ok := ParseCaddy([]byte(bad)); ok {
			t.Fatalf("%q parsed", bad)
		}
	}
}

func TestBusy(t *testing.T) {
	pageSem <- struct{}{}
	defer func() { <-pageSem }()
	start := time.Now()
	_, _, _, _, err := (&Reader{Dirs: []string{t.TempDir()}}).Page(context.Background(), Query{}, time.Time{}, 10)
	if !errors.Is(err, ErrBusy) || time.Since(start) < 900*time.Millisecond {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
}

// A filtered page must not spend the budget on the first-listed file while a
// newer match sits in another.
func TestPageFilteredBudgetFollowsTime(t *testing.T) {
	share, enrol, front := t.TempDir(), t.TempDir(), t.TempDir()
	var lines []string
	for i := 0; i < 20000; i++ {
		lines = append(lines, jsonLine(Entry{Time: stampOf(at(i)), Src: "share", Act: "pass", IP: "203.0.113.7", Host: "nas.example.org"}))
	}
	appendLines(t, filepath.Join(share, "share-2026-11-13.jsonl"), lines...)
	appendLines(t, filepath.Join(enrol, "enrolment-2026-11-13.jsonl"), jsonLine(Entry{Time: stampOf(at(20001)), Src: "log", Msg: "needle"}))
	appendLines(t, filepath.Join(front, "front.log"), caddyLineAt(at(20002), "192.0.2.1", "GET", "/x", 200))
	r := &Reader{Dirs: []string{share, enrol, front}, MaxBytes: 256 << 10}

	es, _, partial := page(t, r, Query{Src: []string{"front"}}, at(30000), 10)
	if partial || !slices.Equal(times(es), stamps(20002)) {
		t.Fatalf("Src=front: partial=%v %v", partial, times(es))
	}
	es, _, _ = page(t, r, Query{Text: "needle"}, at(30000), 10)
	if !slices.Equal(times(es), stamps(20001)) {
		t.Fatalf("Text=needle: %v", times(es))
	}
}

// Entries sharing the last millisecond of a page stay on that page.
// Continuing a stopped search from resume reaches every match, in two files,
// with no gap; a stop before anything was read resumes from before itself.
func TestPageResumeLosesNothing(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	var la, lb, want []string
	for i := 0; i < 4000; i++ {
		e := Entry{Time: stampOf(at(i / 2)), Src: "share", Host: fmt.Sprintf("h%04d", i)} // two per millisecond
		if i%3 == 0 {
			e.Msg = "needle"
			want = append(want, e.Host)
		}
		if i%2 == 0 {
			la = append(la, jsonLine(e))
		} else {
			e.Src = "relay"
			lb = append(lb, jsonLine(e))
		}
	}
	appendLines(t, filepath.Join(a, "share-2026-11-13.jsonl"), la...)
	appendLines(t, filepath.Join(b, "enrolment-2026-11-13.jsonl"), lb...)
	// Each page spends about 80 KiB seeking (two files of 150 KiB) and reads the rest.
	setChunk(t, 256)
	r := &Reader{Dirs: []string{a, b}, MaxBytes: 120 << 10}
	got := map[string]bool{}
	before, stops := time.Time{}, 0
	for pages := 0; ; pages++ {
		if pages > 500 {
			t.Fatal("the search does not move")
		}
		es, more, partial, resume, err := r.Page(context.Background(), Query{Text: "needle"}, before, 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			got[e.Host] = true
		}
		if !more {
			break
		}
		if !partial {
			t.Fatal("more without a budget stop")
		}
		if stops++; !before.IsZero() && !resume.Before(before) {
			t.Fatalf("resume %v does not move back from %v", resume, before)
		}
		before = resume
	}
	if stops < 3 || len(got) != len(want) {
		t.Fatalf("%d stops, %d of %d matches", stops, len(got), len(want))
	}
	setChunk(t, 64) // the file is large for this chunk: Page seeks first, and stops there
	_, _, partial, resume, _ := (&Reader{Dirs: []string{a}, MaxBytes: 1}).Page(context.Background(), Query{}, at(100), 10)
	if !partial || !resume.Equal(at(100)) {
		t.Fatalf("a stop in the seek: partial=%v resume=%v", partial, resume)
	}
}

func TestPageKeepsSameMillisecondTogether(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	appendLines(t, filepath.Join(a, "share-2026-11-13.jsonl"),
		jsonLine(Entry{Time: stampOf(at(0)), Src: "share", Msg: "a0"}),
		jsonLine(Entry{Time: stampOf(at(1)), Src: "share", Msg: "a1"}),
		jsonLine(Entry{Time: stampOf(at(1)), Src: "share", Msg: "a2"}),
		jsonLine(Entry{Time: stampOf(at(2)), Src: "share", Msg: "a3"}))
	appendLines(t, filepath.Join(b, "enrolment-2026-11-13.jsonl"),
		jsonLine(Entry{Time: stampOf(at(1)), Src: "relay", Msg: "b1"}),
		jsonLine(Entry{Time: stampOf(at(1)), Src: "relay", Msg: "b2"}))
	r := &Reader{Dirs: []string{a, b}}
	var got []string
	before := time.Time{}
	for pages := 0; pages < 10; pages++ {
		es, more, _ := page(t, r, Query{}, before, 2)
		for _, e := range es {
			got = append(got, e.Msg)
		}
		if !more {
			break
		}
		before, _ = time.Parse(timeLayout, es[len(es)-1].Time)
	}
	if slices.Sort(got); !slices.Equal(got, []string{"a0", "a1", "a2", "a3", "b1", "b2"}) {
		t.Fatalf("got %v", got)
	}
	if es, more, _ := page(t, r, Query{}, time.Time{}, 0); len(es) != 1 || !more {
		t.Fatalf("n=0 is clamped to 1: %v more=%v", times(es), more)
	}
}
