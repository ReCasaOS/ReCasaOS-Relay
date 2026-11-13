package journal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a race-safe fake clock.
type clock struct{ ns atomic.Int64 }

func newClock(t time.Time) *clock { c := &clock{}; c.set(t); return c }
func (c *clock) set(t time.Time)  { c.ns.Store(t.UnixNano()) }
func (c *clock) now() time.Time   { return time.Unix(0, c.ns.Load()).UTC() }

var noon = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

func open(t *testing.T, dir, svc string, keep time.Duration, max int64, c *clock) *Writer {
	t.Helper()
	w, err := Open(dir, svc, keep, max, c.now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

func readLines(t *testing.T, name string) []string {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func readEntries(t *testing.T, name string) []Entry {
	t.Helper()
	var out []Entry
	for _, l := range readLines(t, name) {
		var e Entry
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("bad line %q: %v", l, err)
		}
		out = append(out, e)
	}
	return out
}

func mkfile(t *testing.T, dir, name string, size int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.Repeat("x", size)), 0o640); err != nil {
		t.Fatal(err)
	}
}

func exists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(dir, name))
	return err == nil
}

func TestWriteJSONLine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	w := open(t, dir, "share", 168*time.Hour, 1<<30, newClock(noon))
	w.Write(Entry{Src: "share", IP: "203.0.113.7", Host: "a.example", Act: "pass", In: 10})
	w.Write(Entry{Src: "relay", Event: "ban_open", Msg: "<x> & y"})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, "share-2026-11-13.jsonl")
	got := readLines(t, name)
	want := []string{
		`{"time":"2026-11-13T12:00:00.000Z","src":"share","svc":"share","ip":"203.0.113.7","host":"a.example","act":"pass","in":10}`,
		`{"time":"2026-11-13T12:00:00.000Z","src":"relay","svc":"share","event":"ban_open","msg":"<x> & y"}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if st, _ := os.Stat(name); st.Mode().Perm() != 0o640 {
		t.Errorf("file mode %v, want 0640", st.Mode().Perm())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o750 {
		t.Errorf("dir mode %v, want 0750", st.Mode().Perm())
	}
	// Caller-set time and svc are kept.
	w2 := open(t, dir, "share", 168*time.Hour, 1<<30, newClock(noon))
	w2.Write(Entry{Time: "2026-11-13T01:02:03.004Z", Svc: "front", Src: "front"})
	w2.Close()
	if l := readLines(t, name); l[len(l)-1] != `{"time":"2026-11-13T01:02:03.004Z","src":"front","svc":"front"}` {
		t.Fatalf("caller fields overwritten: %s", l[len(l)-1])
	}
}

func TestRotatesAtMidnightUTC(t *testing.T) {
	dir := t.TempDir()
	c := newClock(time.Date(2026, 11, 13, 23, 59, 59, 500e6, time.UTC))
	w := open(t, dir, "share", 168*time.Hour, 1<<30, c)
	for i := 0; i < 3; i++ {
		w.Write(Entry{Src: "share", Msg: fmt.Sprint("before", i)})
	}
	c.set(time.Date(2026, 11, 14, 0, 0, 0, 500e6, time.UTC))
	for i := 0; i < 3; i++ {
		w.Write(Entry{Src: "share", Msg: fmt.Sprint("after", i)})
	}
	w.Close()
	for day, prefix := range map[string]string{"2026-11-13": "before", "2026-11-14": "after"} {
		es := readEntries(t, filepath.Join(dir, "share-"+day+".jsonl"))
		if len(es) != 3 {
			t.Fatalf("%s: %d lines, want 3", day, len(es))
		}
		for i, e := range es {
			if e.Msg != fmt.Sprint(prefix, i) || !strings.HasPrefix(e.Time, day) {
				t.Errorf("%s line %d: %+v", day, i, e)
			}
		}
	}
}

func TestDeletesOlderThanKeep(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "share-2026-11-05.jsonl", 10)     // ended 11-06 00:00, before noon-168h
	mkfile(t, dir, "share-2026-11-06.jsonl", 10)     // ended 11-07 00:00, kept
	mkfile(t, dir, "enrolment-2026-11-01.jsonl", 10) // another service's
	mkfile(t, dir, "share-x-2026-11-01.jsonl", 10)   // not ours
	mkfile(t, dir, "notes.txt", 10)
	c := newClock(noon)

	w := open(t, dir, "share", 168*time.Hour, 1<<30, c)
	w.Close() // the first sweep runs when the loop starts
	if exists(dir, "share-2026-11-05.jsonl") {
		t.Error("11-05 kept, want deleted")
	}
	for _, n := range []string{"share-2026-11-06.jsonl", "enrolment-2026-11-01.jsonl", "share-x-2026-11-01.jsonl", "notes.txt"} {
		if !exists(dir, n) {
			t.Errorf("%s deleted, want kept", n)
		}
	}

	// The periodic sweep picks up files that age out later.
	old := sweepEvery
	sweepEvery = 5 * time.Millisecond
	t.Cleanup(func() { sweepEvery = old })
	open(t, dir, "share", 168*time.Hour, 1<<30, c)
	c.set(noon.Add(24 * time.Hour))
	deadline := time.Now().Add(5 * time.Second)
	for exists(dir, "share-2026-11-06.jsonl") {
		if time.Now().After(deadline) {
			t.Fatal("11-06 not deleted by the periodic sweep")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSizeCapDeletesOldestFirst(t *testing.T) {
	dir := t.TempDir()
	mkfile(t, dir, "share-2026-11-10.jsonl", 100)
	mkfile(t, dir, "share-2026-11-11.jsonl", 100)
	mkfile(t, dir, "share-2026-11-12.jsonl", 100)
	mkfile(t, dir, "share-2026-11-13.jsonl", 40) // today's counts in the total
	w := open(t, dir, "share", 168*time.Hour, 150, newClock(noon))
	w.Close()
	if exists(dir, "share-2026-11-10.jsonl") || exists(dir, "share-2026-11-11.jsonl") {
		t.Error("the two oldest should be deleted (340, 240 > 150; 140 <= 150)")
	}
	if !exists(dir, "share-2026-11-12.jsonl") || !exists(dir, "share-2026-11-13.jsonl") {
		t.Error("11-12 and today's should be kept")
	}

	// Today's alone above the cap starts over, with a line saying so.
	dir = t.TempDir()
	mkfile(t, dir, "share-2026-11-12.jsonl", 100)
	mkfile(t, dir, "share-2026-11-13.jsonl", 500)
	w = open(t, dir, "share", 168*time.Hour, 250, newClock(noon))
	w.Close()
	if exists(dir, "share-2026-11-12.jsonl") {
		t.Error("11-12 kept, want deleted")
	}
	es := readEntries(t, filepath.Join(dir, "share-2026-11-13.jsonl"))
	if len(es) != 1 || es[0].Src != "log" || es[0].Svc != "share" || es[0].Msg == "" {
		t.Fatalf("today's after cap: %+v, want one log line", es)
	}
}

// gate blocks every file write until opened.
type gate struct {
	w    io.Writer
	open chan struct{}
}

func (g gate) Write(p []byte) (int, error) { <-g.open; return g.w.Write(p) }

func TestWriteNeverBlocks(t *testing.T) {
	g := gate{open: make(chan struct{})}
	old := wrapFile
	wrapFile = func(f *os.File) io.Writer { g.w = f; return g }
	t.Cleanup(func() { wrapFile = old })
	dir := t.TempDir()
	w := open(t, dir, "share", 168*time.Hour, 1<<30, newClock(noon))

	const n = 100000
	start := time.Now()
	for i := 0; i < n; i++ {
		w.Write(Entry{Src: "share", Act: "pass"})
	}
	took := time.Since(start)
	close(g.open)
	w.Close()
	if took > time.Second {
		t.Fatalf("%d writes took %v with a blocked file", n, took)
	}
	var written, dropped int64
	for _, e := range readEntries(t, filepath.Join(dir, "share-2026-11-13.jsonl")) {
		if e.Src == "log" {
			if e.Msg != "lines not written" {
				t.Errorf("log line %+v", e)
			}
			dropped += e.Count
		} else {
			written++
		}
	}
	if dropped == 0 || written+dropped != n {
		t.Fatalf("written %d + dropped %d, want %d with drops", written, dropped, n)
	}
}

func TestLogWriterSplitsLines(t *testing.T) {
	dir := t.TempDir()
	w := open(t, dir, "enrolment", 168*time.Hour, 1<<30, newClock(noon))
	lw := w.Log()
	if n, err := io.WriteString(lw, "one\n"); n != 4 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	io.WriteString(lw, "two\nthree\n\n")
	log.New(lw, "", 0).Printf("four %d", 4)
	w.Close()
	var msgs []string
	for _, e := range readEntries(t, filepath.Join(dir, "enrolment-2026-11-13.jsonl")) {
		if e.Src != "log" || e.Svc != "enrolment" || e.Time == "" {
			t.Errorf("entry %+v", e)
		}
		msgs = append(msgs, e.Msg)
	}
	if got := strings.Join(msgs, "|"); got != "one|two|three|four 4" {
		t.Fatalf("msgs %q", got)
	}
}

func TestNilWriterIsNoop(t *testing.T) {
	var w *Writer
	w.Write(Entry{Msg: "x"})
	if n, err := w.Log().Write([]byte("x\n")); n != 2 || err != nil {
		t.Fatalf("Log().Write = %d, %v", n, err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCloseTwiceAndWriteAfterClose(t *testing.T) {
	w := open(t, t.TempDir(), "share", 168*time.Hour, 1<<30, newClock(noon))
	w.Close()
	w.Write(Entry{Msg: "late"}) // must not panic
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
