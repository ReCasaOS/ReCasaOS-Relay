package journal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	timeLayout = "2006-01-02T15:04:05.000Z07:00"
	dayLayout  = "2006-01-02"
	queueSize  = 4096
)

// Test seams, set before Open.
var (
	sweepEvery = time.Minute
	wrapFile   = func(f *os.File) io.Writer { return f }
)

// Writer appends Entries to <dir>/<svc>-YYYY-MM-DD.jsonl (UTC days) from
// one background goroutine, and deletes its own files older than keep or
// beyond maxSize in total. A nil *Writer does nothing.
type Writer struct {
	dir, svc string
	keep     time.Duration
	maxSize  int64
	now      func() time.Time

	ch      chan Entry
	dropped atomic.Int64
	quit    chan struct{}
	done    chan struct{}
	once    sync.Once
	err     error // set by the loop before done is closed

	// Owned by the loop goroutine.
	f        *os.File
	out      io.Writer
	day      string
	total    int64 // bytes in all of this writer's files
	sweepDue bool
	buf      bytes.Buffer
	enc      *json.Encoder
	failing  bool
}

// Open creates dir (0750) if missing, opens today's file and starts the
// background loop.
func Open(dir, svc string, keep time.Duration, maxSize int64, now func() time.Time) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	w := &Writer{
		dir: dir, svc: svc, keep: keep, maxSize: maxSize, now: now,
		ch:   make(chan Entry, queueSize),
		quit: make(chan struct{}),
		done: make(chan struct{}),
	}
	w.enc = json.NewEncoder(&w.buf)
	w.enc.SetEscapeHTML(false)
	if err := w.rotate(w.today()); err != nil {
		return nil, err
	}
	go w.loop()
	return w, nil
}

// Write queues e, setting time and svc when empty. It never blocks: when
// the queue is full the line is dropped and counted.
func (w *Writer) Write(e Entry) {
	if w == nil {
		return
	}
	w.stamp(&e)
	select {
	case w.ch <- e:
	default:
		w.dropped.Add(1)
	}
}

func (w *Writer) stamp(e *Entry) {
	if e.Time == "" {
		e.Time = w.now().UTC().Format(timeLayout)
	}
	if e.Svc == "" {
		e.Svc = w.svc
	}
}

func (w *Writer) today() string { return w.now().UTC().Format(dayLayout) }

// Log returns a writer for log.SetOutput: each line becomes a "log" Entry,
// without the standard log date prefix (the entry has its own time).
func (w *Writer) Log() io.Writer {
	if w == nil {
		return io.Discard
	}
	return logWriter{w}
}

type logWriter struct{ w *Writer }

var logPrefix = regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d(\.\d{6})? `)

func (l logWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(string(p), "\n") {
		if line = logPrefix.ReplaceAllString(line, ""); line != "" {
			l.w.Write(Entry{Src: "log", Msg: line})
		}
	}
	return len(p), nil
}

// Close writes the lines queued when it is called, then closes the file.
// Later Writes are dropped.
func (w *Writer) Close() error {
	if w == nil {
		return nil
	}
	w.once.Do(func() { close(w.quit) })
	<-w.done
	return w.err
}

func (w *Writer) loop() {
	defer close(w.done)
	w.sweep()
	t := time.NewTicker(sweepEvery)
	defer t.Stop()
	for {
		select {
		case e := <-w.ch:
			w.line(e)
		case <-t.C:
			w.sweepDue = true
		case <-w.quit:
			// Only what is queued now, so Close returns under steady writes.
			for n := len(w.ch); n > 0; n-- {
				w.line(<-w.ch)
			}
			w.reportDrops()
			if w.sweepDue {
				w.sweep()
			}
			if w.f != nil {
				w.err = w.f.Close()
			}
			return
		}
		w.reportDrops()
		if w.sweepDue {
			w.sweep()
		}
	}
}

func (w *Writer) reportDrops() {
	if n := w.dropped.Swap(0); n > 0 {
		e := Entry{Src: "log", Count: n, Msg: "lines not written"}
		w.stamp(&e)
		if !w.line(e) {
			w.dropped.Add(n)
		}
	}
}

// line writes e to the file of e's own day, so a line queued before
// midnight lands in that day's file even if written after. It reports
// whether the line was written.
func (w *Writer) line(e Entry) bool {
	day := ""
	if len(e.Time) >= len(dayLayout) {
		if _, err := time.Parse(dayLayout, e.Time[:len(dayLayout)]); err == nil {
			day = e.Time[:len(dayLayout)]
		}
	}
	if day == "" {
		day = w.today()
	}
	if w.f == nil || day != w.day {
		w.report(w.rotate(day))
	}
	if w.f == nil {
		return false
	}
	w.buf.Reset()
	w.enc.Encode(e) // an Entry always encodes
	n, err := w.out.Write(w.buf.Bytes())
	w.report(err)
	// Sweep as soon as the total crosses the cap, not only once a minute.
	if w.maxSize > 0 && w.total <= w.maxSize && w.total+int64(n) > w.maxSize {
		w.sweepDue = true
	}
	w.total += int64(n)
	return err == nil
}

func (w *Writer) rotate(day string) error {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
	f, err := os.OpenFile(w.name(day), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	w.f, w.out, w.day = f, wrapFile(f), day
	return nil
}

func (w *Writer) name(day string) string {
	return filepath.Join(w.dir, w.svc+"-"+day+".jsonl")
}

// report prints a file error to stderr once per failing spell; never through
// log, whose output may come back here.
func (w *Writer) report(err error) {
	if err != nil && !w.failing {
		fmt.Fprintf(os.Stderr, "journal %s: %v\n", w.svc, err)
	}
	w.failing = err != nil
}

// sweep moves to today's file, deletes this writer's files older than keep
// or dated in the future, then the oldest while the total exceeds maxSize.
// Today's file is never deleted; alone above the cap it starts over.
func (w *Writer) sweep() {
	w.sweepDue = false
	today := w.today()
	if w.f == nil || w.day != today {
		// An idle or clock-corrected writer must not pin an old file past keep.
		w.report(w.rotate(today))
	}
	names, _ := filepath.Glob(filepath.Join(w.dir, w.svc+"-*.jsonl"))
	cut := w.now().Add(-w.keep)
	type file struct {
		name string
		size int64
	}
	var old []file // sorted oldest first, as Glob sorts names
	var total int64
	for _, n := range names {
		day := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(n), w.svc+"-"), ".jsonl")
		d, err := time.Parse(dayLayout, day)
		if err != nil || (w.f != nil && n == w.f.Name()) {
			continue // not ours, or the open file
		}
		if d.Add(24*time.Hour).Before(cut) || day > today {
			os.Remove(n)
			continue
		}
		if st, err := os.Stat(n); err == nil {
			old = append(old, file{n, st.Size()})
			total += st.Size()
		}
	}
	w.total = total
	if w.f == nil {
		return
	}
	st, err := w.f.Stat()
	if err != nil {
		return
	}
	w.total += st.Size()
	if w.maxSize <= 0 {
		return
	}
	for len(old) > 0 && w.total > w.maxSize {
		if os.Remove(old[0].name) == nil {
			w.total -= old[0].size
		}
		old = old[1:]
	}
	if len(old) == 0 && st.Size() > w.maxSize && w.f.Truncate(0) == nil {
		w.total = 0
		e := Entry{Src: "log", Msg: fmt.Sprintf("journal above its size cap of %d bytes: today's file started over", w.maxSize)}
		w.stamp(&e)
		w.line(e)
	}
}
