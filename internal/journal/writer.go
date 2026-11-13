package journal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	f       *os.File
	out     io.Writer
	day     string
	buf     bytes.Buffer
	enc     *json.Encoder
	failing bool
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
	if err := w.rotate(now().UTC().Format(dayLayout)); err != nil {
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

// Log returns a writer for log.SetOutput: each line becomes a "log" Entry.
func (w *Writer) Log() io.Writer {
	if w == nil {
		return io.Discard
	}
	return logWriter{w}
}

type logWriter struct{ w *Writer }

func (l logWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(string(p), "\n") {
		if line != "" {
			l.w.Write(Entry{Src: "log", Msg: line})
		}
	}
	return len(p), nil
}

// Close writes what is queued, then closes the file. Later Writes are dropped.
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
			w.sweep()
		case <-w.quit:
			for len(w.ch) > 0 { // only this goroutine receives, so this never blocks
				w.line(<-w.ch)
			}
			w.reportDrops()
			if w.f != nil {
				w.err = w.f.Close()
			}
			return
		}
		w.reportDrops()
	}
}

func (w *Writer) reportDrops() {
	if n := w.dropped.Swap(0); n > 0 {
		e := Entry{Src: "log", Count: n, Msg: "lines not written"}
		w.stamp(&e)
		w.line(e)
	}
}

// line writes e to the file of e's own day, so a line queued before
// midnight lands in that day's file even if written after.
func (w *Writer) line(e Entry) {
	day := w.now().UTC().Format(dayLayout)
	if len(e.Time) >= len(dayLayout) {
		if _, err := time.Parse(dayLayout, e.Time[:len(dayLayout)]); err == nil {
			day = e.Time[:len(dayLayout)]
		}
	}
	if w.f == nil || day > w.day {
		w.report(w.rotate(day))
	}
	if w.f == nil {
		return
	}
	w.buf.Reset()
	w.enc.Encode(e) // an Entry always encodes
	_, err := w.out.Write(w.buf.Bytes())
	w.report(err)
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

// sweep deletes this writer's files older than keep, then the oldest while
// the total exceeds maxSize. The open file is never deleted; alone above the
// cap it starts over.
func (w *Writer) sweep() {
	names, _ := filepath.Glob(filepath.Join(w.dir, w.svc+"-*.jsonl"))
	cut := w.now().Add(-w.keep)
	type file struct {
		name string
		size int64
	}
	var old []file // sorted oldest first, as Glob sorts names
	var total int64
	for _, n := range names {
		d, err := time.Parse(dayLayout, strings.TrimSuffix(strings.TrimPrefix(filepath.Base(n), w.svc+"-"), ".jsonl"))
		if err != nil || (w.f != nil && n == w.f.Name()) {
			continue // not ours, or the open file
		}
		if d.Add(24 * time.Hour).Before(cut) {
			os.Remove(n)
			continue
		}
		if st, err := os.Stat(n); err == nil {
			old = append(old, file{n, st.Size()})
			total += st.Size()
		}
	}
	if w.f == nil || w.maxSize <= 0 {
		return
	}
	st, err := w.f.Stat()
	if err != nil {
		return
	}
	total += st.Size()
	for len(old) > 0 && total > w.maxSize {
		if os.Remove(old[0].name) == nil {
			total -= old[0].size
		}
		old = old[1:]
	}
	if len(old) == 0 && st.Size() > w.maxSize && w.f.Truncate(0) == nil {
		e := Entry{Src: "log", Msg: fmt.Sprintf("journal above its size cap of %d bytes: today's file started over", w.maxSize)}
		w.stamp(&e)
		w.line(e)
	}
}
