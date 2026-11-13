package journal

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Test seams.
var (
	readChunk   = 64 << 10
	followEvery = 500 * time.Millisecond
)

const maxLine = 1 << 20 // longer lines are skipped, not buffered

// ErrBusy is returned by Page when another Page is still running.
var ErrBusy = errors.New("busy")

// pageSem lets one Page run at a time in the whole process.
var pageSem = make(chan struct{}, 1)

var errBudget = errors.New("read budget spent")

// Query selects entries. Zero fields select everything.
type Query struct {
	Src      []string
	Text     string // case-insensitive, in ip, host, path, reason, source, event, msg
	Problems bool   // act=cut, status >= 400, or src=log
	From, To time.Time
}

// Reader reads the journal files in Dirs: ours (*.jsonl), and a Caddy access
// log (*.log, current and rolled) if one is there.
type Reader struct {
	Dirs     []string
	Now      func() time.Time // default time.Now
	MaxBytes int64            // read per Page, default 64 MiB
	MaxTime  time.Duration    // per Page, default 5 s
}

type filter struct {
	q              Query
	from, to, text string
}

func newFilter(q Query) filter {
	f := filter{q: q, text: strings.ToLower(q.Text)}
	if !q.From.IsZero() {
		f.from = q.From.UTC().Format(timeLayout)
	}
	if !q.To.IsZero() {
		f.to = q.To.UTC().Format(timeLayout)
	}
	return f
}

// match compares times as strings: every Time has the fixed timeLayout in UTC.
func (f *filter) match(e *Entry) bool {
	if f.from != "" && e.Time < f.from || f.to != "" && e.Time > f.to {
		return false
	}
	if len(f.q.Src) > 0 && !slices.Contains(f.q.Src, e.Src) {
		return false
	}
	if f.q.Problems && e.Act != "cut" && e.Status < 400 && e.Src != "log" {
		return false
	}
	if f.text == "" {
		return true
	}
	for _, s := range []string{e.IP, e.Host, e.Path, e.Reason, e.Source, e.Event, e.Msg} {
		if strings.Contains(strings.ToLower(s), f.text) {
			return true
		}
	}
	return false
}

// mayMatch tells whether fl can hold entries of q.Src: Caddy's files hold
// only front; front-*.jsonl (enrolment's ingest) front and log; ours never front.
func (f *filter) mayMatch(fl file) bool {
	if len(f.q.Src) == 0 {
		return true
	}
	front := fl.caddy || strings.HasPrefix(filepath.Base(fl.name), "front-")
	for _, src := range f.q.Src {
		if (src == "front") == front || src == "log" && !fl.caddy {
			return true
		}
	}
	return false
}

// parseLine reads one line of ours or of Caddy's; false for anything else,
// such as a partial line left by a full disk.
func parseLine(line []byte, caddy bool) (Entry, bool) {
	if caddy {
		return ParseCaddy(line)
	}
	var e Entry
	if json.Unmarshal(line, &e) != nil || len(e.Time) != len("2006-01-02T15:04:05.000Z") {
		return e, false
	}
	if _, err := time.Parse(timeLayout, e.Time); err != nil {
		return e, false
	}
	return e, true
}

type file struct {
	name  string
	caddy bool
}

var dayName = regexp.MustCompile(`-(\d{4}-\d\d-\d\d)\.jsonl$`)

// files lists the journal files that may hold entries in [lo, hi] (zero:
// unbounded): ours by the day in their name, Caddy's by mtime, the time of
// their last line.
func (r *Reader) files(lo, hi time.Time) []file {
	var out []file
	for _, dir := range r.Dirs {
		des, _ := os.ReadDir(dir) // a missing dir has nothing yet
		for _, de := range des {
			name := de.Name()
			if !de.Type().IsRegular() {
				continue
			}
			switch {
			case strings.HasSuffix(name, ".jsonl"):
				if m := dayName.FindStringSubmatch(name); m != nil {
					if d, err := time.Parse(dayLayout, m[1]); err == nil &&
						(!lo.IsZero() && !d.Add(24*time.Hour).After(lo) || !hi.IsZero() && d.After(hi)) {
						continue
					}
				}
				out = append(out, file{filepath.Join(dir, name), false})
			case strings.HasSuffix(name, ".log"):
				// A minute of slack: mtime may be stored in whole seconds.
				if info, err := de.Info(); err == nil && !lo.IsZero() && info.ModTime().Add(time.Minute).Before(lo) {
					continue
				}
				out = append(out, file{filepath.Join(dir, name), true})
			}
		}
	}
	return out
}

// scan is one Page's read budget.
type scan struct {
	ctx      context.Context
	left     int64
	deadline time.Time
	now      func() time.Time
}

// grant allows reading up to want bytes, at least one.
func (s *scan) grant(want int64) (int64, error) {
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	if s.left <= 0 || s.now().After(s.deadline) {
		return 0, errBudget
	}
	n := min(want, s.left)
	s.left -= n
	return n, nil
}

// cursor reads one file backwards, line by line, in chunks.
type cursor struct {
	f     *os.File
	caddy bool
	off   int64  // file[:off] is not read yet
	buf   []byte // file[off:end of the next line to return]
	// frontier is the time of the last line read, matching or not: the
	// lines still unread are not newer.
	frontier string
	head     *Entry // a matching entry not yet taken
}

// bound is the newest time this cursor may still yield.
func (c *cursor) bound() string {
	if c.head != nil {
		return c.head.Time
	}
	return c.frontier
}

// prev returns the line before the last one returned, io.EOF at the start.
func (c *cursor) prev(s *scan) ([]byte, error) {
	for {
		if i := bytes.LastIndexByte(c.buf, '\n'); i >= 0 {
			line := c.buf[i+1:]
			c.buf = c.buf[:i]
			return line, nil
		}
		if c.off == 0 {
			if c.buf == nil {
				return nil, io.EOF
			}
			line := c.buf
			c.buf = nil
			return line, nil
		}
		if len(c.buf) > maxLine {
			c.buf = c.buf[:0] // the head of that line will not parse either
		}
		n, err := s.grant(min(int64(readChunk), c.off))
		if err != nil {
			return nil, err
		}
		nb := make([]byte, int(n)+len(c.buf))
		if _, err := c.f.ReadAt(nb[:n], c.off-n); err != nil {
			return nil, io.EOF // the file shrank under us: nothing more to read here
		}
		copy(nb[n:], c.buf)
		c.off -= n
		c.buf = nb
	}
}

// seek moves the end of the cursor back to about the first line at or after
// stop, bisecting on the offset (lines are in time order), so a page deep in
// a large file does not read the newer part of it.
func (c *cursor) seek(s *scan, stop string) error {
	lo, hi, end := int64(0), c.off, c.off // end: a line start, all lines from it at or after stop
	for hi-lo > int64(readChunk) {
		mid := lo + (hi-lo)/2
		n, err := s.grant(4096)
		if err != nil {
			return err
		}
		p := make([]byte, n)
		k, _ := c.f.ReadAt(p, mid)
		p = p[:k]
		e, ok, start := Entry{}, false, int64(-1)
		if i := bytes.IndexByte(p, '\n'); i >= 0 {
			if j := bytes.IndexByte(p[i+1:], '\n'); j >= 0 {
				e, ok = parseLine(p[i+1:i+1+j], c.caddy)
				start = mid + int64(i) + 1
			}
		}
		switch {
		case ok && e.Time >= stop:
			end, hi = start, mid
		case ok:
			lo = start
		default:
			lo = mid + 1 // unknown: keeping end is always safe
		}
	}
	c.off = end
	return nil
}

// step reads one line, keeping it as head when it matches; false when the
// file has nothing more in range.
func (c *cursor) step(s *scan, f *filter, stop string) (bool, error) {
	line, err := c.prev(s)
	if err == io.EOF {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	e, ok := parseLine(line, c.caddy)
	if !ok {
		return true, nil
	}
	c.frontier = e.Time
	if f.from != "" && e.Time < f.from {
		return false, nil // older than the range from here on
	}
	if (stop == "" || e.Time < stop) && f.match(&e) {
		c.head = &e
	}
	return true, nil
}

// Page returns n entries (clamped to 1..1000) matching q older than before
// (zero: now), newest first, merged by time across all files; it may return
// more than n so that entries sharing the last one's millisecond are not
// split across pages. more tells whether older matching entries exist. When
// the read budget runs out it returns what it found with partial (and more)
// true, and resume: the before that continues the search where it stopped,
// losing no entry (it may repeat some of one millisecond); zero when it
// stopped before reading anything and before was zero.
func (r *Reader) Page(ctx context.Context, q Query, before time.Time, n int) (entries []Entry, more, partial bool, resume time.Time, err error) {
	select {
	case pageSem <- struct{}{}:
	case <-ctx.Done():
		return nil, false, false, time.Time{}, ctx.Err()
	case <-time.After(time.Second):
		return nil, false, false, time.Time{}, ErrBusy
	}
	defer func() { <-pageSem }()

	now := r.Now
	if now == nil {
		now = time.Now
	}
	s := &scan{ctx: ctx, left: cmp.Or(r.MaxBytes, 64<<20), now: now}
	s.deadline = now().Add(cmp.Or(r.MaxTime, 5*time.Second))
	n = min(max(n, 1), 1000)
	f := newFilter(q)
	// Entries at or after stop are skipped; To is inclusive.
	stop := before
	if !q.To.IsZero() {
		if to := q.To.Truncate(time.Millisecond).Add(time.Millisecond); stop.IsZero() || to.Before(stop) {
			stop = to
		}
	}
	stopAt := ""
	if !stop.IsZero() {
		stopAt = stop.UTC().Format(timeLayout)
	}
	var live []*cursor
	// stopped ends the page on err; at the budget, the search resumes just after the newest time some
	// live cursor may still yield: everything newer was read.
	stopped := func(err error) ([]Entry, bool, bool, time.Time, error) {
		if err != errBudget {
			return nil, false, false, time.Time{}, err
		}
		bound := ""
		for _, c := range live {
			bound = max(bound, c.bound())
		}
		resume := stop
		if t, err := time.Parse(timeLayout, bound); err == nil { // "" and "~" (nothing read) keep stop
			if t = t.Add(time.Millisecond); stop.IsZero() || t.Before(stop) {
				resume = t
			}
		}
		return entries, true, true, resume, nil
	}

	for _, fl := range r.files(q.From, stop) {
		if !f.mayMatch(fl) {
			continue
		}
		fh, err := os.Open(fl.name)
		if err != nil {
			continue // deleted since listed
		}
		defer fh.Close()
		st, err := fh.Stat()
		if err != nil {
			continue
		}
		c := &cursor{f: fh, caddy: fl.caddy, off: st.Size(), frontier: "~"} // "~" sorts after any time
		if stopAt != "" {
			if err := c.seek(s, stopAt); err != nil {
				live = nil // the files not opened yet were not read at all
				return stopped(err)
			}
		}
		live = append(live, c)
	}
	// Always move the cursor that may hold the newest entry, so the budget is
	// spent across files by time, not on whichever file is listed first.
	for len(live) > 0 {
		i := 0
		for j, c := range live {
			if c.bound() > live[i].bound() {
				i = j
			}
		}
		c := live[i]
		if c.head != nil {
			if len(entries) >= n && c.head.Time != entries[len(entries)-1].Time {
				return entries, true, false, time.Time{}, nil
			}
			entries = append(entries, *c.head)
			c.head = nil
			continue
		}
		ok, err := c.step(s, &f, stopAt)
		if err != nil {
			return stopped(err)
		}
		if !ok {
			live = slices.Delete(live, i, i+1)
		}
	}
	return entries, false, false, time.Time{}, nil
}

// tail follows one file by identity, so a renamed (rolled) file keeps its
// place.
type tail struct {
	f     *os.File
	info  os.FileInfo
	caddy bool
	off   int64
	carry []byte // a line not finished yet
	seen  bool
}

// read appends the matching entries of the lines written up to size.
func (t *tail) read(size int64, f *filter, out []Entry) []Entry {
	for t.off < size {
		p := make([]byte, min(size-t.off, maxLine))
		k, err := t.f.ReadAt(p, t.off)
		t.off += int64(k)
		data := append(t.carry, p[:k]...)
		i := bytes.LastIndexByte(data, '\n')
		t.carry = append([]byte(nil), data[i+1:]...)
		if len(t.carry) > maxLine {
			t.carry = nil
		}
		for _, line := range bytes.Split(data[:i+1], []byte{'\n'}) {
			if e, ok := parseLine(line, t.caddy); ok && f.match(&e) {
				out = append(out, e)
			}
		}
		if err != nil && k == 0 {
			break
		}
	}
	return out
}

// Follow sends to out the entries matching q written from now on, in every
// file of Dirs and in files appearing later, polling every 500 ms. A file
// that shrank (started over) is read again from its start. It returns when
// ctx ends; out is not closed.
func (r *Reader) Follow(ctx context.Context, q Query, out chan<- Entry) {
	f := newFilter(q)
	var tails []*tail
	defer func() {
		for _, t := range tails {
			t.f.Close()
		}
	}()
	tick := time.NewTicker(followEvery)
	defer tick.Stop()
	for first := true; ; first = false {
		var batch []Entry
		for _, t := range tails {
			t.seen = false
		}
		for _, fl := range r.files(time.Time{}, time.Time{}) {
			info, err := os.Stat(fl.name)
			if err != nil {
				continue
			}
			i := slices.IndexFunc(tails, func(t *tail) bool { return os.SameFile(t.info, info) })
			if i < 0 {
				fh, err := os.Open(fl.name)
				if err != nil {
					continue
				}
				if info, err = fh.Stat(); err != nil {
					fh.Close()
					continue
				}
				t := &tail{f: fh, info: info, caddy: fl.caddy}
				if first {
					t.off = info.Size() // from now on
				}
				tails, i = append(tails, t), len(tails)
			}
			t := tails[i]
			t.seen = true
			if info.Size() < t.off {
				t.off, t.carry = 0, nil
			}
			batch = t.read(info.Size(), &f, batch)
		}
		tails = slices.DeleteFunc(tails, func(t *tail) bool {
			if !t.seen {
				t.f.Close()
			}
			return !t.seen
		})
		slices.SortStableFunc(batch, func(a, b Entry) int { return strings.Compare(a.Time, b.Time) })
		for _, e := range batch {
			select {
			case out <- e:
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			return
		}
	}
}
