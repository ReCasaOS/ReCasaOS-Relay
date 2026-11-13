package main

import (
	"sync"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/journal"
)

// cutWindow is the shortest gap between two journal lines of one key; maxCutKeys bounds the keys tracked.
const cutWindow = 10 * time.Second

var maxCutKeys = 10000

// cutLog writes refused connections to the journal without letting a flood fill it: per key, reason and
// source, the first refusal is written at once and the next ones are counted for flush.
type cutLog struct {
	mu sync.Mutex
	m  map[string]*cutSum // by key|reason|source; "|reason|source" holds those past maxCutKeys
}

// cutSum is one entry's refusals since its last journal line.
type cutSum struct {
	ip, host, reason, source string // of the first refusal
	n                        int64
	last                     time.Time
}

func (l *cutLog) log(jw *journal.Writer, key, ip, host, reason, source string, now time.Time) {
	if jw == nil {
		return
	}
	k := key + "|" + reason + "|" + source
	l.mu.Lock()
	if l.m == nil {
		l.m = map[string]*cutSum{}
	}
	if l.m[k] == nil && len(l.m) >= maxCutKeys {
		k, ip, host = "|"+reason+"|"+source, "", ""
	}
	if s := l.m[k]; s != nil {
		s.n++
		l.mu.Unlock()
		return
	}
	l.m[k] = &cutSum{ip: ip, host: host, reason: reason, source: source, last: now}
	l.mu.Unlock()
	jw.Write(journal.Entry{Src: "share", IP: ip, Host: host, Act: "cut", Reason: reason, Source: source})
}

// flush writes, for each entry whose last line is cutWindow old, one line with the count of its refusals
// since; an entry with none frees its slot, and its next refusal is written at once again.
func (l *cutLog) flush(jw *journal.Writer, now time.Time) {
	var out []journal.Entry
	l.mu.Lock()
	for k, s := range l.m {
		switch {
		case now.Sub(s.last) < cutWindow:
		case s.n == 0:
			delete(l.m, k)
		default:
			out = append(out, journal.Entry{Src: "share", IP: s.ip, Host: s.host, Act: "cut", Reason: s.reason, Source: s.source, Count: s.n})
			s.n, s.last = 0, now
		}
	}
	l.mu.Unlock()
	for _, e := range out {
		jw.Write(e)
	}
}
