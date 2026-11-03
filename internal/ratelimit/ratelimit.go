// Package ratelimit is a goroutine-safe rolling one-hour window limiter.
package ratelimit

import (
	"sync"
	"time"
)

const window = time.Hour

// Limiter allows at most perHour events per key in any rolling hour.
type Limiter struct {
	mu        sync.Mutex
	perHour   int
	now       func() time.Time
	events    map[string][]time.Time
	lastSweep time.Time
}

// New returns a Limiter. perHour <= 0 means every call is refused (retryAfter 1h).
func New(perHour int, now func() time.Time) *Limiter {
	return &Limiter{perHour: perHour, now: now, events: map[string][]time.Time{}}
}

// Allow records an event for key if under the limit. When refused, retryAfter is
// the time until the oldest counted event leaves the window, rounded up to a second.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	if l.perHour <= 0 {
		return false, window
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) >= time.Minute {
		for k := range l.events {
			l.trim(k, now)
		}
		l.lastSweep = now
	}
	l.trim(key, now)
	ev := l.events[key]
	if len(ev) >= l.perHour {
		return false, (ev[0].Add(window).Sub(now) + time.Second - 1).Truncate(time.Second)
	}
	l.events[key] = append(ev, now)
	return true, 0
}

// trim drops events that left the window and deletes the key when none remain.
func (l *Limiter) trim(key string, now time.Time) {
	ev := l.events[key]
	i := 0
	for i < len(ev) && !ev[i].Add(window).After(now) {
		i++
	}
	if i == len(ev) {
		delete(l.events, key)
	} else if i > 0 {
		l.events[key] = ev[i:]
	}
}
