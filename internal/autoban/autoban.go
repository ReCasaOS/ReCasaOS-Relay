// Package autoban counts what a client address does wrong (probing trap paths, bursts of 404s,
// guessing share names) and says when its key must be banned. In memory only, safe for concurrent use.
package autoban

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	defaultNotFound = 20
	defaultNames    = 10
	defaultTraps    = 3
	defaultWindow   = 10 * time.Minute
	boxExemption    = 24 * time.Hour
	maxNameLen      = 64
	trapWindow      = time.Hour // not configurable: three probes an hour apart are not a scan
)

// maxKeys caps the keys each counter tracks so attacker-chosen keys cannot grow the maps without bound.
// A var so a test can lower it.
var maxKeys = 50_000

// Paths no honest client asks the relay for; Config.Traps hits within trapWindow ban, whatever the status code.
var traps = []string{
	"/.env", "/.git/", "/.aws/", "/wp-login.php", "/wp-admin", "/xmlrpc.php",
	"/phpmyadmin", "/cgi-bin/", "/vendor/phpunit", "/actuator",
}

// Paths browsers and crawlers ask for legitimately: their 404s are not counted.
var harmless404 = map[string]bool{"/robots.txt": true, "/sitemap.xml": true, "/favicon.ico": true}

// Config sets the thresholds; a zero field takes its default.
type Config struct {
	NotFound, Names, Traps int
	Window                 time.Duration
}

// Detector holds the counters per key (a client address).
type Detector struct {
	cfg      Config
	now      func() time.Time
	mu       sync.Mutex
	notFound map[string][]time.Time          // key -> times of its recent 404s
	traps    map[string][]time.Time          // key -> times of its recent trap requests
	names    map[string]map[string]time.Time // key -> unknown share name -> last try
	exempt   map[string]time.Time            // key -> end of the box exemption
	// last full sweep of each map and how many ran: a full counter must not be rescanned per request
	lastSweep [4]time.Time
	sweeps    int
}

// New returns a Detector.
func New(cfg Config, now func() time.Time) *Detector {
	if cfg.NotFound <= 0 {
		cfg.NotFound = defaultNotFound
	}
	if cfg.Names <= 0 {
		cfg.Names = defaultNames
	}
	if cfg.Traps <= 0 {
		cfg.Traps = defaultTraps
	}
	if cfg.Window <= 0 {
		cfg.Window = defaultWindow
	}
	return &Detector{cfg: cfg, now: now, notFound: map[string][]time.Time{}, traps: map[string][]time.Time{}, names: map[string]map[string]time.Time{}, exempt: map[string]time.Time{}}
}

// Box exempts key for 24 h: a box authenticated from it.
func (d *Detector) Box(key string) {
	if key == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if _, known := d.exempt[key]; !known && len(d.exempt) >= maxKeys {
		d.sweep(2, now)
		if len(d.exempt) >= maxKeys {
			return
		}
	}
	d.exempt[key] = now.Add(boxExemption)
}

// Front takes one request to the relay's own pages. fault is "" unless key must be banned now.
func (d *Detector) Front(key, path string, status int) (fault, detail string) {
	if key == "" {
		return "", ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if d.exemptNow(key, now) {
		return "", ""
	}
	p := strings.ToLower(path)
	if strings.HasPrefix(p, "/.well-known/") || strings.HasPrefix(p, "/v1/") { // the relay's own API answers 404 to honest boxes
		return "", ""
	}
	if t := trapOf(p); t != "" { // a trap request is not also a 404
		if d.hit(d.traps, 3, key, now, trapWindow, d.cfg.Traps) {
			d.reset(key)
			return "trap", t
		}
		return "", ""
	}
	if status != 404 || harmless404[p] {
		return "", ""
	}
	if d.hit(d.notFound, 0, key, now, d.cfg.Window, d.cfg.NotFound) {
		d.reset(key)
		return "404", fmt.Sprintf("%d in %s", d.cfg.NotFound, d.cfg.Window)
	}
	return "", ""
}

// hit records one event of key in counter m (sweep slot w) and reports whether limit events fall within
// window; a full counter drops the events of keys it does not track yet.
func (d *Detector) hit(m map[string][]time.Time, w int, key string, now time.Time, window time.Duration, limit int) bool {
	ev, known := m[key]
	if !known && len(m) >= maxKeys {
		d.sweep(w, now)
		if len(m) >= maxKeys {
			return false
		}
	}
	ev = append(trim(ev, now.Add(-window)), now)
	if len(ev) >= limit {
		return true
	}
	m[key] = ev
	return false
}

// Unknown takes one try of a share name no box holds.
func (d *Detector) Unknown(key, name string) (fault, detail string) {
	if key == "" {
		return "", ""
	}
	if len(name) > maxNameLen {
		name = name[:maxNameLen]
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	if d.exemptNow(key, now) {
		return "", ""
	}
	seen, known := d.names[key]
	if !known {
		if len(d.names) >= maxKeys {
			d.sweep(1, now)
			if len(d.names) >= maxKeys {
				return "", ""
			}
		}
		seen = map[string]time.Time{}
	}
	for n, at := range seen {
		if !at.After(now.Add(-d.cfg.Window)) {
			delete(seen, n)
		}
	}
	seen[name] = now
	if len(seen) >= d.cfg.Names {
		d.reset(key)
		return "names", fmt.Sprintf("%d in %s", d.cfg.Names, d.cfg.Window)
	}
	d.names[key] = seen
	return "", ""
}

func (d *Detector) exemptNow(key string, now time.Time) bool {
	end, ok := d.exempt[key]
	if ok && !end.After(now) {
		delete(d.exempt, key)
		return false
	}
	return ok
}

func (d *Detector) reset(key string) {
	delete(d.notFound, key)
	delete(d.traps, key)
	delete(d.names, key)
}

// sweep drops the expired keys of map w (0 404s, 1 names, 2 exemptions, 3 traps), at most once a second per
// map: under a flood of new keys a full map is refused without a scan, and frees up at the next sweep.
func (d *Detector) sweep(w int, now time.Time) {
	if now.Sub(d.lastSweep[w]) < time.Second {
		return
	}
	d.lastSweep[w] = now
	d.sweeps++
	cut := now.Add(-d.cfg.Window)
	switch w {
	case 0, 3:
		m := d.notFound
		if w == 3 {
			m, cut = d.traps, now.Add(-trapWindow)
		}
		for k, ev := range m {
			if len(trim(ev, cut)) == 0 {
				delete(m, k)
			}
		}
	case 1:
		for k, seen := range d.names {
			live := false
			for _, at := range seen {
				if at.After(cut) {
					live = true
					break
				}
			}
			if !live {
				delete(d.names, k)
			}
		}
	default:
		for k, end := range d.exempt {
			if !end.After(now) {
				delete(d.exempt, k)
			}
		}
	}
}

// trim drops times at or before cut.
func trim(ev []time.Time, cut time.Time) []time.Time {
	i := 0
	for i < len(ev) && !ev[i].After(cut) {
		i++
	}
	return ev[i:]
}

// trapOf returns the trap entry p (lower-case) matches, or "".
func trapOf(p string) string {
	for _, t := range traps {
		if strings.HasSuffix(t, "/") {
			if strings.HasPrefix(p, t) {
				return t
			}
			continue
		}
		if p == t || (strings.HasPrefix(p, t) && strings.ContainsRune("/?", rune(p[len(t)]))) {
			return t
		}
	}
	return ""
}
