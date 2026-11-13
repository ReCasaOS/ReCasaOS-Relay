package main

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/journal"
)

// connCap counts the open connections of each key and refuses one past max.
type connCap struct {
	max    int
	what   string // names the cap in the log line
	mu     sync.Mutex
	open   map[string]int
	logged time.Time
	cuts   map[string]*cutSum // refusals written to the journal, by key; "" holds those past maxCutKeys
}

// cutSum is a key's refusals since its last journal line.
type cutSum struct {
	ip, host, source string // of the key's first refusal
	n                int64
	last             time.Time
}

// cutWindow is the shortest gap between two journal lines of one key; maxCutKeys bounds the keys tracked.
const cutWindow = 10 * time.Second

var maxCutKeys = 10000

func newConnCap(max int, what string) *connCap {
	return &connCap{max: max, what: what, open: map[string]int{}, cuts: map[string]*cutSum{}}
}

// acquire takes a slot for key; false when key already holds max. Each true is paired with one release.
// The empty key (an uncapped source, see ipKey) is always let through.
func (c *connCap) acquire(key string) bool {
	if key == "" {
		return true
	}
	c.mu.Lock()
	if c.open[key] < c.max {
		c.open[key]++
		c.mu.Unlock()
		return true
	}
	now := time.Now()
	logIt := now.Sub(c.logged) >= time.Minute // at most one line a minute under a flood
	if logIt {
		c.logged = now
	}
	c.mu.Unlock()
	if logIt { // outside the lock: a stalled stderr must not stall accept
		log.Printf("share: %s cap (%d) reached by %s, refusing connections", c.what, c.max, key)
	}
	return false
}

// logRefused journals a refusal of conn (key as given to acquire) without letting a flood fill the
// journal: a key's first refusal is written at once, the next ones are counted for flushCuts.
func (c *connCap) logRefused(jw *journal.Writer, key string, conn net.Conn, host, source string, now time.Time) {
	if jw == nil {
		return
	}
	c.mu.Lock()
	if c.cuts[key] == nil && len(c.cuts) >= maxCutKeys {
		key = "" // never a refused key: acquire lets "" through
	}
	if s := c.cuts[key]; s != nil {
		s.n++
		c.mu.Unlock()
		return
	}
	s := &cutSum{source: source, last: now}
	if key != "" {
		s.ip, s.host = peerIP(conn), host
	}
	c.cuts[key] = s
	c.mu.Unlock()
	jw.Write(journal.Entry{Src: "share", IP: s.ip, Host: s.host, Act: "cut", Reason: "cap", Source: source})
}

// flushCuts writes, for each key whose last line is cutWindow old, one line with the count of its refusals
// since; a key with none frees its slot, and its next refusal is written at once again.
func (c *connCap) flushCuts(jw *journal.Writer, now time.Time) {
	var out []journal.Entry
	c.mu.Lock()
	for k, s := range c.cuts {
		switch {
		case now.Sub(s.last) < cutWindow:
		case s.n == 0:
			delete(c.cuts, k)
		default:
			out = append(out, journal.Entry{Src: "share", IP: s.ip, Host: s.host, Act: "cut", Reason: "cap", Source: s.source, Count: s.n})
			s.n, s.last = 0, now
		}
	}
	c.mu.Unlock()
	for _, e := range out {
		jw.Write(e)
	}
}

func (c *connCap) release(key string) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open[key]--; c.open[key] <= 0 {
		delete(c.open, key) // the map holds only keys with open connections
	}
}

// ipKey is the client's IPv4 address, or its IPv6 /64: one subscriber usually holds a whole /64. It is
// empty, uncapped, for loopback, private and link-local sources: Docker's userland proxy (IPv6 or hairpin
// connections to a published port) and boxes on the relay's own LAN all arrive from such an address,
// and capping it would cap all of them together.
func ipKey(a net.Addr) string {
	t, ok := a.(*net.TCPAddr)
	if !ok {
		return a.String()
	}
	if t.IP.IsLoopback() || t.IP.IsPrivate() || t.IP.IsLinkLocalUnicast() || t.IP.IsUnspecified() {
		return ""
	}
	if ip4 := t.IP.To4(); ip4 != nil {
		return ip4.String()
	}
	return t.IP.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
