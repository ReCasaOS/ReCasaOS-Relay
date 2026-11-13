package main

import (
	"log"
	"net"
	"sync"
	"time"
)

// connCap counts the open connections of each key and refuses one past max.
type connCap struct {
	max    int
	what   string // names the cap in the log line
	mu     sync.Mutex
	open   map[string]int
	logged time.Time
	cuts   cutLog // its refusals in the journal
}

func newConnCap(max int, what string) *connCap {
	return &connCap{max: max, what: what, open: map[string]int{}}
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
