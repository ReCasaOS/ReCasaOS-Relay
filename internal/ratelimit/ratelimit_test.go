package ratelimit

import (
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestLimiterAllowsNThenRefuses(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(3, c.now)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("call %d refused", i)
		}
		c.t = c.t.Add(10 * time.Minute)
	}
	// Oldest event is 30 min old, so it leaves the window in 30 min.
	ok, retry := l.Allow("a")
	if ok || retry != 30*time.Minute {
		t.Fatalf("ok=%v retry=%v", ok, retry)
	}
	// Refusals are not counted: once the oldest leaves, one call fits again.
	c.t = c.t.Add(30 * time.Minute)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("still refused after window expiry")
	}
}

func TestLimiterKeysAreIndependent(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(1, c.now)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal()
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("a not limited")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("b limited by a")
	}
}

func TestLimiterPrunesKeys(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(5, c.now)
	l.Allow("a")
	l.Allow("b")
	c.t = c.t.Add(2 * time.Hour)
	l.Allow("c")
	l.mu.Lock()
	n := len(l.events)
	l.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d keys kept, want 1", n)
	}
}

func TestLimiterNonPositiveAlwaysRefuses(t *testing.T) {
	l := New(0, time.Now)
	if ok, retry := l.Allow("a"); ok || retry != time.Hour {
		t.Fatalf("ok=%v retry=%v", ok, retry)
	}
}

func TestLimiterCapsKeys(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(2, c.now)
	l.maxKeys = 2
	l.Allow("a")
	l.Allow("b")
	if ok, retry := l.Allow("c"); ok || retry != time.Minute {
		t.Fatalf("new key admitted when full: ok=%v retry=%v", ok, retry)
	}
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("existing key refused when full")
	}
	if len(l.events) != 2 {
		t.Fatalf("%d keys, want 2", len(l.events))
	}
	// Old keys expire; the cap path sweeps them before refusing, so a new key fits.
	c.t = c.t.Add(window)
	if ok, _ := l.Allow("c"); !ok {
		t.Fatal("new key refused although old keys expired")
	}
}

// At the cap, a refused new key does not pay a full sweep again within a second of the last one.
func TestLimiterAtCapSweepsAtMostOncePerSecond(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	start := c.t
	l := New(5, c.now)
	l.maxKeys = 2
	l.Allow("a") // first call sweeps: lastSweep = start
	c.t = start.Add(59 * time.Minute)
	l.Allow("b") // periodic sweep: lastSweep = start+59m
	c.t = start.Add(window - 500*time.Millisecond)
	if ok, _ := l.Allow("c"); ok {
		t.Fatal("new key admitted at the cap") // at-cap sweep runs, a is still live
	}
	c.t = start.Add(window + 100*time.Millisecond) // a has expired, last sweep 0.6 s ago
	if ok, _ := l.Allow("c"); ok {
		t.Fatal("at-cap sweep ran again within a second")
	}
	c.t = start.Add(window + 600*time.Millisecond) // 1.1 s since the last sweep
	if ok, _ := l.Allow("c"); !ok {
		t.Fatal("new key refused although a sweep is due and a key expired")
	}
}
