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
