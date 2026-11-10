package ratelimit

import (
	"testing"
	"time"
)

// A limiter that refuses every new key once its table is full is switched off, for everyone it
// does not know yet, by whoever fills the table. One that guards nothing a flood could not do
// anyway lets the new key through, uncounted, and goes on counting the keys it knows.
func TestLimiterOpenWhenFullLetsANewKeyThrough(t *testing.T) {
	c := &clock{time.Unix(1_800_000_000, 0)}
	l := New(2, c.now).OpenWhenFull()
	l.maxKeys = 2
	l.Allow("a")
	l.Allow("b")

	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("c"); !ok {
			t.Fatalf("call %d of a new key refused when full", i+1)
		}
	}
	if len(l.events) != 2 {
		t.Fatalf("%d keys, want 2: the new key is not kept", len(l.events))
	}

	// the keys it knows are counted as before
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("second event of a known key refused")
	}
	if ok, retry := l.Allow("a"); ok || retry <= 0 {
		t.Fatalf("third event of a known key: ok=%v retry=%v, want refused", ok, retry)
	}

	// with room again, a new key is counted like any other
	c.t = c.t.Add(window)
	l.Allow("c")
	l.Allow("c")
	if ok, _ := l.Allow("c"); ok {
		t.Fatal("a new key is not counted once the table has room")
	}
}
