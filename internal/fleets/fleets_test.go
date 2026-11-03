package fleets

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestFleetLocksAreReleased(t *testing.T) {
	var l Locks
	for i := 0; i < 100; i++ {
		unlock, err := l.Lock(context.Background(), "fleet"+strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		unlock()
	}
	if len(l.m) != 0 {
		t.Fatalf("%d lock entries left behind", len(l.m))
	}
	unlock, _ := l.Lock(context.Background(), "a")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := l.Lock(ctx, "a"); err == nil {
		t.Fatal("second lock on a held fleet must wait and give up with the context")
	}
	unlock()
	if len(l.m) != 0 {
		t.Fatalf("%d lock entries left behind after a cancelled wait", len(l.m))
	}
}
