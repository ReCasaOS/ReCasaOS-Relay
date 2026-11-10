package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The rate limit bounds how fast a network creates fleets, not how many it holds: at 5 an hour
// for an address (50 for a /48) one network took every place of the relay in a day. A network
// holds so many fleets at once, and gets a place back when one of its fleets goes.
func TestCreateFleetRefusedPastTheFleetsOfOneAddress(t *testing.T) {
	e := setup(t, func(c *Config, _ *Deps) {
		c.CreateRatePerHour = 100
		c.MaxFleetsPerOrigin = 2
	})
	for i := 0; i < 2; i++ {
		if rec := e.post(t, "192.0.2.1:"+strconv.Itoa(4000+i), nil); rec.Code != http.StatusCreated {
			t.Fatalf("call %d: %d %s", i+1, rec.Code, rec.Body)
		}
	}
	before := e.hs.callCount()
	rec := e.post(t, "192.0.2.1:5000", nil)
	if rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "too many fleets from this network") {
		t.Fatalf("third fleet of the address: %d %s, want 429", rec.Code, rec.Body)
	}
	if ra, err := strconv.Atoi(rec.Header().Get("Retry-After")); err != nil || ra < 1 {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	if e.hs.callCount() != before {
		t.Fatal("a creation refused for its network reached Headscale")
	}
	if rec := e.post(t, "192.0.2.2:4000", nil); rec.Code != http.StatusCreated {
		t.Fatalf("another address: %d, want 201", rec.Code)
	}

	// one of its fleets goes: the address has a place again
	all, err := e.st.ListFleets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all {
		if f.Origin == "192.0.2.1" {
			if err := e.st.DeleteFleet(context.Background(), f.ID); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if rec := e.post(t, "192.0.2.1:6000", nil); rec.Code != http.StatusCreated {
		t.Fatalf("after one of its fleets went: %d %s, want 201", rec.Code, rec.Body)
	}
}

// A subscriber holds many /64s: they are counted together as their /48 as well.
func TestCreateFleetRefusedPastTheFleetsOfOnePrefix48(t *testing.T) {
	e := setup(t, func(c *Config, _ *Deps) {
		c.CreateRatePerHour = 100
		c.MaxFleetsPerOrigin = 10
		c.MaxFleetsPerPrefix48 = 2
	})
	for i, remote := range []string{"[2001:db8:1:1::1]:1", "[2001:db8:1:2::1]:1"} {
		if rec := e.post(t, remote, nil); rec.Code != http.StatusCreated {
			t.Fatalf("call %d: %d %s", i+1, rec.Code, rec.Body)
		}
	}
	if rec := e.post(t, "[2001:db8:1:3::1]:1", nil); rec.Code != http.StatusTooManyRequests || !strings.Contains(rec.Body.String(), "too many fleets from this network") {
		t.Fatalf("a third /64 of the /48: %d %s, want 429", rec.Code, rec.Body)
	}
	if rec := e.post(t, "[2001:db8:2:1::1]:1", nil); rec.Code != http.StatusCreated {
		t.Fatalf("another /48: %d, want 201", rec.Code)
	}
	f, err := e.st.ListFleets(context.Background())
	if err != nil || len(f) != 3 {
		t.Fatalf("%d fleets, %v; want 3", len(f), err)
	}
	for _, fleet := range f {
		if !strings.HasSuffix(fleet.Origin, "::/64") || !strings.HasSuffix(fleet.Origin48, "::/48") {
			t.Errorf("fleet %s kept %q and %q as its network", fleet.ID, fleet.Origin, fleet.Origin48)
		}
	}
}

// The count and the creation are one decision here too: creations in flight count.
func TestFleetsOfOneAddressHoldUnderConcurrentCreations(t *testing.T) {
	e := setup(t, func(c *Config, _ *Deps) {
		c.CreateRatePerHour = 100
		c.MaxFleetsPerOrigin = 1
	})
	e.hs.createDelay = 50 * time.Millisecond
	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = e.post(t, "192.0.2.1:"+strconv.Itoa(4000+i), nil).Code
		}()
	}
	wg.Wait()
	created := 0
	for _, c := range codes {
		if c == http.StatusCreated {
			created++
		} else if c != http.StatusTooManyRequests {
			t.Fatalf("codes %v", codes)
		}
	}
	if n, _ := e.st.CountFleets(context.Background()); created != 1 || n != 1 {
		t.Fatalf("created %d (store %d), want 1: %v", created, n, codes)
	}
}

// Phones and PCs join with a code and are not boxes: the quota of boxes does not count them, and
// nothing else did. A fleet holds so many of them.
func TestDeviceCodeRefusedAtTheDevicesOfAFleet(t *testing.T) {
	e := setupKeys(t, func(c *Config, _ *Deps) {
		c.DeviceCodeTTL = 10 * time.Minute
		c.MaxPendingDeviceCodes = 5
		c.MaxDevicesPerFleet = 2
	})
	ctx := context.Background()
	if err := e.st.AddDevice(ctx, e.id, "node-1", now0); err != nil {
		t.Fatal(err)
	}
	if rec := e.deviceCode(e.secret, ip1); rec.Code != http.StatusCreated {
		t.Fatalf("with one device of two: %d %s, want 201", rec.Code, rec.Body)
	}
	if err := e.st.AddDevice(ctx, e.id, "node-2", now0); err != nil {
		t.Fatal(err)
	}
	if rec := e.deviceCode(e.secret, ip1); rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "device quota reached") {
		t.Fatalf("with two devices of two: %d %s, want 409", rec.Code, rec.Body)
	}
	if err := e.st.DeleteDevice(ctx, "node-1"); err != nil {
		t.Fatal(err)
	}
	if rec := e.deviceCode(e.secret, ip1); rec.Code != http.StatusCreated {
		t.Fatalf("after a device left: %d %s, want 201", rec.Code, rec.Body)
	}
}

// The /48 limit is for IPv6: an IPv4 address is one network, bound by the limit of an address
// alone, whatever the other is set to.
func TestThePrefix48LimitLeavesAnIPv4AddressToItsOwn(t *testing.T) {
	e := setup(t, func(c *Config, _ *Deps) {
		c.CreateRatePerHour = 100
		c.MaxFleetsPerOrigin = 3
		c.MaxFleetsPerPrefix48 = 1
	})
	for i := 0; i < 3; i++ {
		if rec := e.post(t, "192.0.2.1:"+strconv.Itoa(4000+i), nil); rec.Code != http.StatusCreated {
			t.Fatalf("fleet %d of an IPv4 address: %d %s, want 201", i+1, rec.Code, rec.Body)
		}
	}
	if rec := e.post(t, "192.0.2.1:5000", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("fourth fleet of the address: %d, want 429", rec.Code)
	}
	// and IPv6 is still counted by /48
	if rec := e.post(t, "[2001:db8:1:1::1]:1", nil); rec.Code != http.StatusCreated {
		t.Fatalf("first fleet of a /48: %d, want 201", rec.Code)
	}
	if rec := e.post(t, "[2001:db8:1:2::1]:1", nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second /64 of the /48: %d, want 429", rec.Code)
	}
}
