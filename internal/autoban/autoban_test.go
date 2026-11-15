package autoban

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func newDet() (*Detector, *clock) {
	c := &clock{time.Unix(1_700_000_000, 0)}
	return New(Config{}, c.now), c
}

func TestTrap(t *testing.T) {
	cases := map[string]string{
		"/.env": "trap", "/.ENV": "trap", "/.git/config": "trap", "/wp-admin/x": "trap", "/actuator?x": "trap",
		"/.environment": "", "/.well-known/.env": "", "/env": "", "/wp-administrator": "",
	}
	for path, want := range cases {
		d, _ := newDet()
		if got, _ := d.Front("1.1.1.1", path, 200); got != want {
			t.Errorf("%s: got %q want %q", path, got, want)
		}
	}
	d, _ := newDet()
	if f, detail := d.Front("k", "/.GIT/x", 200); f != "trap" || detail != "/.git/" {
		t.Errorf("detail = %q %q", f, detail)
	}
}

func TestNotFound(t *testing.T) {
	d, c := newDet()
	for i := 0; i < 19; i++ {
		if f, _ := d.Front("k", "/a", 404); f != "" {
			t.Fatalf("early fault at %d", i)
		}
	}
	if f, detail := d.Front("k", "/a", 404); f != "404" || detail != "20 in 10m0s" {
		t.Fatalf("20th: %q %q", f, detail)
	}
	// the fault reset the counters
	if f, _ := d.Front("k", "/a", 404); f != "" {
		t.Fatal("counters not reset")
	}

	d, c = newDet()
	for i := 0; i < 20; i++ {
		if f, _ := d.Front("k", "/a", 404); f != "" {
			t.Fatal("spread 404s banned")
		}
		c.add(35 * time.Second) // 20 over ~11 min
	}
	d, _ = newDet()
	for i := 0; i < 100; i++ {
		if f, _ := d.Front("k", "/a", 200); f != "" {
			t.Fatal("200 counted")
		}
	}
	for _, p := range []string{"/sitemap.xml", "/robots.txt", "/favicon.ico", "/.well-known/x", "/v1/share", "/V1/fleets/x/devices"} {
		for i := 0; i < 50; i++ {
			if f, _ := d.Front("k", p, 404); f != "" {
				t.Fatalf("%s counted", p)
			}
		}
	}
	_ = c
}

func TestNames(t *testing.T) {
	d, _ := newDet()
	for i := 0; i < 9; i++ {
		if f, _ := d.Unknown("k", fmt.Sprint("n", i)); f != "" {
			t.Fatalf("early fault at %d", i)
		}
	}
	if f, detail := d.Unknown("k", "n9"); f != "names" || detail != "10 in 10m0s" {
		t.Fatalf("10th: %q %q", f, detail)
	}
	d, _ = newDet()
	for i := 0; i < 50; i++ {
		if f, _ := d.Unknown("k", "same"); f != "" {
			t.Fatal("same name banned")
		}
	}
	// names sharing their first 64 bytes are one name
	d, _ = newDet()
	long := strings.Repeat("a", 64)
	for i := 0; i < 20; i++ {
		if f, _ := d.Unknown("k", long+fmt.Sprint(i)); f != "" {
			t.Fatal("truncation missing")
		}
	}
}

func TestBoxExempt(t *testing.T) {
	d, c := newDet()
	d.Box("k")
	if f, _ := d.Front("k", "/.env", 404); f != "" {
		t.Fatal("trap banned an exempt box")
	}
	for i := 0; i < 30; i++ {
		if f, _ := d.Front("k", "/a", 404); f != "" {
			t.Fatal("404 banned an exempt box")
		}
		if f, _ := d.Unknown("k", fmt.Sprint(i)); f != "" {
			t.Fatal("names banned an exempt box")
		}
	}
	c.add(25 * time.Hour)
	if f, _ := d.Front("k", "/.env", 404); f != "trap" {
		t.Fatal("exemption did not expire")
	}
}

func TestBounded(t *testing.T) {
	old := maxKeys
	maxKeys = 2
	defer func() { maxKeys = old }()
	d, _ := newDet()
	d.Box("") // ignored
	for _, k := range []string{"a", "b"} {
		d.Front(k, "/x", 404)
		d.Unknown(k, "n")
		d.Box(k + "box")
	}
	for i := 0; i < 30; i++ {
		if f, _ := d.Front("c", "/x", 404); f != "" {
			t.Fatal("untracked key banned")
		}
		if f, _ := d.Unknown("c", fmt.Sprint(i)); f != "" {
			t.Fatal("untracked key banned")
		}
	}
	if len(d.notFound) > 2 || len(d.names) > 2 || len(d.exempt) > 2 {
		t.Fatal("cap exceeded")
	}
}

func TestFullSweptOncePerSecond(t *testing.T) {
	old := maxKeys
	maxKeys = 3
	defer func() { maxKeys = old }()
	d, c := newDet()
	for _, k := range []string{"a", "b", "c"} {
		d.Front(k, "/x", 404)
		d.Unknown(k, "n")
		d.Box(k)
	}
	before := d.sweeps
	for i := 0; i < 100; i++ { // flood of new keys against a full, live table
		d.Front(fmt.Sprint("x", i), "/x", 404)
		d.Unknown(fmt.Sprint("x", i), "n")
		d.Box(fmt.Sprint("x", i))
	}
	if n := d.sweeps - before; n > 3 {
		t.Fatalf("%d sweeps for 3 maps within one second", n)
	}
	c.add(11 * time.Minute) // everything expired: slots free up at the next sweep
	for _, k := range []string{"n1", "n2", "n3"} {
		d.Front(k, "/x", 404)
	}
	if len(d.notFound) != 3 {
		t.Fatalf("expired keys did not free slots: %d", len(d.notFound))
	}
	d.Unknown("n1", "z")
	if _, ok := d.names["n1"]; !ok {
		t.Fatal("names slot not freed")
	}
	c.add(25 * time.Hour)
	d.Box("fresh")
	if _, ok := d.exempt["fresh"]; !ok {
		t.Fatal("exempt slot not freed")
	}
}
