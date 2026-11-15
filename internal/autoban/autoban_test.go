package autoban

import (
	"bytes"
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

// hit3 sends three requests for path and returns the last answer: a trap needs three within the hour.
func hit3(d *Detector, key, path string, status int) (fault, detail string) {
	for i := 0; i < 3; i++ {
		fault, detail = d.Front(key, path, status)
	}
	return
}

func TestTrap(t *testing.T) {
	cases := map[string]string{
		"/.env": "trap", "/.ENV": "trap", "/.git/config": "trap", "/wp-admin/x": "trap", "/actuator?x": "trap",
		"/.environment": "", "/.well-known/.env": "", "/env": "", "/wp-administrator": "",
	}
	for path, want := range cases {
		d, _ := newDet()
		if got, _ := hit3(d, "1.1.1.1", path, 200); got != want {
			t.Errorf("%s: got %q want %q", path, got, want)
		}
	}
	d, _ := newDet()
	if f, detail := hit3(d, "k", "/.GIT/x", 200); f != "trap" || detail != "/.git/" {
		t.Errorf("detail = %q %q", f, detail)
	}
}

func TestTrapNeedsThreeInAnHour(t *testing.T) {
	d, c := newDet()
	for i, p := range []string{"/.env", "/wp-login.php"} {
		if f, _ := d.Front("k", p, 200); f != "" {
			t.Fatalf("hit %d banned", i+1)
		}
	}
	// different trap paths count together; the detail is the entry of the last hit
	if f, detail := d.Front("k", "/.aws/credentials", 200); f != "trap" || detail != "/.aws/" {
		t.Fatalf("3rd: %q %q", f, detail)
	}
	if f, _ := d.Front("k", "/.env", 200); f != "" {
		t.Fatal("counters not reset")
	}

	d, c = newDet()
	for i := 0; i < 3; i++ { // 3 hits over 2 h: never 3 within the hour
		if f, _ := d.Front("k", "/.env", 200); f != "" {
			t.Fatalf("spread hit %d banned", i+1)
		}
		c.add(time.Hour)
	}
	// two hits then a third just inside the hour of the second
	d, c = newDet()
	d.Front("k", "/.env", 200)
	c.add(40 * time.Minute)
	d.Front("k", "/.env", 200)
	c.add(40 * time.Minute)
	if f, _ := d.Front("k", "/.env", 200); f != "" {
		t.Fatal("first hit is 80 min old and must not count")
	}
}

func TestTrapIsNotAlsoA404(t *testing.T) {
	d, _ := newDet()
	for i := 0; i < 2; i++ {
		d.Front("k", "/.env", 404)
	}
	for i := 0; i < 18; i++ { // 2 trap 404s + 18 plain = 20 only if the traps counted
		if f, _ := d.Front("k", "/a", 404); f != "" {
			t.Fatalf("trap 404s counted toward the burst (fault %q at %d)", f, i)
		}
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
	for i := 0; i < 5; i++ {
		if f, _ := d.Front("k", "/.env", 404); f != "" {
			t.Fatal("trap banned an exempt box")
		}
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
	if f, _ := hit3(d, "k", "/.env", 404); f != "trap" {
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
		d.Front(k, "/.env", 404)
		d.Unknown(k, "n")
		d.Box(k + "box")
	}
	for i := 0; i < 30; i++ {
		if f, _ := d.Front("c", "/x", 404); f != "" {
			t.Fatal("untracked key banned")
		}
		if f, _ := d.Front("c", "/.env", 404); f != "" {
			t.Fatal("untracked key banned")
		}
		if f, _ := d.Unknown("c", fmt.Sprint(i)); f != "" {
			t.Fatal("untracked key banned")
		}
	}
	if len(d.notFound) > 2 || len(d.traps) > 2 || len(d.names) > 2 || len(d.exempt) > 2 {
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

func TestSaveLoadCarriesCountsOverARestart(t *testing.T) {
	d, c := newDet()
	d.Front("203.0.113.1/32", "/.env", 404) // 2 of 3 traps
	d.Front("203.0.113.1/32", "/.env", 404)
	d.Unknown("203.0.113.2/32", "a")
	d.Box("203.0.113.3/32")
	var b bytes.Buffer
	if err := d.Save(&b); err != nil {
		t.Fatal(err)
	}
	n := New(Config{}, c.now)
	if err := n.Load(&b); err != nil {
		t.Fatal(err)
	}
	if f, _ := n.Front("203.0.113.1/32", "/.git/config", 404); f != "trap" {
		t.Errorf("third trap after the restart: %q, want trap", f)
	}
	if f, _ := hit3(n, "203.0.113.3/32", "/.env", 404); f != "" {
		t.Errorf("the box exemption was lost: %q", f)
	}
	for i := 0; i < 8; i++ {
		n.Unknown("203.0.113.2/32", fmt.Sprint("n", i))
	}
	if f, _ := n.Unknown("203.0.113.2/32", "last"); f != "names" {
		t.Errorf("tenth name after the restart: %q, want names", f)
	}
	if err := New(Config{}, c.now).Load(strings.NewReader(`{"Names":{"k":null}}`)); err != nil {
		t.Errorf("null entry: %v", err)
	}
	if New(Config{}, c.now).Load(strings.NewReader("not json")) == nil {
		t.Error("garbage loaded")
	}
}

func TestSetConfigAppliesAtOnce(t *testing.T) {
	d, _ := newDet()
	d.Front("203.0.113.1/32", "/.env", 404)
	d.SetConfig(Config{Traps: 2})
	if got := d.Config(); got.Traps != 2 || got.NotFound != defaultNotFound || got.Window != defaultWindow {
		t.Fatalf("config = %+v", got)
	}
	if f, _ := d.Front("203.0.113.1/32", "/.env", 404); f != "trap" {
		t.Errorf("second trap under a limit of 2: %q", f)
	}
}
