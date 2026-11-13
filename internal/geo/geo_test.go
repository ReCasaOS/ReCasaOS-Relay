package geo

import (
	"bytes"
	"compress/gzip"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func build(t *testing.T, typ string, nets map[string]mmdbtype.Map) []byte {
	t.Helper()
	w, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: typ, IPVersion: 6, IncludeReservedNetworks: true})
	if err != nil {
		t.Fatal(err)
	}
	for cidr, v := range nets {
		_, n, _ := net.ParseCIDR(cidr)
		if err := w.Insert(n, v); err != nil {
			t.Fatal(err)
		}
	}
	var b bytes.Buffer
	if _, err := w.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func countryDB(t *testing.T) []byte {
	cc := func(c string) mmdbtype.Map {
		return mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(c)}}
	}
	return build(t, "DBIP-Country-Lite", map[string]mmdbtype.Map{
		"203.0.113.0/24": cc("XX"), "198.51.100.0/25": cc("XX"), "192.0.2.0/24": cc("YY"), "2001:db8::/32": cc("XX"),
	})
}

func asnDB(t *testing.T) []byte {
	as := func(n uint32, o string) mmdbtype.Map {
		return mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(n), "autonomous_system_organization": mmdbtype.String(o)}
	}
	return build(t, "DBIP-ASN-Lite", map[string]mmdbtype.Map{
		"203.0.113.0/24": as(64500, "Example Net"), "192.0.2.0/24": as(64501, "Other"),
	})
}

func gz(b []byte) []byte {
	var o bytes.Buffer
	w := gzip.NewWriter(&o)
	w.Write(b)
	w.Close()
	return o.Bytes()
}

func fixtureDir(t *testing.T) *DB {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, countryFile), countryDB(t), 0o644)
	os.WriteFile(filepath.Join(dir, asnFile), asnDB(t), 0o644)
	d := &DB{Dir: dir, BaseURL: "http://127.0.0.1:1/"}
	d.reopen()
	return d
}

func TestCountryAndASNLookup(t *testing.T) {
	d := fixtureDir(t)
	a := netip.MustParseAddr("203.0.113.9")
	if c := d.Country(a); c != "XX" {
		t.Fatalf("country = %q", c)
	}
	if n, o := d.ASN(a); n != 64500 || o != "Example Net" {
		t.Fatalf("asn = %d %q", n, o)
	}
	if c := d.Country(netip.MustParseAddr("::ffff:192.0.2.1")); c != "YY" {
		t.Fatalf("mapped address country = %q", c)
	}
	if c := d.Country(netip.MustParseAddr("8.8.8.8")); c != "" {
		t.Fatalf("unknown country = %q", c)
	}
	if n, _ := d.ASN(netip.MustParseAddr("8.8.8.8")); n != 0 {
		t.Fatalf("unknown asn = %d", n)
	}
}

func TestCountryPrefixes(t *testing.T) {
	d := fixtureDir(t)
	got := d.CountryPrefixes("XX")
	for _, p := range []string{"203.0.113.0/24", "198.51.100.0/25", "2001:db8::/32"} {
		if !slices.Contains(got, netip.MustParsePrefix(p)) {
			t.Errorf("missing %s in %v", p, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("got %v", got)
	}
	if got := d.ASNPrefixes(64501); len(got) != 1 || got[0] != netip.MustParsePrefix("192.0.2.0/24") {
		t.Errorf("asn prefixes %v", got)
	}
}

func TestNoFilesMeansNoPrefixes(t *testing.T) {
	d := &DB{Dir: t.TempDir(), BaseURL: "http://127.0.0.1:1/"}
	if d.CountryPrefixes("XX") != nil || d.ASNPrefixes(1) != nil {
		t.Fatal("prefixes without files")
	}
	if c := d.Country(netip.MustParseAddr("1.1.1.1")); c != "" {
		t.Fatal(c)
	}
	if n, o := d.ASN(netip.MustParseAddr("1.1.1.1")); n != 0 || o != "" {
		t.Fatal(n, o)
	}
	if d.Version() != "" {
		t.Fatal(d.Version())
	}
}

func TestDownloadReplacesOldMonth(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		switch r.URL.Path {
		case "/dbip-country-lite-2026-12.mmdb.gz":
			w.Write(gz(countryDB(t)))
		case "/dbip-asn-lite-2026-12.mmdb.gz":
			w.Write(gz(asnDB(t)))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	now := time.Date(2026, 12, 3, 10, 0, 0, 0, time.UTC)
	d := &DB{Dir: t.TempDir(), BaseURL: srv.URL + "/", Now: func() time.Time { return now }}
	if err := d.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if d.Country(netip.MustParseAddr("203.0.113.1")) != "XX" {
		t.Fatal("downloaded file not in use")
	}
	if d.Version() != time.Now().UTC().Format("2006-01") { // mtime is the real clock, not the fake one
		t.Fatalf("version %q", d.Version())
	}
	h := hits.Load()
	now = now.Add(time.Hour)
	d.Tick(t.Context())
	if hits.Load() != h {
		t.Fatal("second tick the same day hit the network")
	}
}

func TestFailedDownloadRetriesAfterAnHour(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer srv.Close()
	now := time.Date(2026, 12, 3, 10, 0, 0, 0, time.UTC)
	d := &DB{Dir: t.TempDir(), BaseURL: srv.URL + "/", Now: func() time.Time { return now }}
	if d.Tick(t.Context()) == nil {
		t.Fatal("500 accepted")
	}
	h := hits.Load()
	now = now.Add(30 * time.Minute)
	d.Tick(t.Context())
	if hits.Load() != h {
		t.Fatal("retried before the hour")
	}
	now = now.Add(31 * time.Minute)
	d.Tick(t.Context())
	if hits.Load() == h {
		t.Fatal("no retry after the hour")
	}
}

func TestDownloadKeepsOldOnBadGzip(t *testing.T) {
	d := fixtureDir(t)
	old := d.CountryPrefixes("XX")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not gzip")) }))
	defer srv.Close()
	now := time.Now().AddDate(0, 2, 0)
	d.BaseURL, d.Now = srv.URL+"/", func() time.Time { return now }
	if err := d.Tick(t.Context()); err == nil {
		t.Fatal("bad gzip accepted")
	}
	if got := d.CountryPrefixes("XX"); !slices.Equal(got, old) {
		t.Fatalf("old file lost: %v", got)
	}
	if m, _ := filepath.Glob(filepath.Join(d.Dir, "*.tmp*")); len(m) != 0 {
		t.Fatalf("tmp left: %v", m)
	}
	// a valid gzip around a body that is not an mmdb is rejected too
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(gz([]byte("nope"))) }))
	defer srv2.Close()
	d.BaseURL = srv2.URL + "/"
	now = now.Add(2 * time.Hour)
	if err := d.Tick(t.Context()); err == nil {
		t.Fatal("non-mmdb accepted")
	}
	if got := d.CountryPrefixes("XX"); !slices.Equal(got, old) {
		t.Fatalf("old file lost: %v", got)
	}
}
