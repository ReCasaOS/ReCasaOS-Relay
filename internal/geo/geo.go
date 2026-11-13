// Package geo answers country and AS questions from the DB-IP Lite files and keeps them fresh.
package geo

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

const (
	countryFile = "dbip-country-lite.mmdb"
	asnFile     = "dbip-asn-lite.mmdb"
	defaultBase = "https://download.db-ip.com/free/"
	maxGz       = 200 << 20
	maxRaw      = 1 << 30
	okEvery     = 24 * time.Hour
	retryEvery  = time.Hour
)

// DB holds the two files in Dir. Zero Client, Now and BaseURL mean the defaults.
type DB struct {
	Dir     string
	Client  *http.Client
	Now     func() time.Time
	BaseURL string
	MaxRaw  int64 // cap on one decompressed file; 0 means 1 GiB

	mu      sync.RWMutex // lookups hold it shared; a swapped-out reader is closed under the write lock
	country *maxminddb.Reader
	asn     *maxminddb.Reader
	loaded  bool

	checked time.Time // Tick-only state: one caller at a time
	failed  bool
}

func (d *DB) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *DB) path(name string) string { return filepath.Join(d.Dir, name) }

// reopen swaps in readers for whatever files can be opened now and reports whether it opened any.
func (d *DB) reopen() bool {
	c, _ := maxminddb.Open(d.path(countryFile))
	a, _ := maxminddb.Open(d.path(asnFile))
	d.mu.Lock()
	defer d.mu.Unlock()
	d.loaded = true
	// a file that cannot be opened keeps the previous good reader
	if c != nil {
		if d.country != nil {
			d.country.Close()
		}
		d.country = c
	}
	if a != nil {
		if d.asn != nil {
			d.asn.Close()
		}
		d.asn = a
	}
	return c != nil || a != nil
}

// month is the "YYYY-MM" a file was written in, "" when it is missing.
func (d *DB) month(name string) string {
	fi, err := os.Stat(d.path(name))
	if err != nil {
		return ""
	}
	return fi.ModTime().UTC().Format("2006-01")
}

// Version is the file month, "" until the files are open and unless both exist; with two
// different months, the older. An expansion cached before the first open is so never reused.
func (d *DB) Version() string {
	d.mu.RLock()
	loaded := d.loaded
	d.mu.RUnlock()
	if !loaded {
		return ""
	}
	c, a := d.month(countryFile), d.month(asnFile)
	if c == "" || a == "" {
		return ""
	}
	return min(c, a)
}

// Tick opens the files on first use, then at most once a day (an hour after a failure) fetches
// the current month's files when they are missing or older. A failure keeps the old files.
// changed is true when the files in use changed: opened for the first time or replaced.
func (d *DB) Tick(ctx context.Context) (changed bool, err error) {
	d.mu.RLock()
	loaded := d.loaded
	d.mu.RUnlock()
	if !loaded {
		changed = d.reopen()
	}
	now := d.now()
	wait := okEvery
	if d.failed {
		wait = retryEvery
	}
	if !d.checked.IsZero() && now.Sub(d.checked) < wait {
		return changed, nil
	}
	d.checked, d.failed = now, false
	month := now.UTC().Format("2006-01")
	var errs []error
	updated := false
	for _, f := range []struct{ file, kind string }{{countryFile, "country"}, {asnFile, "asn"}} {
		if d.month(f.file) >= month {
			continue
		}
		if err := d.fetch(ctx, f.file, fmt.Sprintf("dbip-%s-lite-%s.mmdb.gz", f.kind, month)); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.kind, err))
			continue
		}
		updated = true
		log.Printf("geo: updated %s database to %s", f.kind, month)
	}
	if updated {
		d.reopen()
	}
	d.failed = len(errs) > 0
	return changed || updated, errors.Join(errs...)
}

func (d *DB) fetch(ctx context.Context, file, remote string) error {
	base := d.BaseURL
	if base == "" {
		base = defaultBase
	}
	cl := d.Client
	if cl == nil {
		cl = &http.Client{Timeout: 5 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+remote, nil)
	if err != nil {
		return err
	}
	resp, err := cl.Do(req)
	if ue := (*url.Error)(nil); errors.As(err, &ue) { // its message carries the URL: log only the cause
		err = ue.Err
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	zr, err := gzip.NewReader(io.LimitReader(resp.Body, maxGz))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(d.Dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(d.Dir, file+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	limit := d.MaxRaw
	if limit == 0 {
		limit = maxRaw
	}
	n, err := io.Copy(tmp, io.LimitReader(zr, limit+1))
	if err == nil && n > limit {
		err = errors.New("decompressed file too large")
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	r, err := maxminddb.Open(tmp.Name())
	if err != nil {
		return err
	}
	r.Close()
	return os.Rename(tmp.Name(), d.path(file))
}

type countryRecord struct {
	Country struct {
		ISO string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

type asnRecord struct {
	N   uint   `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

// Country is the ISO country of a, "" when unknown.
func (d *DB) Country(a netip.Addr) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var rec countryRecord
	if d.country == nil || d.country.Lookup(a.Unmap()).Decode(&rec) != nil {
		return ""
	}
	return rec.Country.ISO
}

// ASN is the AS number and organisation of a, zero values when unknown.
func (d *DB) ASN(a netip.Addr) (uint, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var rec asnRecord
	if d.asn == nil || d.asn.Lookup(a.Unmap()).Decode(&rec) != nil {
		return 0, ""
	}
	return rec.N, rec.Org
}

// CountryPrefixes lists every network of country cc; nil without the file.
func (d *DB) CountryPrefixes(cc string) []netip.Prefix {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.country == nil {
		return nil
	}
	var out []netip.Prefix
	for res := range d.country.Networks() {
		var rec countryRecord
		if res.Decode(&rec) == nil && rec.Country.ISO == cc {
			out = append(out, unmap(res.Prefix()))
		}
	}
	return out
}

// ASNPrefixes lists every network of AS asn; nil without the file.
func (d *DB) ASNPrefixes(asn uint) []netip.Prefix {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.asn == nil {
		return nil
	}
	var out []netip.Prefix
	for res := range d.asn.Networks() {
		var rec asnRecord
		if res.Decode(&rec) == nil && rec.N == asn {
			out = append(out, unmap(res.Prefix()))
		}
	}
	return out
}

// unmap turns an IPv4 network stored in the IPv6 tree (::ffff:a.b.c.d/96+n) into an IPv4 prefix.
func unmap(p netip.Prefix) netip.Prefix {
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p
}
