// Package protect compiles every filter source (allow list, manual bans, feeds, community bans,
// suspended names, per-box settings) into the one JSON snapshot that `share` polls.
package protect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/feeds"
	"github.com/ReCasaOS/recasaos-relay/internal/geo"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// maxAge: Current rebuilds a snapshot older than this even without Invalidate (bans expire, feeds refresh).
const maxAge = 30 * time.Second

type Manual struct {
	Address []string `json:"address"`
	Range   []string `json:"range"`
	ASN     []string `json:"asn"`
	Country []string `json:"country"`
}

type Community struct {
	Address []string `json:"address"`
	Range   []string `json:"range"`
}

type NameFilter struct {
	Filter    bool `json:"filter"`
	Community bool `json:"community"`
}

// Snapshot is the body of GET /internal/share/filter.
type Snapshot struct {
	Version   string                `json:"version"`
	Allow     []string              `json:"allow"`
	Manual    Manual                `json:"manual"`
	External  map[string][]string   `json:"external"`
	Community Community             `json:"community"`
	Names     map[string]NameFilter `json:"names"`
	Suspended []string              `json:"suspended"`
}

type Compiler struct {
	Store store.Store
	Feeds *feeds.Fetcher
	Geo   *geo.DB
	Now   func() time.Time // default time.Now

	mu      sync.Mutex // one build at a time; guards the cache below
	body    []byte
	version string
	builtAt time.Time
	dirty   bool
	expand  map[string][]string // geo expansions, valid for expandVer

	expandVer string
	allow     atomic.Pointer[[]netip.Prefix] // allow list of the last build
}

func (c *Compiler) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Invalidate makes the next Current rebuild.
func (c *Compiler) Invalidate() {
	c.mu.Lock()
	c.dirty = true
	c.mu.Unlock()
}

// Current returns the cached snapshot, rebuilt after Invalidate or when older than 30 s.
func (c *Compiler) Current(ctx context.Context) ([]byte, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.body != nil && !c.dirty && c.now().Sub(c.builtAt) < maxAge {
		return c.body, c.version, nil
	}
	body, version, err := c.build(ctx)
	if err != nil {
		return nil, "", err
	}
	c.body, c.version, c.builtAt, c.dirty = body, version, c.now(), false
	return body, version, nil
}

// Build compiles a fresh snapshot, bypassing the cache.
func (c *Compiler) Build(ctx context.Context) ([]byte, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.build(ctx)
}

// Allowed reports whether an allow-list prefix covers p, from the last build (the store before any).
func (c *Compiler) Allowed(p netip.Prefix) bool {
	list := c.allow.Load()
	if list == nil {
		entries, err := c.Store.AllowList(context.Background())
		if err != nil {
			return false
		}
		l := parseAll(allowStrings(entries))
		list = &l
	}
	a := p.Addr().Unmap()
	return slices.ContainsFunc(*list, func(q netip.Prefix) bool { return q.Bits() <= p.Bits() && q.Contains(a) })
}

func allowStrings(es []store.AllowEntry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Prefix)
	}
	return out
}

// norm turns an address or a prefix into a masked prefix.
func norm(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func parseAll(ss []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		if p, ok := norm(s); ok {
			out = append(out, p)
		}
	}
	return out
}

// strs renders prefixes sorted and deduplicated, never nil (JSON `[]`).
func strs(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func (c *Compiler) geoPrefixes(kind, value string) []netip.Prefix {
	if c.Geo == nil {
		return nil
	}
	if v := c.Geo.Version(); v != c.expandVer || c.expand == nil {
		c.expand, c.expandVer = map[string][]string{}, v
	}
	k := kind + ":" + value
	if s, ok := c.expand[k]; ok {
		return parseAll(s)
	}
	var ps []netip.Prefix
	if kind == "country" {
		ps = c.Geo.CountryPrefixes(value)
	} else if n, err := strconv.ParseUint(value, 10, 32); err == nil {
		ps = c.Geo.ASNPrefixes(uint(n))
	}
	c.expand[k] = strs(ps)
	return ps
}

func (c *Compiler) build(ctx context.Context) ([]byte, string, error) {
	now := c.now()
	s := Snapshot{External: map[string][]string{}, Names: map[string]NameFilter{}}

	allow, err := c.Store.AllowList(ctx)
	if err != nil {
		return nil, "", err
	}
	al := parseAll(allowStrings(allow))
	s.Allow = strs(al)

	manual, err := c.Store.ManualBans(ctx, now)
	if err != nil {
		return nil, "", err
	}
	var addr, rng, asn, country []netip.Prefix
	for _, m := range manual {
		switch m.Kind {
		case "address", "range":
			if p, ok := norm(m.Value); ok {
				if m.Kind == "address" {
					addr = append(addr, p)
				} else {
					rng = append(rng, p)
				}
			}
		case "asn":
			asn = append(asn, c.geoPrefixes("asn", m.Value)...)
		case "country":
			country = append(country, c.geoPrefixes("country", m.Value)...)
		}
	}
	s.Manual = Manual{Address: strs(addr), Range: strs(rng), ASN: strs(asn), Country: strs(country)}

	fs, err := c.Store.Feeds(ctx)
	if err != nil {
		return nil, "", err
	}
	for _, f := range fs {
		if !f.Enabled || c.Feeds == nil {
			continue
		}
		if ps, err := c.Feeds.Load(f.ID); err == nil {
			s.External[f.Name] = strs(ps)
		}
	}

	bans, err := c.Store.ActiveBans(ctx, now)
	if err != nil {
		return nil, "", err
	}
	var ca, cr []netip.Prefix
	for _, b := range bans {
		if p, ok := norm(b.Key); ok {
			if b.Kind == "range" {
				cr = append(cr, p)
			} else {
				ca = append(ca, p)
			}
		}
	}
	s.Community = Community{Address: strs(ca), Range: strs(cr)}

	names, err := c.Store.ProtectedNames(ctx)
	if err != nil {
		return nil, "", err
	}
	for n, p := range names {
		s.Names[n] = NameFilter{Filter: p.RelayFilter, Community: p.RelayFilter && p.ShareBans}
	}

	susp, err := c.Store.SuspendedNames(ctx)
	if err != nil {
		return nil, "", err
	}
	s.Suspended = append([]string{}, susp...)
	slices.Sort(s.Suspended)

	raw, err := json.Marshal(s) // Version still empty
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	s.Version = hex.EncodeToString(sum[:])
	body, err := json.Marshal(s)
	if err != nil {
		return nil, "", err
	}
	c.allow.Store(&al)
	return body, s.Version, nil
}
