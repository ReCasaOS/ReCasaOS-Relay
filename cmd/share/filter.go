package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

var (
	errBuild = errors.New("cannot build the request")
	errBody  = errors.New("unreadable body")
)

func errStatus(code int) error { return fmt.Errorf("enrolment answered %d", code) }

// filterClient has its own, longer timeout: enrolment may build the snapshot inside the request, and the
// timeout counts the body read too.
var filterClient = &http.Client{Timeout: 60 * time.Second}

// maxSnapshot bounds the body of GET /internal/share/filter (1 000 000 entries is a few tens of MiB).
const maxSnapshot = 64 << 20

type nameFilter struct {
	Filter    bool `json:"filter"`
	Community bool `json:"community"`
}

// snapshot is the body of GET /internal/share/filter (see the contract).
type snapshot struct {
	Version string   `json:"version"`
	Allow   []string `json:"allow"`
	Manual  struct {
		Address []string `json:"address"`
		Range   []string `json:"range"`
		ASN     []string `json:"asn"`
		Country []string `json:"country"`
	} `json:"manual"`
	External  map[string][]string `json:"external"`
	Community struct {
		Address []string `json:"address"`
		Range   []string `json:"range"`
	} `json:"community"`
	Names     map[string]nameFilter `json:"names"`
	Suspended []string              `json:"suspended"`
}

type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || a.hi == b.hi && a.lo < b.lo }

func (a u128) next() u128 { // a+1; the caller rules out the maximum
	if a.lo++; a.lo == 0 {
		a.hi++
	}
	return a
}

func u128Of(a netip.Addr) u128 {
	b := a.As16()
	var u u128
	for i := 0; i < 8; i++ {
		u.hi, u.lo = u.hi<<8|uint64(b[i]), u.lo<<8|uint64(b[i+8])
	}
	return u
}

type r6 struct{ lo, hi u128 }

// prefixSet is a set of address ranges per family, sorted and merged, searched by bisection. An IPv4
// range is one uint64, from<<32|to, so that sorting the slice sorts by start and 500 000 entries take 4 MB.
type prefixSet struct {
	v4 []uint64
	v6 []r6
}

// newPrefixSet skips entries that do not parse as a prefix.
func newPrefixSet(prefixes []string) prefixSet {
	var s prefixSet
	for _, e := range prefixes {
		p, err := netip.ParsePrefix(e)
		if err != nil {
			continue
		}
		a, bits := p.Addr(), p.Bits()
		if a.Is4In6() && bits >= 96 {
			a, bits = a.Unmap(), bits-96
		}
		a = netip.PrefixFrom(a, bits).Masked().Addr()
		if a.Is4() {
			b := a.As4()
			lo := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
			s.v4 = append(s.v4, uint64(lo)<<32|uint64(lo|uint32(uint64(1)<<(32-bits)-1)))
			continue
		}
		lo, hi := u128Of(a), u128Of(a)
		if h := 128 - bits; h >= 64 {
			hi.hi |= ^uint64(0) >> (128 - h)
			hi.lo = ^uint64(0)
		} else if h > 0 {
			hi.lo |= ^uint64(0) >> (64 - h)
		}
		s.v6 = append(s.v6, r6{lo, hi})
	}
	slices.Sort(s.v4)
	out := s.v4[:0]
	for _, r := range s.v4 {
		if n := len(out); n > 0 && uint64(uint32(r>>32)) <= uint64(uint32(out[n-1]))+1 {
			if uint32(r) > uint32(out[n-1]) {
				out[n-1] = out[n-1]&^0xffffffff | r&0xffffffff
			}
			continue
		}
		out = append(out, r)
	}
	s.v4 = slices.Clip(out)
	slices.SortFunc(s.v6, func(a, b r6) int {
		switch {
		case a.lo.less(b.lo):
			return -1
		case b.lo.less(a.lo):
			return 1
		}
		return 0
	})
	o6 := s.v6[:0]
	for _, r := range s.v6 {
		if n := len(o6); n > 0 {
			last := &o6[n-1]
			if last.hi == (u128{^uint64(0), ^uint64(0)}) || !last.hi.next().less(r.lo) { // overlaps or touches
				if last.hi.less(r.hi) {
					last.hi = r.hi
				}
				continue
			}
		}
		o6 = append(o6, r)
	}
	s.v6 = slices.Clip(o6)
	return s
}

func (s prefixSet) contains(a netip.Addr) bool {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		x := uint64(b[0])<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
		key := x<<32 | 0xffffffff
		i := sort.Search(len(s.v4), func(i int) bool { return s.v4[i] > key })
		return i > 0 && uint64(uint32(s.v4[i-1])) >= x
	}
	x := u128Of(a)
	i := sort.Search(len(s.v6), func(i int) bool { return x.less(s.v6[i].lo) })
	return i > 0 && !s.v6[i-1].hi.less(x)
}

type feedSet struct {
	name string
	set  prefixSet
}

// filter is one compiled snapshot. It is immutable once built.
type filter struct {
	version                          string
	allow                            prefixSet
	mAddress, mRange, mASN, mCountry prefixSet
	ext                              []feedSet // by feed name
	cAddress, cRange                 prefixSet
	names                            map[string]nameFilter
	suspended                        map[string]struct{}
}

func parseFilter(body []byte) (*filter, error) {
	var s snapshot
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, err
	}
	f := &filter{
		version: s.Version, allow: newPrefixSet(s.Allow),
		mAddress: newPrefixSet(s.Manual.Address), mRange: newPrefixSet(s.Manual.Range),
		mASN: newPrefixSet(s.Manual.ASN), mCountry: newPrefixSet(s.Manual.Country),
		cAddress: newPrefixSet(s.Community.Address), cRange: newPrefixSet(s.Community.Range),
		names: s.Names, suspended: make(map[string]struct{}, len(s.Suspended)),
	}
	for n, e := range s.External {
		f.ext = append(f.ext, feedSet{n, newPrefixSet(e)})
	}
	slices.SortFunc(f.ext, func(a, b feedSet) int { return strings.Compare(a.name, b.name) })
	for _, n := range s.Suspended {
		f.suspended[n] = struct{}{}
	}
	return f, nil
}

// decide says why the visitor at a is refused for the share name, and by which source; "" means pass.
// Order: allow list, operator bans, suspended name, then the box's own choices (feeds, community list).
// A name absent from the snapshot (a box that never set its protection) only has the first three.
func (f *filter) decide(a netip.Addr, name string) (reason, source string) {
	if f.allow.contains(a) {
		return "", ""
	}
	switch {
	case f.mAddress.contains(a):
		return "manual", "address"
	case f.mRange.contains(a):
		return "manual", "range"
	case f.mASN.contains(a):
		return "manual", "asn"
	case f.mCountry.contains(a):
		return "manual", "country"
	}
	if _, ok := f.suspended[name]; ok {
		return "suspended", ""
	}
	nf, ok := f.names[name]
	if !ok || !nf.Filter {
		return "", ""
	}
	for _, e := range f.ext {
		if e.set.contains(a) {
			return "external", e.name
		}
	}
	if nf.Community {
		switch {
		case f.cAddress.contains(a):
			return "community", "address"
		case f.cRange.contains(a):
			return "community", "range"
		}
	}
	return "", ""
}

// remoteAddr is the TCP peer of c, IPv4-mapped addresses as IPv4. Anything else is not filtered.
func remoteAddr(c net.Conn) (netip.Addr, bool) {
	t, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return netip.Addr{}, false
	}
	a, ok := netip.AddrFromSlice(t.IP)
	return a.Unmap(), ok
}

// filterHolder is the filter in force: nil until the first snapshot, which lets everything through.
type filterHolder struct {
	cur atomic.Pointer[filter]

	cuts cutLog // filter cuts in the journal

	// touched by the poller only
	loggedNone, down bool
}

func (h *filterHolder) get() *filter {
	if h == nil {
		return nil
	}
	return h.cur.Load()
}

// poll fetches the snapshot once. 304, an error or a bad body keep the filter in force; the log says once
// when polling starts failing and once when it recovers (no URL, no address: the URL is internal).
func (h *filterHolder) poll(ctx context.Context, enrolmentURL string) {
	f, err := h.fetch(ctx, enrolmentURL)
	switch {
	case err != nil && !h.down:
		h.down = true
		log.Printf("share: filter snapshot: %v; keeping the current filter", err)
	case err == nil && h.down:
		h.down = false
		log.Printf("share: filter snapshot: reachable again")
	}
	if f != nil {
		h.cur.Store(f)
		h.loggedNone = false
	}
	if h.get() == nil && !h.loggedNone {
		h.loggedNone = true
		log.Printf("share: no filter yet, letting connections through")
	}
}

func (h *filterHolder) fetch(ctx context.Context, enrolmentURL string) (*filter, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, enrolmentURL+"/internal/share/filter", nil)
	if err != nil {
		return nil, errBuild
	}
	if cur := h.get(); cur != nil && cur.version != "" {
		req.Header.Set("If-None-Match", `"`+cur.version+`"`)
	}
	resp, err := doWith(filterClient, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, nil
	case http.StatusOK:
	default:
		return nil, errStatus(resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSnapshot+1))
	if err != nil || len(body) > maxSnapshot {
		return nil, errBody
	}
	f, err := parseFilter(body)
	if err != nil {
		return nil, errBody
	}
	return f, nil
}
