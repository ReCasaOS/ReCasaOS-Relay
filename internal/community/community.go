// Package community computes the community ban list from the bans that boxes share: an address
// reported by two eligible fleets within 24 h is banned for every sharing box, with strikes, and
// a range is banned when five of its addresses are.
package community

import (
	"cmp"
	"context"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

const (
	day          = 24 * time.Hour
	window       = day             // reports from two fleets within this open a ban
	strikeWindow = 30 * day        // a ban starting this soon after the previous one ended is a repeat
	maxAhead     = 2 * time.Minute // a ban cannot start later than this from now
	rangeMin     = 5               // address bans in one /24 or /48 that ban the range
	asnMin       = 10              // range bans in one ASN that flag it
)

// tiers is the length of strike 1, 2, 3+; 0 is permanent.
var tiers = [3]time.Duration{day, 7 * day, 0}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

type Engine struct {
	Store store.Store
	Now   func() time.Time
	// Allowed is true when the relay allow list covers the prefix; nil allows nothing.
	Allowed func(netip.Prefix) bool
	// MinFleetAge is how old a fleet must be for its reports to count; zero means 7 days.
	MinFleetAge time.Duration
}

type Item struct {
	Key, Reason, App string
	Since            time.Time
}

type ASNFlag struct {
	ASN    uint
	Org    string
	Ranges int
}

// Key returns the community key of an address or of a /32 (IPv4) or /64 (IPv6) prefix: the
// address as a /32, or its /64. Addresses never kept (private, CGNAT, loopback…) are false.
func Key(s string) (string, bool) {
	var a netip.Addr
	bits := -1
	if p, err := netip.ParsePrefix(s); err == nil {
		a, bits = p.Addr(), p.Bits()
	} else if a, err = netip.ParseAddr(s); err != nil || a.Zone() != "" {
		return "", false
	}
	if a.Is4In6() { // checked as IPv4: Prefix.Contains does not match a mapped address
		a = a.Unmap()
		if bits >= 0 {
			bits -= 96
		}
	}
	want := 64
	if a.Is4() {
		want = 32
	}
	if bits >= 0 && bits != want {
		return "", false
	}
	if !a.IsGlobalUnicast() || a.IsPrivate() || cgnat.Contains(a) {
		return "", false
	}
	return netip.PrefixFrom(a, want).Masked().String(), true
}

func (e *Engine) now() time.Time {
	if e.Now == nil {
		return time.Now()
	}
	return e.Now()
}

func (e *Engine) allowed(p netip.Prefix) bool { return e.Allowed != nil && e.Allowed(p) }

// Accept stores the items of box ref that pass the acceptance rules and drops the others
// silently: sharing on, fleet old enough with a share name, and the address seen reaching this
// box through the relay from 24 h before the ban started. Field rules are the route's job.
func (e *Engine) Accept(ctx context.Context, ref store.BoxRef, items []Item) error {
	now := e.now()
	p, ok, err := e.Store.GetProtection(ctx, ref.NodeID)
	if err != nil || !ok || !p.ShareBans {
		return err
	}
	age := e.MinFleetAge
	if age == 0 {
		age = 7 * day
	}
	if ok, err := e.Store.FleetEligible(ctx, ref.FleetID, now.Add(-age)); err != nil || !ok {
		return err
	}
	for _, it := range items {
		key, ok := Key(it.Key)
		if !ok || it.Since.IsZero() || it.Since.Before(now.Add(-day)) || it.Since.After(now.Add(maxAhead)) {
			continue
		}
		seen, err := e.Store.SeenBetween(ctx, key, ref.NodeID, it.Since.Add(-day), now)
		if err != nil {
			return err
		}
		if !seen {
			continue
		}
		r := store.Report{NodeID: ref.NodeID, FleetID: ref.FleetID, Key: key, Reason: it.Reason, App: it.App, Since: it.Since}
		if err := e.Store.AddReport(ctx, r, now); err != nil {
			return err
		}
	}
	return nil
}

// evidence is what opens a ban: the fleets and reasons behind it.
type evidence struct{ fleets, reasons map[string]bool }

func (v *evidence) add(fleet string, reasons ...string) {
	if v.fleets == nil {
		v.fleets, v.reasons = map[string]bool{}, map[string]bool{}
	}
	if fleet != "" {
		v.fleets[fleet] = true
	}
	for _, r := range reasons {
		v.reasons[r] = true
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// open opens a ban on key at now with the strike its history gives.
func (e *Engine) open(ctx context.Context, key, kind string, now time.Time, ev evidence) error {
	n, lastEnd, err := e.Store.Strikes(ctx, key)
	if err != nil {
		return err
	}
	strike := 1
	if n > 0 && now.Sub(lastEnd) < strikeWindow {
		strike = n + 1
	}
	var until time.Time
	if d := tiers[min(strike, len(tiers))-1]; d > 0 {
		until = now.Add(d)
	}
	openers := sortedKeys(ev.fleets)
	return e.Store.OpenBan(ctx, store.CommunityBan{
		Key: key, Kind: kind, Strike: strike, Since: now, Until: until,
		Reasons: strings.Join(sortedKeys(ev.reasons), ","), Fleets: len(openers),
	}, openers)
}

// rangeOf is the /24 or /48 holding an address key.
func rangeOf(p netip.Prefix) netip.Prefix {
	bits := 48
	if p.Addr().Is4() {
		bits = 24
	}
	return netip.PrefixFrom(p.Addr(), bits).Masked()
}

// Tick ends the expired bans, then opens the address and range bans that are due, and reports
// whether it opened any (an ended ban has already left ActiveBans at its end time). Only evidence
// newer than the end of a key's previous ban counts, so a ban that ends or is lifted is not
// reopened (and escalated) on the reports or bans that opened it. Running it twice is a no-op.
func (e *Engine) Tick(ctx context.Context) (opened bool, err error) {
	now := e.now()
	if err := e.Store.EndExpired(ctx, now); err != nil {
		return false, err
	}
	reports, err := e.Store.ReportsSince(ctx, now.Add(-window))
	if err != nil {
		return false, err
	}
	byKey := map[string][]store.Report{}
	for _, r := range reports {
		byKey[r.Key] = append(byKey[r.Key], r)
	}
	active, err := e.activeKeys(ctx, now)
	if err != nil {
		return false, err
	}
	for _, key := range slices.Sorted(maps.Keys(byKey)) {
		p, err := netip.ParsePrefix(key)
		if err != nil || active[key] || e.allowed(p) {
			continue
		}
		_, lastEnd, err := e.Store.Strikes(ctx, key)
		if err != nil {
			return opened, err
		}
		var ev evidence
		for _, r := range byKey[key] {
			if r.Since.After(lastEnd) {
				ev.add(r.FleetID, r.Reason)
			}
		}
		if len(ev.fleets) < 2 {
			continue
		}
		if err := e.open(ctx, key, "address", now, ev); err != nil {
			return opened, err
		}
		opened = true
	}
	ranges, err := e.tickRanges(ctx, now, byKey)
	return opened || ranges, err
}

func (e *Engine) tickRanges(ctx context.Context, now time.Time, byKey map[string][]store.Report) (opened bool, err error) {
	bans, err := e.Store.ActiveBans(ctx, now)
	if err != nil {
		return false, err
	}
	members := map[netip.Prefix][]store.CommunityBan{}
	active := map[string]bool{}
	for _, b := range bans {
		active[b.Key] = true
		if p, err := netip.ParsePrefix(b.Key); err == nil && b.Kind == "address" {
			members[rangeOf(p)] = append(members[rangeOf(p)], b)
		}
	}
	rs := slices.SortedFunc(maps.Keys(members), func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	for _, rng := range rs {
		key := rng.String()
		if len(members[rng]) < rangeMin || active[key] || e.allowed(rng) {
			continue
		}
		_, lastEnd, err := e.Store.Strikes(ctx, key)
		if err != nil {
			return opened, err
		}
		// shortcut: openers are the fleets of the last 24 h reports on member keys; a member
		// opened earlier (a 7-day ban) adds its reasons but no fleet.
		var ev evidence
		n := 0
		for _, b := range members[rng] {
			if !b.Since.After(lastEnd) {
				continue
			}
			n++
			ev.add("", strings.Split(b.Reasons, ",")...)
			for _, r := range byKey[b.Key] {
				ev.add(r.FleetID)
			}
		}
		if n < rangeMin {
			continue
		}
		if err := e.open(ctx, key, "range", now, ev); err != nil {
			return opened, err
		}
		opened = true
	}
	return opened, nil
}

func (e *Engine) activeKeys(ctx context.Context, now time.Time) (map[string]bool, error) {
	bans, err := e.Store.ActiveBans(ctx, now)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, b := range bans {
		out[b.Key] = true
	}
	return out, nil
}

// FlaggedASNs returns the ASNs holding asnMin or more of the range bans given, by the first
// address of each range; ASN 0 (unknown) is never flagged.
func FlaggedASNs(bans []store.CommunityBan, asnOf func(netip.Addr) (uint, string)) []ASNFlag {
	byASN := map[uint]*ASNFlag{}
	for _, b := range bans {
		p, err := netip.ParsePrefix(b.Key)
		if err != nil || b.Kind != "range" {
			continue
		}
		asn, org := asnOf(p.Masked().Addr())
		if asn == 0 {
			continue
		}
		if byASN[asn] == nil {
			byASN[asn] = &ASNFlag{ASN: asn, Org: org}
		}
		byASN[asn].Ranges++
	}
	var out []ASNFlag
	for _, f := range byASN {
		if f.Ranges >= asnMin {
			out = append(out, *f)
		}
	}
	slices.SortFunc(out, func(a, b ASNFlag) int { return cmp.Compare(a.ASN, b.ASN) })
	return out
}
