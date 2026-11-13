package admin

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/community"
	"github.com/ReCasaOS/recasaos-relay/internal/sharename"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// refusalReasons is the order of the columns; the share process writes exactly these.
var refusalReasons = []string{"manual", "suspended", "external", "community", "cap"}

const topKeys = 50

type nameView struct {
	store.NameRow
	Today        []int64 // by refusalReasons
	Filter, Bans string  // "on", "off" or "not set" (a box older than the setting)
	IsSuspended  bool
}

type countRow struct {
	Key   string
	Count int64
}

// protectStats gathers what the overview, community, names and caps sections show. "Today" is since 00:00 UTC.
func (h *handler) protectStats(ctx context.Context, now time.Time) (map[string]any, error) {
	st := h.deps.Store
	day := now.UTC().Truncate(24 * time.Hour)
	week := day.AddDate(0, 0, -6)
	totals, err := st.RefusalTotals(ctx, week)
	if err != nil {
		return nil, err
	}
	col := map[string]int{}
	for i, r := range refusalReasons {
		col[r] = i
	}
	today := make([]int64, len(refusalReasons))
	series := make([]chartSeries, len(refusalReasons))
	for i, r := range refusalReasons {
		series[i] = chartSeries{Name: r, Values: make([]float64, 7)}
	}
	for _, t := range totals {
		i, ok := col[t.Reason]
		if !ok {
			continue
		}
		if !t.Hour.Before(day) {
			today[i] += t.Count
		}
		if d := int(t.Hour.Sub(week) / (24 * time.Hour)); d >= 0 && d < 7 {
			series[i].Values[d] += float64(t.Count)
		}
	}
	active, err := st.ActiveBans(ctx, now)
	if err != nil {
		return nil, err
	}
	permanent, err := st.PermanentBans(ctx)
	if err != nil {
		return nil, err
	}
	var timed []store.CommunityBan
	for _, b := range active {
		if !b.Until.IsZero() {
			timed = append(timed, b)
		}
	}
	var flags []community.ASNFlag
	if h.deps.Geo != nil {
		flags = community.FlaggedASNs(active, h.deps.Geo.ASN)
	}
	prot, err := st.ProtectedNames(ctx)
	if err != nil {
		return nil, err
	}
	sharing := 0
	for _, p := range prot {
		if p.ShareBans {
			sharing++
		}
	}
	suspended, err := st.SuspendedNames(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := st.ListNames(ctx)
	if err != nil {
		return nil, err
	}
	onOff := func(set, v bool) string {
		switch {
		case !set:
			return "not set"
		case v:
			return "on"
		}
		return "off"
	}
	names := make([]nameView, len(rows))
	byKey, byName := map[string]int64{}, map[string]int64{}
	// The empty name is what no box owns: the per-address cap fires before the name is known.
	for i := -1; i < len(rows); i++ {
		n := ""
		if i >= 0 {
			n = rows[i].Name
			p, set := prot[n]
			names[i] = nameView{NameRow: rows[i], Today: make([]int64, len(refusalReasons)),
				Filter: onOff(set, p.RelayFilter), Bans: onOff(set, p.ShareBans), IsSuspended: slices.Contains(suspended, n)}
		}
		rs, err := st.RefusalsOf(ctx, n, day, 100000)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			if c, ok := col[r.Reason]; ok && i >= 0 {
				names[i].Today[c] += r.Count
			}
			if r.Reason == "cap" {
				byKey[r.Key] += r.Count
				byName[n] += r.Count
			}
		}
	}
	return map[string]any{
		"Reasons": refusalReasons, "Today": today, "Chart": stackedChart(series, 7, "refused"), "Series": series,
		"Sharing": sharing, "ActiveBans": len(active), "Timed": timed, "Permanent": permanent, "Flags": flags,
		"Names": names, "CapKeys": top(byKey, topKeys), "CapNames": top(byName, len(byName)),
	}, nil
}

// top returns the n largest counts, ties by key.
func top(m map[string]int64, n int) []countRow {
	out := make([]countRow, 0, len(m))
	for k, c := range m {
		out = append(out, countRow{k, c})
	}
	slices.SortFunc(out, func(a, b countRow) int {
		if a.Count != b.Count {
			return int(b.Count - a.Count)
		}
		return strings.Compare(a.Key, b.Key)
	})
	return out[:min(n, len(out))]
}

// communityKey reads the form's key: a canonical prefix, as the community list stores it, and not broader than a feed may hold.
func communityKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := strings.TrimSpace(r.PostFormValue("key"))
	if p, err := netip.ParsePrefix(key); err != nil || p != p.Masked() || !broadEnough(p) {
		http.Error(w, "key: a canonical prefix, /8 or narrower for IPv4, /19 for IPv6", http.StatusBadRequest)
		return "", false
	}
	return key, true
}

func (h *handler) liftCommunity(w http.ResponseWriter, r *http.Request) {
	key, ok := communityKey(w, r)
	if !ok {
		return
	}
	ctx, cancel := writeCtx(r)
	defer cancel()
	if err := h.deps.Store.LiftBan(ctx, key, h.deps.Now()); err != nil && !errors.Is(err, store.ErrNotFound) {
		h.storeError(w, "lift ban", err)
		return
	}
	h.done(w, r, "#community")
}

// allowCommunity moves a banned key to the allow list: the ban is lifted, and no later report can ban it again.
func (h *handler) allowCommunity(w http.ResponseWriter, r *http.Request) {
	key, ok := communityKey(w, r)
	if !ok {
		return
	}
	ctx, cancel := writeCtx(r)
	defer cancel()
	if _, err := h.deps.Store.AddAllow(ctx, store.AllowEntry{Prefix: key, Note: "from community list", Added: h.deps.Now()}); err != nil {
		h.storeError(w, "add allow", err)
		return
	}
	if err := h.deps.Store.LiftBan(ctx, key, h.deps.Now()); err != nil && !errors.Is(err, store.ErrNotFound) {
		h.storeError(w, "lift ban", err)
		return
	}
	h.done(w, r, "#community")
}

func (h *handler) banASN(w http.ResponseWriter, r *http.Request) {
	v := manualValue("asn", r.PathValue("asn"))
	if v == "" {
		http.Error(w, "asn: a positive number", http.StatusBadRequest)
		return
	}
	ctx, cancel := writeCtx(r)
	defer cancel()
	if _, err := h.deps.Store.AddManual(ctx, store.ManualBan{Kind: "asn", Value: v, Note: "flagged network", Since: h.deps.Now()}); err != nil {
		h.storeError(w, "ban asn", err)
		return
	}
	h.done(w, r, "#community")
}

func (h *handler) nameAction(w http.ResponseWriter, r *http.Request) {
	name, action := r.PathValue("name"), r.PathValue("action")
	if sharename.ValidLabel(name) != nil {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	ctx, cancel := writeCtx(r)
	defer cancel()
	var err error
	switch action {
	case "suspend":
		err = h.deps.Store.SuspendName(ctx, name, h.deps.Now())
	case "resume":
		err = h.deps.Store.ResumeName(ctx, name)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.storeError(w, action+" name", err)
		return
	}
	h.done(w, r, "#names")
}
