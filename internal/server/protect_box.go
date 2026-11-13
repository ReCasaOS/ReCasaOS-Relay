package server

import (
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/community"
	"github.com/ReCasaOS/recasaos-relay/internal/journal"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

const (
	maxBansBody   = 32 << 10
	maxBansItems  = 200
	refusalsSpan  = 7 * 24 * time.Hour
	refusalsLimit = 2000
)

var appRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func rfc3339OrNil(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// putProtection handles PUT /v1/share/protection.
func (h *shareHandler) putProtection(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RelayFilter bool `json:"relay_filter"`
		ShareBans   bool `json:"share_bans"`
	}
	ref, ok := h.boxAuth(w, r, &body)
	if !ok {
		return
	}
	ctx, cancel := opCtx(r)
	defer cancel()
	now := h.deps.Now()
	old, had, err := h.deps.Store.GetProtection(ctx, ref.NodeID)
	if err != nil {
		internalError(w, "get protection", err)
		return
	}
	p := store.Protection{RelayFilter: body.RelayFilter, ShareBans: body.ShareBans}
	switch {
	case !p.ShareBans:
	case old.ShareBans:
		p.ShareBansAt = old.ShareBansAt
	default:
		p.ShareBansAt = now
	}
	if err := h.deps.Store.SetProtection(ctx, ref.NodeID, p); err != nil {
		internalError(w, "set protection", err)
		return
	}
	h.invalidate()
	if !had || old.RelayFilter != p.RelayFilter || old.ShareBans != p.ShareBans { // boxes PUT at every resync
		h.deps.Journal.Write(journal.Entry{Src: "relay", Event: "protection",
			Msg: fmt.Sprintf("%s relay_filter=%t share_bans=%t", ref.NodeID, p.RelayFilter, p.ShareBans)})
	}
	bans, err := h.deps.Store.ActiveBans(ctx, now)
	if err != nil {
		internalError(w, "active bans", err)
		return
	}
	y, m, _ := now.UTC().Date()
	n, err := h.deps.Store.ContributedSince(ctx, ref.FleetID, time.Date(y, m, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		internalError(w, "contributed", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"relay_filter": p.RelayFilter, "share_bans": p.ShareBans, "share_bans_at": rfc3339OrNil(p.ShareBansAt),
		"community_size": len(bans), "contributed_month": n,
	})
}

// postBans handles POST /v1/share/bans: field rules here, acceptance rules in the engine.
func (h *shareHandler) postBans(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Bans []struct {
			Key, Reason, App string
			Since            time.Time
		} `json:"bans"`
	}
	ref, ok := h.boxAuthMax(w, r, &body, maxBansBody)
	if !ok {
		return
	}
	now := h.deps.Now()
	if len(body.Bans) > maxBansItems {
		writeError(w, http.StatusBadRequest, "bad request")
		return
	}
	items := make([]community.Item, 0, len(body.Bans))
	for _, b := range body.Bans {
		_, keyOK := community.Key(b.Key)
		switch b.Reason {
		case "waf", "scan", "rate", "code":
		default:
			keyOK = false
		}
		if !keyOK || !appRE.MatchString(b.App) || b.Since.IsZero() || b.Since.Before(now.Add(-24*time.Hour)) || b.Since.After(now.Add(2*time.Minute)) {
			writeError(w, http.StatusBadRequest, "bad request")
			return
		}
		items = append(items, community.Item{Key: b.Key, Reason: b.Reason, App: b.App, Since: b.Since})
	}
	if h.deps.Community != nil {
		ctx, cancel := opCtx(r)
		defer cancel()
		n, err := h.deps.Community.Accept(ctx, ref, items)
		if n > 0 {
			h.deps.Journal.Write(journal.Entry{Src: "relay", Event: "reports", Msg: ref.NodeID, Count: int64(n)})
		}
		if err != nil {
			internalError(w, "accept bans", err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// getRefusals handles GET /v1/share/refusals: the refusals of the box's own name.
func (h *shareHandler) getRefusals(w http.ResponseWriter, r *http.Request) {
	ref, ok := h.boxAuth(w, r, nil)
	if !ok {
		return
	}
	out := []map[string]any{}
	if ref.Name != "" {
		ctx, cancel := opCtx(r)
		defer cancel()
		rs, err := h.deps.Store.RefusalsOf(ctx, ref.Name, h.deps.Now().Add(-refusalsSpan), refusalsLimit)
		if err != nil {
			internalError(w, "refusals", err)
			return
		}
		for _, x := range rs {
			out = append(out, map[string]any{"hour": x.Hour.UTC().Format(time.RFC3339), "key": x.Key, "reason": x.Reason, "source": x.Source, "count": x.Count})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
