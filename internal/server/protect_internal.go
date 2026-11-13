package server

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/community"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

const (
	maxEventsBody  = 1 << 20
	maxEventsItems = 20000
)

// filter handles GET /internal/share/filter: the compiled snapshot, 304 when If-None-Match is current.
func (h *internalHandler) filter(w http.ResponseWriter, r *http.Request) {
	body, version, err := h.deps.Protect.Current(r.Context())
	if err != nil {
		log.Printf("internal: filter snapshot: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	etag := `"` + version + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-store")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

var refusalReasons = map[string]bool{"manual": true, "suspended": true, "external": true, "community": true, "cap": true}

// events handles POST /internal/share/events: visitors `share` accepted and the refusals it counted.
func (h *internalHandler) events(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEventsBody))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	var in struct {
		Seen []struct {
			Key    string `json:"key"`
			NodeID string `json:"node_id"`
		} `json:"seen"`
		Refusals []struct {
			Hour   time.Time `json:"hour"`
			Name   string    `json:"name"`
			Key    string    `json:"key"`
			Reason string    `json:"reason"`
			Source string    `json:"source"`
			Count  int64     `json:"count"`
		} `json:"refusals"`
	}
	if json.Unmarshal(b, &in) != nil || len(in.Seen)+len(in.Refusals) > maxEventsItems {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	var seen []store.Seen
	for _, s := range in.Seen {
		if s.NodeID == "" {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		if k, ok := community.Key(s.Key); ok { // private and reserved addresses are never kept
			seen = append(seen, store.Seen{Key: k, NodeID: s.NodeID})
		}
	}
	var refs []store.Refusal
	for _, f := range in.Refusals {
		if !refusalReasons[f.Reason] || f.Count <= 0 || f.Hour.IsZero() {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		if k, ok := community.Key(f.Key); ok || f.Key == "" { // "": share's row past its per-name cap
			refs = append(refs, store.Refusal{Hour: f.Hour.UTC().Truncate(time.Hour), Name: f.Name, Key: k, Reason: f.Reason, Source: f.Source, Count: f.Count})
		}
	}
	ctx := r.Context()
	if err := h.deps.Store.RecordSeen(ctx, h.deps.Now(), seen); err != nil {
		log.Printf("internal: record seen: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := h.deps.Store.AddRefusals(ctx, refs); err != nil {
		log.Printf("internal: add refusals: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
