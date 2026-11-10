package server

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// heartbeatTTL: a tunnel counts as online when its node appeared in a usage post less than this ago
// (`share` posts every 15 s).
const heartbeatTTL = 45 * time.Second

// heartbeats remembers, in memory, when each node last appeared in a usage post.
type heartbeats struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (b *heartbeats) record(nodeIDs []string, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.seen == nil {
		b.seen = map[string]time.Time{}
	}
	for id, t := range b.seen { // keeps the map as small as the tunnels alive
		if now.Sub(t) >= heartbeatTTL {
			delete(b.seen, id)
		}
	}
	for _, id := range nodeIDs {
		b.seen[id] = now
	}
}

func (b *heartbeats) online(nodeID string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ok := b.seen[nodeID]
	return ok && now.Sub(t) < heartbeatTTL
}

// internalOnly answers 404 to a request that carries header, which only the public `front` proxy
// sets: a caller on the compose network does not. Empty header: nothing can be told apart, so
// nothing is refused (the compose file always sets TRUSTED_PROXY_HEADER).
func internalOnly(header string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if header != "" && len(r.Header.Values(header)) > 0 {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	})
}

type internalHandler struct {
	deps  Deps
	beats *heartbeats
}

// boxByKey handles GET /internal/share/boxes/{key}: which name and node a box key stands for.
func (h *internalHandler) boxByKey(w http.ResponseWriter, r *http.Request) {
	ref, err := h.deps.Store.BoxByKey(r.Context(), r.PathValue("key"))
	switch {
	case errors.Is(err, store.ErrNotFound) || err == nil && ref.Name == "":
		writeError(w, http.StatusNotFound, "not found")
	case err != nil:
		log.Printf("internal: box by key: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"name": ref.Name, "node_id": ref.NodeID, "fleet_id": ref.FleetID})
	}
}

// usage handles POST /internal/share/usage: it validates the samples, adds their deltas to the
// shared-traffic buckets and records the heartbeat.
func (h *internalHandler) usage(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	var samples []struct {
		FleetID string `json:"fleet_id"`
		NodeID  string `json:"node_id"`
		Rx      int64  `json:"rx"`
		Tx      int64  `json:"tx"`
	}
	if json.Unmarshal(b, &samples) != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ids := make([]string, 0, len(samples))
	us := make([]store.UsageSample, 0, len(samples))
	for _, s := range samples {
		if s.FleetID == "" || s.NodeID == "" || s.Rx < 0 || s.Tx < 0 {
			writeError(w, http.StatusBadRequest, "invalid request")
			return
		}
		ids = append(ids, s.NodeID)
		us = append(us, store.UsageSample{FleetID: s.FleetID, NodeID: s.NodeID, Rx: s.Rx, Tx: s.Tx})
	}
	now := h.deps.Now()
	if err := h.deps.Store.ApplyShareUsage(r.Context(), now, us); err != nil {
		log.Printf("internal: apply share usage: %v", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.beats.record(ids, now)
	w.WriteHeader(http.StatusNoContent)
}
