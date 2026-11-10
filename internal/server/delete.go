package server

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
)

// validHostname reports whether s is a plausible DNS label: 1 to 63 of [A-Za-z0-9-].
func validHostname(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// removeNode handles DELETE /v1/fleets/{id}/nodes/{hostname}. A hostname that is not a node of the
// fleet is a success: the client wanted it gone and it is.
func (h *fleetsHandler) removeNode(w http.ResponseWriter, r *http.Request) {
	f, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	hostname := r.PathValue("hostname")
	if !validHostname(hostname) {
		writeError(w, http.StatusBadRequest, "invalid hostname")
		return
	}
	// Detached like the other writes: a node half-removed for a client that hung up helps nobody.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()
	// By id, not by hostname: a device may share the box's hostname and must survive.
	nodes, err := h.deps.Headscale.ListNodes(ctx, f.HeadscaleUser)
	var devs map[string]bool
	if err == nil {
		devs, err = h.deps.Store.DeviceIDs(ctx, f.ID)
	}
	for _, n := range nodes {
		if err != nil {
			break
		}
		if n.Hostname == hostname && !devs[n.ID] {
			err = h.deps.Headscale.DeleteNodeByID(ctx, n.ID)
			if err == nil { // the node's name goes with the key (share_names cascades)
				err = h.deps.Store.DeleteBoxKey(ctx, n.ID)
			}
		}
	}
	if err != nil {
		log.Printf("fleet %s: remove node: %v", f.ID, err)
		writeError(w, http.StatusBadGateway, "upstream error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteFleet handles DELETE /v1/fleets/{id}. Once the fleet is gone its secret no longer
// authenticates anything, so a repeat answers 404 ("already deleted"); after a failure the row is
// still there and the same call can be repeated.
func (h *fleetsHandler) deleteFleet(w http.ResponseWriter, r *http.Request) {
	f, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), fleets.RemoveTimeout)
	defer cancel()
	if err := h.deps.Remover.Remove(ctx, f); err != nil {
		log.Printf("fleet %s: delete: %v", f.ID, err)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			writeError(w, http.StatusServiceUnavailable, "busy, retry later")
			return
		}
		writeError(w, http.StatusBadGateway, "upstream error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
