package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/devicecode"
	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// createDeviceCode handles POST /v1/fleets/{id}/device-codes: a short code a phone types to join.
func (h *fleetsHandler) createDeviceCode(w http.ResponseWriter, r *http.Request) {
	f, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	if ok, retry := h.keyLimiter.Allow(f.ID); !ok {
		tooMany(w, retry)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()
	code, err := devicecode.New()
	if err != nil {
		log.Printf("fleet %s: device code: %v", f.ID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	norm, _ := devicecode.Normalize(code)
	now := h.deps.Now()
	expires := now.Add(h.cfg.DeviceCodeTTL).UTC()
	switch err := h.deps.Store.CreateDeviceCode(ctx, f.ID, devicecode.Hash(norm), expires, now, h.cfg.MaxPendingDeviceCodes); {
	case errors.Is(err, store.ErrTooManyCodes):
		writeError(w, http.StatusConflict, "too many unused device codes")
		return
	case err != nil:
		log.Printf("fleet %s: store device code: %v", f.ID, err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := h.deps.Store.Touch(ctx, f.ID, now); err != nil {
		log.Printf("fleet %s: touch: %v", f.ID, err)
	}
	writeJSON(w, http.StatusCreated, map[string]string{"code": code, "expires_at": expires.Format(time.RFC3339)})
}

// listDevices handles GET /v1/fleets/{id}/devices. A device row whose node is gone from Headscale
// (removed from the phone, or expired) is dropped here.
func (h *fleetsHandler) listDevices(w http.ResponseWriter, r *http.Request) {
	f, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), opTimeout)
	defer cancel()
	// Rows first, nodes second: a device joining in between is then missing from ids (just not
	// listed) instead of looking like a stale row and being deleted.
	ids, err := h.deps.Store.DeviceIDs(ctx, f.ID)
	var nodes []headscale.Node
	if err == nil {
		nodes, err = h.deps.Headscale.ListNodes(ctx, f.HeadscaleUser)
	}
	if err != nil {
		log.Printf("fleet %s: list devices: %v", f.ID, err)
		writeError(w, http.StatusBadGateway, "upstream error")
		return
	}
	type device struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
		IP       string `json:"ip"`
		Online   bool   `json:"online"`
		LastSeen string `json:"last_seen"`
	}
	out := []device{} // [] rather than null
	for _, n := range nodes {
		if !ids[n.ID] {
			continue
		}
		delete(ids, n.ID)
		d := device{n.ID, n.Hostname, n.IP, n.Online, ""}
		if !n.LastSeen.IsZero() {
			d.LastSeen = n.LastSeen.UTC().Format(time.RFC3339)
		}
		out = append(out, d)
	}
	for id := range ids { // left over: the node no longer exists
		if err := h.deps.Store.DeleteDevice(ctx, id); err != nil {
			log.Printf("fleet %s: drop device %s: %v", f.ID, id, err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": out})
}

// removeDevice handles DELETE /v1/fleets/{id}/devices/{node}. Only a device of this fleet is
// deleted; any other id is a quiet success.
func (h *fleetsHandler) removeDevice(w http.ResponseWriter, r *http.Request) {
	f, ok := h.authenticate(w, r)
	if !ok {
		return
	}
	node := r.PathValue("node")
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()
	ids, err := h.deps.Store.DeviceIDs(ctx, f.ID)
	if err == nil && ids[node] {
		if err = h.deps.Headscale.DeleteNodeByID(ctx, node); err == nil {
			err = h.deps.Store.DeleteDevice(ctx, node)
		}
	}
	if err != nil {
		log.Printf("fleet %s: remove device: %v", f.ID, err)
		writeError(w, http.StatusBadGateway, "upstream error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
