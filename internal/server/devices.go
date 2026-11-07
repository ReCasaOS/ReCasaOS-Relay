package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/devicecode"
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
