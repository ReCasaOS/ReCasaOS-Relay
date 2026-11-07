package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/devicecode"
)

func (e fleetEnv) deviceCode(secret, remote string) *httptest.ResponseRecorder {
	return e.call(http.MethodPost, "/v1/fleets/"+e.id+"/device-codes", secret, remote)
}

func TestCreateDeviceCode(t *testing.T) {
	e := setupKeys(t, func(c *Config, d *Deps) {
		c.DeviceCodeTTL = 10 * time.Minute
		c.MaxPendingDeviceCodes = 5
		d.Now = func() time.Time { return now0.Add(time.Minute) }
	})
	rec := e.deviceCode(e.secret, ip1)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		Code      string `json:"code"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	norm, ok := devicecode.Normalize(body.Code)
	if !ok {
		t.Fatalf("code %q does not normalize", body.Code)
	}
	if _, err := time.Parse(time.RFC3339, body.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	f, err := e.st.Fleet(t.Context(), e.id)
	if err != nil || !f.LastOnline.Equal(now0.Add(time.Minute)) {
		t.Fatalf("fleet %v %v", f, err)
	}
	if got, err := e.st.TakeDeviceCode(t.Context(), devicecode.Hash(norm), now0.Add(2*time.Minute)); err != nil || got != e.id {
		t.Fatalf("store holds hash? %q %v", got, err)
	}
	// that one is consumed: 5 more fit, the 6th does not
	for i := 0; i < 5; i++ {
		if r := e.deviceCode(e.secret, ip1); r.Code != http.StatusCreated {
			t.Fatalf("code %d: %d", i, r.Code)
		}
	}
	if r := e.deviceCode(e.secret, ip1); r.Code != http.StatusConflict {
		t.Fatalf("6th = %d", r.Code)
	}
	if e.deviceCode("wrong", ip1).Code != http.StatusUnauthorized {
		t.Fatal("wrong secret not 401")
	}
	if r := e.call(http.MethodPost, "/v1/fleets/nosuchfleet/device-codes", e.secret, ip1); r.Code != http.StatusNotFound {
		t.Fatalf("unknown fleet = %d", r.Code)
	}
}
