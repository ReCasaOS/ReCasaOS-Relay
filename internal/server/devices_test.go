package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestListDevices(t *testing.T) {
	d := setupDel(t, nil)
	seen := now0.Add(-time.Minute)
	a := d.hs.AddNode(d.user, "iphone", true)
	b := d.hs.AddNode(d.user, "laptop", false)
	d.hs.AddNode(d.user, "box-a", true)
	d.hs.SetNodeInfo(d.user, "iphone", []string{"100.64.0.9"}, seen, time.Time{})
	for _, id := range []string{a, b, "999"} { // 999: its node is gone
		if err := d.st.AddDevice(t.Context(), d.id, id, now0); err != nil {
			t.Fatal(err)
		}
	}
	rec := d.do(http.MethodGet, "/v1/fleets/"+d.id+"/devices", d.secret, ip1)
	var body struct {
		Devices []struct {
			ID       string
			Hostname string
			IP       string
			LastSeen string `json:"last_seen"`
			Online   bool
		} `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != 200 || len(body.Devices) != 2 {
		t.Fatalf("%d %v %s", rec.Code, err, rec.Body)
	}
	if g := body.Devices[0]; g.ID != a || g.Hostname != "iphone" || g.IP != "100.64.0.9" || !g.Online || g.LastSeen != seen.UTC().Format(time.RFC3339) {
		t.Fatalf("device %+v", g)
	}
	if body.Devices[1].LastSeen != "" {
		t.Fatalf("unknown last_seen = %q", body.Devices[1].LastSeen)
	}
	if ids, _ := d.st.DeviceIDs(t.Context(), d.id); ids["999"] || len(ids) != 2 {
		t.Fatalf("stale row kept: %v", ids)
	}
	if d.do(http.MethodGet, "/v1/fleets/"+d.id+"/devices", "wrong", ip1).Code != http.StatusUnauthorized {
		t.Fatal("wrong secret not 401")
	}
}

func TestListDevicesEmptyIsArray(t *testing.T) {
	d := setupDel(t, nil)
	rec := d.do(http.MethodGet, "/v1/fleets/"+d.id+"/devices", d.secret, ip1)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"devices":[]`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestDeleteDevice(t *testing.T) {
	d := setupDel(t, nil)
	own := d.hs.AddNode(d.user, "iphone", true)
	box := d.hs.AddNode(d.user, "box-a", true)
	other := d.hs.AddNode("f-other", "tablet", true)
	if err := d.st.AddDevice(t.Context(), d.id, own, now0); err != nil {
		t.Fatal(err)
	}
	addFleet(t, d.st, "fleet0002")
	if err := d.st.AddDevice(t.Context(), "fleet0002", other, now0); err != nil {
		t.Fatal(err)
	}
	del := func(id string) int {
		return d.do(http.MethodDelete, "/v1/fleets/"+d.id+"/devices/"+id, d.secret, ip1).Code
	}
	d.log.Reset()
	if del(other) != 204 || del(box) != 204 || strings.Contains(d.log.String(), "node:") {
		t.Fatalf("foreign ids touched Headscale: %q", d.log)
	}
	if del(own) != 204 || !strings.Contains(d.log.String(), "node:"+own) {
		t.Fatalf("own device: %q", d.log)
	}
	if ids, _ := d.st.DeviceIDs(t.Context(), d.id); len(ids) != 0 {
		t.Fatalf("row kept: %v", ids)
	}
	if d.hs.NodeCount(d.user) != 1 || d.hs.NodeCount("f-other") != 1 {
		t.Fatal("wrong nodes deleted")
	}
}
