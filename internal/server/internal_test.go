package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func (e *shareEnv) internal(method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = ip1
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

func TestInternalRoutesRefuseProxiedRequests(t *testing.T) {
	e := setupShare(t, nil)
	a := e.linked(t, "box-a")
	wantStatus(t, e.as(a, "PUT", "/v1/share/name", `{"name":"abc"}`), 201, "")
	proxied := map[string]string{"X-Client-IP": "203.0.113.9"}
	usage := `[{"fleet_id":"` + e.id + `","node_id":"` + a.node + `","rx":1,"tx":2}]`

	wantStatus(t, e.internal("GET", "/internal/share/boxes/"+a.key, "", proxied), 404, "")
	wantStatus(t, e.internal("POST", "/internal/share/usage", usage, proxied), 404, "")
	// the refused heartbeat was not recorded
	wantStatus(t, e.as(a, "GET", "/v1/share", ""), 200, `{"name":"abc","host":"abc.share.example","domain":"share.example","tunnel_online":false}`)

	// from the compose network (no front header)
	wantStatus(t, e.internal("GET", "/internal/share/boxes/"+a.key, "", nil), 200, `{"name":"abc","node_id":"`+a.node+`","fleet_id":"`+e.id+`"}`)
	wantStatus(t, e.internal("POST", "/internal/share/usage", usage, nil), 204, "")
}

func TestInternalBoxByKeyNeedsAName(t *testing.T) {
	e := setupShare(t, nil)
	a := e.linked(t, "box-a")
	wantStatus(t, e.internal("GET", "/internal/share/boxes/"+a.key, "", nil), 404, "") // linked, no name
	wantStatus(t, e.internal("GET", "/internal/share/boxes/unknown", "", nil), 404, "")
}

func TestInternalUsageValidatesBody(t *testing.T) {
	e := setupShare(t, nil)
	for _, body := range []string{
		`nope`, `{}`, `[{"fleet_id":"","node_id":"1","rx":0,"tx":0}]`, `[{"fleet_id":"f","node_id":"","rx":0,"tx":0}]`,
		`[{"fleet_id":"f","node_id":"1","rx":-1,"tx":0}]`, `[{"fleet_id":"f","node_id":"1","rx":"x","tx":0}]`,
	} {
		wantStatus(t, e.internal("POST", "/internal/share/usage", body, nil), 400, `{"error":"invalid request"}`)
	}
	wantStatus(t, e.internal("POST", "/internal/share/usage", `[]`, nil), 204, "")
	big := `[` + strings.Repeat(`{"fleet_id":"f","node_id":"1","rx":0,"tx":0},`, 2000) + `{"fleet_id":"f","node_id":"1","rx":0,"tx":0}]`
	if len(big) <= 64<<10 {
		t.Fatal("test body too small")
	}
	wantStatus(t, e.internal("POST", "/internal/share/usage", big, nil), http.StatusRequestEntityTooLarge, "")
}

func TestHeartbeatsExpireAfter45s(t *testing.T) {
	var b heartbeats
	t0 := now0
	if b.online("1", t0) {
		t.Fatal("never seen is online")
	}
	b.record([]string{"1", "2"}, t0)
	if !b.online("1", t0.Add(44*time.Second)) || b.online("1", t0.Add(45*time.Second)) {
		t.Fatal("online window is not 45 s")
	}
	b.record([]string{"2"}, t0.Add(50*time.Second))
	if len(b.seen) != 1 {
		t.Fatalf("stale entry kept: %v", b.seen)
	}
}

func TestUsagePostAppliesDeltas(t *testing.T) {
	e := setupShare(t, nil)
	post := func(rx, tx int) {
		body := `[{"fleet_id":"fleet0001","node_id":"7","rx":` + strconv.Itoa(rx) + `,"tx":` + strconv.Itoa(tx) + `}]`
		wantStatus(t, e.internal("POST", "/internal/share/usage", body, nil), 204, "")
	}
	post(100, 10)
	post(250, 5)
	got, err := e.st.ShareTotals(context.Background(), time.Unix(0, 0))
	if err != nil || len(got) != 1 || got[0].Rx != 350 || got[0].Tx != 15 || got[0].NodeID != "7" {
		t.Fatalf("ShareTotals = %+v, %v; want one node 7 with rx 350 tx 15", got, err)
	}
	if rel, _ := e.st.UsageTotals(context.Background(), time.Unix(0, 0)); len(rel) != 0 {
		t.Fatalf("shared bytes leaked into the relayed totals: %+v", rel)
	}
}

func TestInternalUsageRefusesBadSamplesAndStoreFailure(t *testing.T) {
	e := setupShare(t, nil)
	wantStatus(t, e.internal("POST", "/internal/share/usage", `[{"fleet_id":"f","node_id":"1","rx":-5,"tx":0}]`, nil), 400, `{"error":"invalid request"}`)
	wantStatus(t, e.internal("POST", "/internal/share/usage", `[{"fleet_id":"","node_id":"1","rx":1,"tx":0}]`, nil), 400, `{"error":"invalid request"}`)
	if got, _ := e.st.ShareTotals(context.Background(), time.Unix(0, 0)); len(got) != 0 {
		t.Fatalf("a refused post stored %+v", got)
	}
	e.st.Close()
	wantStatus(t, e.internal("POST", "/internal/share/usage", `[{"fleet_id":"f","node_id":"1","rx":1,"tx":0}]`, nil), 500, `{"error":"internal error"}`)
}
