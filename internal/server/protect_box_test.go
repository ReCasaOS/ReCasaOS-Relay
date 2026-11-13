package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/community"
	"github.com/ReCasaOS/recasaos-relay/internal/protect"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

func setupBoxProtect(t *testing.T) *shareEnv {
	t.Helper()
	return &shareEnv{delEnv: setupDelDeps(t, func(c *Config) {
		c.ShareDomain = "share.example"
		c.TrustedProxyHeader = "X-Client-IP"
	}, func(d *Deps) {
		d.Community = &community.Engine{Store: d.Store, Now: d.Now}
	})}
}

func decode(t *testing.T, rec interface{ String() string }, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(rec.String()), v); err != nil {
		t.Fatalf("body %s: %v", rec, err)
	}
}

func TestProtectionPutAndAnswer(t *testing.T) {
	e := setupBoxProtect(t)
	b := e.linked(t, "box-a")
	rec := e.as(b, "PUT", "/v1/share/protection", `{"relay_filter":true,"share_bans":false}`)
	wantStatus(t, rec, 200, `{"relay_filter":true,"share_bans":false,"share_bans_at":null,"community_size":0,"contributed_month":0}`)
	rec = e.as(b, "PUT", "/v1/share/protection", `{"relay_filter":true,"share_bans":true}`)
	wantStatus(t, rec, 200, "")
	var got map[string]any
	decode(t, rec.Body, &got)
	at := got["share_bans_at"]
	if at != now0.UTC().Format(time.RFC3339) {
		t.Fatalf("share_bans_at = %v", at)
	}
	// still on: unchanged
	rec = e.as(b, "PUT", "/v1/share/protection", `{"relay_filter":false,"share_bans":true}`)
	decode(t, rec.Body, &got)
	if got["share_bans_at"] != at || got["relay_filter"] != false {
		t.Fatalf("got %v", got)
	}
	rec = e.as(b, "PUT", "/v1/share/protection", `{"share_bans":false}`)
	wantStatus(t, rec, 200, `{"relay_filter":false,"share_bans":false,"share_bans_at":null,"community_size":0,"contributed_month":0}`)
}

func TestProtectionOffPurgesReports(t *testing.T) {
	e := setupBoxProtect(t)
	b := e.linked(t, "box-a")
	ctx := context.Background()
	e.as(b, "PUT", "/v1/share/protection", `{"relay_filter":true,"share_bans":true}`)
	if err := e.st.AddReport(ctx, store.Report{NodeID: b.node, FleetID: e.id, Key: "203.0.113.7/32", Reason: "scan", App: "x", Since: now0}, now0); err != nil {
		t.Fatal(err)
	}
	e.as(b, "PUT", "/v1/share/protection", `{"relay_filter":true,"share_bans":false}`)
	if rs, err := e.st.ReportsSince(ctx, time.Time{}); err != nil || len(rs) != 0 {
		t.Fatalf("reports = %+v, %v", rs, err)
	}
}

func TestBansRejectsBadItems(t *testing.T) {
	e := setupBoxProtect(t)
	b := e.linked(t, "box-a")
	since := now0.UTC().Add(-time.Minute).Format(time.RFC3339)
	item := func(key, reason, app, since string) string {
		return fmt.Sprintf(`{"key":%q,"reason":%q,"app":%q,"since":%q}`, key, reason, app, since)
	}
	bad := []string{
		item("203.0.113.7", "x", "jellyfin", since),
		item("203.0.113.7", "scan", "../a", since),
		item("garbage", "scan", "jellyfin", since),
		item("10.0.0.1", "scan", "jellyfin", since),
		item("203.0.113.7", "scan", "jellyfin", now0.UTC().Add(-48*time.Hour).Format(time.RFC3339)),
		item("203.0.113.7", "scan", "jellyfin", now0.UTC().Add(5*time.Minute).Format(time.RFC3339)),
		"not json",
	}
	for i, it := range bad {
		body := `{"bans":[` + it + `]}`
		if i == len(bad)-1 {
			body = it
		}
		wantStatus(t, e.as(b, "POST", "/v1/share/bans", body), 400, "")
	}
	many := strings.Repeat(item("203.0.113.7", "scan", "jellyfin", since)+",", 200) + item("203.0.113.7", "scan", "jellyfin", since)
	wantStatus(t, e.as(b, "POST", "/v1/share/bans", `{"bans":[`+many+`]}`), 400, "")
	wantStatus(t, e.as(b, "POST", "/v1/share/bans", `{"bans":[`+item("203.0.113.7", "scan", "jellyfin", since)+`]}`), 204, "")
}

func TestBansDropsSilently(t *testing.T) {
	e := setupBoxProtect(t)
	b := e.linked(t, "box-a") // sharing never turned on
	since := now0.UTC().Add(-time.Minute).Format(time.RFC3339)
	e.st.RecordSeen(context.Background(), now0, []store.Seen{{Key: "203.0.113.7/32", NodeID: b.node}})
	rec := e.as(b, "POST", "/v1/share/bans", `{"bans":[{"key":"203.0.113.7","reason":"scan","app":"jellyfin","since":"`+since+`"}]}`)
	wantStatus(t, rec, 204, "")
	if rs, err := e.st.ReportsSince(context.Background(), time.Time{}); err != nil || len(rs) != 0 {
		t.Fatalf("reports = %+v, %v", rs, err)
	}
}

func TestRefusalsOnlyOwnName(t *testing.T) {
	e := setupBoxProtect(t)
	ctx := context.Background()
	a, c := e.linked(t, "box-a"), e.linked(t, "box-c")
	if err := e.st.ClaimName(ctx, a.node, "mybox", now0); err != nil {
		t.Fatal(err)
	}
	h := now0.Truncate(time.Hour)
	e.st.AddRefusals(ctx, []store.Refusal{
		{Hour: h, Name: "mybox", Key: "203.0.113.7/32", Reason: "external", Source: "FireHOL level 1", Count: 12},
		{Hour: h, Name: "other", Key: "203.0.113.8/32", Reason: "external", Source: "x", Count: 1},
		{Hour: h.Add(-8 * 24 * time.Hour), Name: "mybox", Key: "203.0.113.9/32", Reason: "external", Source: "x", Count: 1},
	})
	rec := e.as(a, "GET", "/v1/share/refusals", "")
	var got []map[string]any
	decode(t, rec.Body, &got)
	if rec.Code != 200 || len(got) != 1 || got[0]["key"] != "203.0.113.7/32" || got[0]["count"] != float64(12) ||
		got[0]["hour"] != h.UTC().Format(time.RFC3339) || got[0]["source"] != "FireHOL level 1" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = e.as(c, "GET", "/v1/share/refusals", "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestContributedMonth(t *testing.T) {
	e := setupBoxProtect(t)
	b := e.linked(t, "box-a")
	ctx := context.Background()
	open := func(key string, since time.Time) {
		t.Helper()
		err := e.st.OpenBan(ctx, store.CommunityBan{Key: key, Kind: "address", Strike: 1, Since: since, Until: since.Add(24 * time.Hour), Reasons: "scan", Fleets: 1}, []string{e.id})
		if err != nil {
			t.Fatal(err)
		}
	}
	first := time.Date(now0.UTC().Year(), now0.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	open("203.0.113.7/32", first.Add(-time.Hour)) // last month
	open("203.0.113.8/32", first.Add(time.Hour))  // this month
	rec := e.as(b, "PUT", "/v1/share/protection", `{"relay_filter":true,"share_bans":false}`)
	var got map[string]any
	decode(t, rec.Body, &got)
	if got["contributed_month"] != float64(1) {
		t.Fatalf("got %v", got)
	}
}

// Claiming or releasing a name changes the snapshot's names: share sees it at its next poll.
func TestNameChangeInvalidatesSnapshot(t *testing.T) {
	var comp *protect.Compiler
	e := &shareEnv{delEnv: setupDelDeps(t, func(c *Config) { c.ShareDomain = "share.example" }, func(d *Deps) {
		comp = &protect.Compiler{Store: d.Store, Now: d.Now}
		d.Protect = comp
	})}
	ctx := context.Background()
	b := e.linked(t, "box-a")
	wantStatus(t, e.as(b, "PUT", "/v1/share/protection", `{"relay_filter":true,"share_bans":false}`), 200, "")
	if body, _, err := comp.Current(ctx); err != nil || strings.Contains(string(body), "mybox") {
		t.Fatalf("%s %v", body, err)
	}
	wantStatus(t, e.as(b, "PUT", "/v1/share/name", `{"name":"mybox"}`), 201, "")
	if body, _, _ := comp.Current(ctx); !strings.Contains(string(body), `"mybox":{"filter":true`) {
		t.Fatalf("claimed name missing: %s", body)
	}
	wantStatus(t, e.as(b, "DELETE", "/v1/share/name", ""), 204, "")
	if body, _, _ := comp.Current(ctx); strings.Contains(string(body), "mybox") {
		t.Fatalf("released name kept: %s", body)
	}
}

// The protection routes have their own per-IP budget: a box sending bans all through an attack
// must not use up the one of the name and ACME routes, nor the other way round.
func TestProtectRoutesHaveTheirOwnLimiter(t *testing.T) {
	e := &shareEnv{delEnv: setupDelDeps(t, func(c *Config) {
		c.ShareDomain = "share.example"
		c.TrustedProxyHeader = "X-Client-IP"
		c.AuthRatePerHour, c.ProtectRatePerHour = 3, 3
	}, func(d *Deps) {
		d.Community = &community.Engine{Store: d.Store, Now: d.Now}
	})}
	b := e.linked(t, "box-a")
	wantStatus(t, e.as(b, "PUT", "/v1/share/protection", `{"relay_filter":true}`), 200, "")
	wantStatus(t, e.as(b, "POST", "/v1/share/bans", `{"bans":[]}`), 204, "")
	wantStatus(t, e.as(b, "GET", "/v1/share/refusals", ""), 200, "")
	wantStatus(t, e.as(b, "GET", "/v1/share/refusals", ""), 429, "")
	wantStatus(t, e.as(b, "PUT", "/v1/share/name", `{"name":"abc"}`), 201, "")
	wantStatus(t, e.as(b, "GET", "/v1/share", ""), 200, "")
}
