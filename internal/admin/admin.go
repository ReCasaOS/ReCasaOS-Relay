// Package admin is a small operator page under /admin: the fleets and nodes of this relay, and the
// two deletions an operator may need. It is mounted only when ADMIN_TOKEN is set.
package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/meter"
	"github.com/ReCasaOS/recasaos-relay/internal/ratelimit"
	"github.com/ReCasaOS/recasaos-relay/internal/sharename"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// MinTokenLen: the token is the only protection of the page.
const MinTokenLen = 24

const opTimeout = 20 * time.Second

// requestsPerHour bounds failed authentications per client address: a token guess costs one.
const requestsPerHour = 120

//go:embed page.html
var pageHTML string

var page = template.Must(template.New("page").Funcs(template.FuncMap{
	"ago": func(t, now time.Time) string {
		switch d := now.Sub(t); {
		case d < time.Minute:
			return "now"
		case d < time.Hour:
			return strconv.Itoa(int(d.Minutes())) + " min ago"
		case d < 48*time.Hour:
			return strconv.Itoa(int(d.Hours())) + " h ago"
		default:
			return strconv.Itoa(int(d.Hours()/24)) + " d ago"
		}
	},
	// until formats a future instant (a node-key expiry) as "in N min/h/d".
	"until": func(t, now time.Time) string {
		switch d := t.Sub(now); {
		case d < time.Hour:
			return "in " + strconv.Itoa(int(d.Minutes())) + " min"
		case d < 48*time.Hour:
			return "in " + strconv.Itoa(int(d.Hours())) + " h"
		default:
			return "in " + strconv.Itoa(int(d.Hours()/24)) + " d"
		}
	},
	"expired": func(t, now time.Time) bool { return now.After(t) },
	"join":    strings.Join,
	"dict": func(kv ...any) map[string]any {
		m := make(map[string]any, len(kv)/2)
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	},
	"bytes": func(n int64) string { return humanBytes(float64(n)) },
	"rate":  humanRate,
}).Parse(pageHTML))

// Config is what the page shows next to the live numbers.
type Config struct {
	Token         string
	NodesPerFleet int
	MaxFleets     int
	// ClientHeader names the header in which `front` puts the client address (X-Client-IP); empty:
	// the TCP peer.
	ClientHeader string
	// MonthlyReference is the monthly traffic the operator budgets, in bytes; 0: none.
	MonthlyReference int64
	// Version is the relay's own, shown at the foot of the page so the operator knows what runs; empty: left out.
	Version string
}

// Deps are the same collaborators the enrolment handlers use.
type Deps struct {
	Store     store.Store
	Headscale headscale.API
	Remover   *fleets.Remover
	Now       func() time.Time // default time.Now
	// Meter feeds the traffic figures; a true nil interface when metering is off.
	Meter interface{ Live() meter.Live }
}

type handler struct {
	cfg       Config
	deps      Deps
	tokenSum  [32]byte
	csrf      string
	nodeFetch chan struct{} // bounds the Headscale calls of one page load
	limiter   *ratelimit.Limiter
}

// New returns the admin handler. The token must be at least MinTokenLen long.
func New(cfg Config, deps Deps) (http.Handler, error) {
	if len(cfg.Token) < MinTokenLen {
		return nil, errors.New("ADMIN_TOKEN must be at least 24 characters")
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	sum := sha256.Sum256([]byte("csrf:" + cfg.Token))
	h := &handler{cfg: cfg, deps: deps, tokenSum: sha256.Sum256([]byte(cfg.Token)),
		csrf: hex.EncodeToString(sum[:]), nodeFetch: make(chan struct{}, 8),
		limiter: ratelimit.New(requestsPerHour, deps.Now)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/{$}", h.index)
	mux.HandleFunc("POST /admin/fleets/{id}/delete", h.deleteFleet)
	mux.HandleFunc("POST /admin/fleets/{id}/nodes/{node}/remove", h.removeNode)
	mux.HandleFunc("POST /admin/share/banned", h.ban)
	mux.HandleFunc("POST /admin/share/names/{name}/revoke", h.ban)
	mux.HandleFunc("POST /admin/share/banned/{name}/delete", h.unban)
	return h.guard(mux), nil
}

// guard asks for the token (HTTP Basic: any user name, the token as password), and for the CSRF
// field on POSTs: the browser resends Basic credentials to any site that makes it post here.
func (h *handler) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		ip := h.client(r)
		// Checked before the token, so a correct guess past the limit is not revealed.
		if h.limiter.Blocked(ip) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		_, pass, ok := r.BasicAuth()
		got := sha256.Sum256([]byte(pass))
		if !ok || subtle.ConstantTimeCompare(got[:], h.tokenSum[:]) != 1 {
			// A refusal here means the limiter is full of other addresses: fail closed, not an unlimited 401.
			if ok, _ := h.limiter.Allow(ip); !ok {
				http.Error(w, "too many requests", http.StatusTooManyRequests)
				return
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="relay admin", charset="UTF-8"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(h.csrf)) != 1 {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// client is the address the rate limit counts: the one `front` set, else the TCP peer.
func (h *handler) client(r *http.Request) string {
	if v := r.Header.Get(h.cfg.ClientHeader); h.cfg.ClientHeader != "" && v != "" {
		return v
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type fleetView struct {
	ID                  string
	Created, LastOnline time.Time
	Nodes               []nodeView // boxes
	Devices             []nodeView // phones and PCs that joined by code; never counted in Online
	Online              int
	Err                 bool    // its nodes could not be listed
	Month               int64   // relayed bytes this month (Rx: what its nodes sent to the relay)
	Shared              int64   // shared bytes this month (Rx: what its boxes sent to visitors)
	Up                  float64 // live bytes/s: the sum of its listed nodes' Up
	RefPct              int     // Month against Config.MonthlyReference, capped at 100
	RefClass            string  // "", "warn" (>= 80 %) or "over" (>= 100 %)
	Chart               template.HTML
	Series              []chartSeries // the chart's legend
}

type nodeView struct {
	headscale.Node
	meter.Rate
	UpMonth     int64
	SharedMonth int64
}

// Idle: under 1 kB/s both ways, which a node's DERP keepalive alone produces.
func (n nodeView) Idle() bool { return n.Up < 1000 && n.Down < 1000 }

func (h *handler) index(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), opTimeout)
	defer cancel()
	now := h.deps.Now()
	rangeKey := r.URL.Query().Get("range")
	cr, ok := chartRanges[rangeKey]
	if !ok {
		rangeKey, cr = "1h", chartRanges["1h"]
	}
	start := cr.start(now)
	kind, series := "relayed", h.deps.Store.UsageSeries
	if r.URL.Query().Get("kind") == "shared" {
		kind, series = "shared", h.deps.Store.ShareSeries
	}
	all, err := h.deps.Store.ListFleets(ctx)
	if err != nil {
		log.Printf("admin: list fleets: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	// Like the devices below, a failure must not take the fleets down.
	names, err := h.deps.Store.ListNames(ctx)
	if err != nil {
		log.Printf("admin: list names: %v", err)
	}
	banned, err := h.deps.Store.BannedNames(ctx)
	if err != nil {
		log.Printf("admin: banned names: %v", err)
	}
	y, m, _ := now.UTC().Date()
	totals, err := h.deps.Store.UsageTotals(ctx, time.Date(y, m, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		log.Printf("admin: usage totals: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	points, err := series(ctx, cr.res, start)
	if err != nil {
		log.Printf("admin: usage series: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	sharedTotals, err := h.deps.Store.ShareTotals(ctx, time.Date(y, m, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		log.Printf("admin: share totals: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	var live meter.Live
	if h.deps.Meter != nil {
		if live = h.deps.Meter.Live(); !live.OK {
			live.Nodes = nil
		}
	}
	// A failure here must not take the whole page down: the operator still needs the fleets, so
	// every node is then shown as a box.
	devices, err := h.deps.Store.AllDevices(ctx)
	if err != nil {
		log.Printf("admin: list devices: %v", err)
	}
	known := map[string]bool{}
	for _, f := range all {
		known[f.ID] = true
	}
	var monthTotal, deleted, deletedShared int64
	var upNow float64
	fleetMonth, nodeMonth := map[string]int64{}, map[[2]string]int64{}
	for _, t := range totals {
		monthTotal += t.Rx
		fleetMonth[t.FleetID] += t.Rx
		nodeMonth[[2]string{t.FleetID, t.NodeID}] += t.Rx
		if !known[t.FleetID] {
			deleted += t.Rx
		}
	}
	var sharedTotal int64
	fleetShared, nodeShared := map[string]int64{}, map[[2]string]int64{}
	for _, t := range sharedTotals {
		sharedTotal += t.Rx
		if !known[t.FleetID] {
			deletedShared += t.Rx
		}
		fleetShared[t.FleetID] += t.Rx
		nodeShared[[2]string{t.FleetID, t.NodeID}] += t.Rx
	}
	for _, rt := range live.Nodes {
		upNow += rt.Up
	}
	fleetPoints := map[string][]store.UsagePoint{}
	for _, p := range points {
		fleetPoints[p.FleetID] = append(fleetPoints[p.FleetID], p)
	}
	sort.Slice(all, func(i, j int) bool {
		if a, b := fleetMonth[all[i].ID], fleetMonth[all[j].ID]; a != b {
			return a > b
		}
		if a, b := fleetShared[all[i].ID], fleetShared[all[j].ID]; a != b {
			return a > b
		}
		return all[i].LastOnline.After(all[j].LastOnline)
	})
	views := make([]fleetView, len(all))
	var wg sync.WaitGroup
	for i, f := range all {
		views[i] = fleetView{ID: f.ID, Created: f.CreatedAt, LastOnline: f.LastOnline, Month: fleetMonth[f.ID], Shared: fleetShared[f.ID]}
		if ref := h.cfg.MonthlyReference; ref > 0 {
			pct := float64(views[i].Month) / float64(ref) * 100
			views[i].RefPct = int(min(pct, 100))
			switch {
			case pct >= 100:
				views[i].RefClass = "over"
			case pct >= 80:
				views[i].RefClass = "warn"
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.nodeFetch <- struct{}{}
			defer func() { <-h.nodeFetch }()
			ns, err := h.deps.Headscale.ListNodes(ctx, f.HeadscaleUser)
			if err != nil {
				log.Printf("admin: fleet %s: list nodes: %v", f.ID, err)
				views[i].Err = true
				return
			}
			for _, n := range ns {
				nv := nodeView{Node: n, Rate: live.Nodes[n.ID], UpMonth: nodeMonth[[2]string{f.ID, n.ID}], SharedMonth: nodeShared[[2]string{f.ID, n.ID}]}
				views[i].Up += nv.Up
				if devices[n.ID] == f.ID {
					views[i].Devices = append(views[i].Devices, nv)
					continue
				}
				views[i].Nodes = append(views[i].Nodes, nv)
				if n.Online {
					views[i].Online++
				}
			}
		}()
	}
	wg.Wait()
	nodes, online, deviceCount := 0, 0, 0
	for i, v := range views {
		nodes += len(v.Nodes)
		deviceCount += len(v.Devices)
		online += v.Online
		names := map[string]string{}
		for _, n := range append(append([]nodeView(nil), v.Nodes...), v.Devices...) {
			names[n.ID] = n.Hostname
		}
		views[i].Series = fleetSeries(fleetPoints[v.ID], names, cr, start)
		views[i].Chart = stackedChart(views[i].Series, cr.n, kind)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := page.Execute(w, map[string]any{
		"Fleets": views, "Nodes": nodes, "DeviceCount": deviceCount, "Online": online, "Now": now,
		"MaxFleets": h.cfg.MaxFleets, "NodesPerFleet": h.cfg.NodesPerFleet, "CSRF": h.csrf,
		"Month": monthTotal, "SharedMonth": sharedTotal, "Kind": kind, "UpNow": upNow, "Live": live.OK, "Deleted": deleted, "DeletedShared": deletedShared,
		"Reference": h.cfg.MonthlyReference, "Range": rangeKey,
		"Names": names, "Banned": banned, "Version": h.cfg.Version,
	}); err != nil {
		log.Printf("admin: render: %v", err)
	}
}

func (h *handler) deleteFleet(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), fleets.RemoveTimeout)
	defer cancel()
	f, err := h.deps.Store.Fleet(ctx, r.PathValue("id"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		log.Printf("admin: get fleet: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if err == nil {
		if err := h.deps.Remover.Remove(ctx, f); err != nil {
			log.Printf("admin: fleet %s: delete: %v", f.ID, err)
			http.Error(w, "upstream error, retry", http.StatusBadGateway)
			return
		}
		log.Printf("admin: fleet %s deleted", f.ID)
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// removeNode only removes a node that belongs to the fleet named in the URL.
func (h *handler) removeNode(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()
	f, err := h.deps.Store.Fleet(ctx, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/admin/", http.StatusSeeOther)
		return
	}
	if err != nil {
		log.Printf("admin: get fleet: %v", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	ns, err := h.deps.Headscale.ListNodes(ctx, f.HeadscaleUser)
	if err != nil {
		log.Printf("admin: fleet %s: list nodes: %v", f.ID, err)
		http.Error(w, "upstream error, retry", http.StatusBadGateway)
		return
	}
	for _, n := range ns {
		if n.ID == r.PathValue("node") {
			if err := h.deps.Headscale.DeleteNodeByID(ctx, n.ID); err != nil {
				log.Printf("admin: fleet %s: remove node: %v", f.ID, err)
				http.Error(w, "upstream error, retry", http.StatusBadGateway)
				return
			}
			// A box has no device row and a device no box key: each delete is a no-op for the other.
			// Dropping the key now (its name cascades to quarantine) closes the tunnel at the next revalidation.
			for _, del := range []func(context.Context, string) error{h.deps.Store.DeleteDevice, h.deps.Store.DeleteBoxKey} {
				if err := del(ctx, n.ID); err != nil {
					log.Printf("admin: fleet %s: delete store rows of %s: %v", f.ID, n.ID, err)
					http.Error(w, "store error", http.StatusInternalServerError)
					return
				}
			}
			log.Printf("admin: fleet %s: node %s removed", f.ID, n.Hostname)
		}
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

// ban adds a name to the forbidden list and frees it from its holder: its box's tunnel closes at
// the next revalidation. The name comes from the form (add) or from the path (revoke).
func (h *handler) ban(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		name = r.PostFormValue("name")
	}
	if sharename.ValidLabel(name) != nil {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()
	if err := h.deps.Store.BanName(ctx, name, h.deps.Now()); err != nil {
		log.Printf("admin: ban %s: %v", name, err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	log.Printf("admin: name %s forbidden", name)
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}

func (h *handler) unban(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()
	name := r.PathValue("name")
	if sharename.ValidLabel(name) != nil {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	// Not found: a double click or the auto-reload raced the click; the name is gone, as asked.
	if err := h.deps.Store.UnbanName(ctx, name); err != nil && !errors.Is(err, store.ErrNotFound) {
		log.Printf("admin: unban %s: %v", name, err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/", http.StatusSeeOther)
}
