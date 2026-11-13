package admin

import (
	"context"
	_ "embed"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ReCasaOS/recasaos-relay/internal/feeds"
	"github.com/ReCasaOS/recasaos-relay/internal/journal"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

//go:embed protect.html
var protectHTML string

// protectPage shares page.html's "css" block.
var protectPage = template.Must(template.Must(page.Clone()).New("protect").Parse(protectHTML))

// refreshTimeout matches the fetcher's own download timeout.
const refreshTimeout = 60 * time.Second

var headerName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// feedView is a feed as the page may show it: never its key nor its URL (either may hold a secret).
type feedView struct {
	store.Feed
	Host, Key, URLHint string
}

type presetView struct {
	feeds.Preset
	Added bool
}

func viewFeed(f store.Feed) feedView {
	v := feedView{Feed: f, Key: mask(f.AuthValue)}
	if u, err := url.Parse(f.URL); err == nil {
		v.Host = u.Host
	}
	v.URLHint = "https://" + v.Host + "/…"
	for _, p := range feeds.Presets {
		if p.Key == f.Preset && p.URL == f.URL { // a preset's own URL is public
			v.URLHint = f.URL
		}
	}
	v.Feed.URL, v.Feed.AuthValue = "", ""
	return v
}

// mask shows the last 4 characters of a key at most, none of a key under 8.
func mask(s string) string {
	r := []rune(s)
	switch {
	case len(r) == 0:
		return ""
	case len(r) < 8:
		return "••••"
	}
	return "••••" + string(r[len(r)-4:])
}

func (h *handler) protection(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), opTimeout)
	defer cancel()
	now := h.deps.Now()
	fs, err := h.deps.Store.Feeds(ctx)
	if err != nil {
		h.storeError(w, "feeds", err)
		return
	}
	manual, err := h.deps.Store.ManualBans(ctx, now)
	if err != nil {
		h.storeError(w, "manual bans", err)
		return
	}
	allow, err := h.deps.Store.AllowList(ctx)
	if err != nil {
		h.storeError(w, "allow list", err)
		return
	}
	views, added := make([]feedView, len(fs)), map[string]bool{}
	for i, f := range fs {
		views[i], added[f.Preset] = viewFeed(f), true
	}
	presets := make([]presetView, len(feeds.Presets))
	for i, p := range feeds.Presets {
		presets[i] = presetView{p, added[p.Key]}
	}
	data, err := h.protectStats(ctx, now)
	if err != nil {
		h.storeError(w, "protection stats", err)
		return
	}
	edit, _ := strconv.ParseInt(r.URL.Query().Get("edit"), 10, 64)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	for k, v := range map[string]any{
		"Now": now, "CSRF": h.csrf, "Version": h.cfg.Version, "Edit": edit,
		"Feeds": views, "Presets": presets, "Fetcher": h.deps.Feeds != nil,
		"Manual": manual, "Allow": allow, "Geo": h.deps.Geo != nil && h.deps.Geo.Version() != "",
		"ConnsPerIP": h.cfg.ConnsPerIP, "ConnsPerIPPerBox": h.cfg.ConnsPerIPPerBox,
	} {
		data[k] = v
	}
	if err := protectPage.Execute(w, data); err != nil {
		log.Printf("admin: render protection: %v", err)
	}
}

func (h *handler) storeError(w http.ResponseWriter, what string, err error) {
	log.Printf("admin: %s: %v", what, err)
	http.Error(w, "store error", http.StatusInternalServerError)
}

// event journals one operator action; the message never holds a feed's URL or key.
func (h *handler) event(ev, ip, host, msg string) {
	h.deps.Journal.Write(journal.Entry{Src: "relay", Event: ev, IP: ip, Host: host, Msg: msg})
}

// done ends every protection write: the snapshot is rebuilt at its next poll.
func (h *handler) done(w http.ResponseWriter, r *http.Request, to string) {
	if h.deps.Protect != nil {
		h.deps.Protect.Invalidate()
	}
	http.Redirect(w, r, "/admin/protection"+to, http.StatusSeeOther)
}

func writeCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
}

// feedForm overlays the form on f; an empty url or auth_value keeps f's. It returns what is wrong, or "".
func feedForm(r *http.Request, f *store.Feed) string {
	name := strings.TrimSpace(r.PostFormValue("name"))
	if n := utf8.RuneCountInString(name); n < 1 || n > 64 {
		return "name: 1 to 64 characters"
	}
	f.Name = name
	if u := strings.TrimSpace(r.PostFormValue("url")); u != "" || f.URL == "" {
		// Only https: a plain-http list could be rewritten in transit to ban everyone.
		if pu, err := url.Parse(u); err != nil || pu.Scheme != "https" || pu.Host == "" {
			return "url: an https:// address"
		}
		f.URL = u
	}
	f.Format, f.Column = r.PostFormValue("format"), 0
	switch f.Format {
	case "text":
	case "csv":
		c, err := strconv.Atoi(r.PostFormValue("column"))
		if err != nil || c < 1 {
			return "column: 1 or more for csv"
		}
		f.Column = c
	default:
		return "format: text or csv"
	}
	every, err := strconv.Atoi(r.PostFormValue("every_s"))
	if err != nil || every < 3600 || every > 365*86400 {
		return "every_s: 3600 (an hour) to a year"
	}
	f.EverySec, f.MaxEntries = every, 100000
	if v := r.PostFormValue("max_entries"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 10_000_000 {
			return "max_entries: 1 to 10 000 000"
		}
		f.MaxEntries = n
	}
	f.AuthName = strings.TrimSpace(r.PostFormValue("auth_name"))
	if f.AuthName != "" && !headerName.MatchString(f.AuthName) { // Authorization-Basic matches too
		return "auth_name: a header name, or Authorization-Basic"
	}
	if v := strings.TrimSpace(r.PostFormValue("auth_value")); v != "" {
		f.AuthValue = v
	}
	if f.AuthName == "" {
		f.AuthValue = ""
	}
	return note(r, &f.Note)
}

func note(r *http.Request, dst *string) string {
	n := strings.TrimSpace(r.PostFormValue("note"))
	if utf8.RuneCountInString(n) > 200 {
		return "note: 200 characters at most"
	}
	*dst = n
	return ""
}

func (h *handler) addFeed(w http.ResponseWriter, r *http.Request) {
	var f store.Feed
	if msg := feedForm(r, &f); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	ctx, cancel := writeCtx(r)
	defer cancel()
	if _, err := h.deps.Store.AddFeed(ctx, f); errors.Is(err, store.ErrExists) {
		http.Error(w, "a list with this name already exists", http.StatusBadRequest)
		return
	} else if err != nil {
		h.storeError(w, "add feed", err)
		return
	}
	h.event("feed_admin", "", "", f.Name+" add")
	h.done(w, r, "#feeds")
}

// addPreset adds a preset, disabled; one that needs a key opens its edit form.
func (h *handler) addPreset(w http.ResponseWriter, r *http.Request) {
	for _, p := range feeds.Presets {
		if p.Key != r.PathValue("key") {
			continue
		}
		ctx, cancel := writeCtx(r)
		defer cancel()
		id, err := h.deps.Store.AddFeed(ctx, store.Feed{Name: p.Name, URL: p.URL, AuthName: p.AuthName, Format: p.Format,
			Column: p.Column, EverySec: p.EverySec, MaxEntries: 100000, Note: p.Note, Preset: p.Key})
		switch {
		case errors.Is(err, store.ErrExists):
			if h.presetAdded(ctx, p) { // a second click
				h.done(w, r, "#feeds")
				return
			}
			http.Error(w, "a list named "+p.Name+" already exists; rename it first", http.StatusBadRequest)
		case err != nil:
			h.storeError(w, "add preset", err)
		case p.NeedsKey:
			h.event("feed_admin", "", "", p.Name+" add")
			h.done(w, r, "?edit="+strconv.FormatInt(id, 10)+"#feeds")
		default:
			h.event("feed_admin", "", "", p.Name+" add")
			h.done(w, r, "#feeds")
		}
		return
	}
	http.NotFound(w, r)
}

// presetAdded: the feed holding p's name is p itself, not a list of the operator's.
func (h *handler) presetAdded(ctx context.Context, p feeds.Preset) bool {
	fs, err := h.deps.Store.Feeds(ctx)
	if err != nil {
		return false
	}
	for _, f := range fs {
		if f.Name == p.Name {
			return f.Preset == p.Key
		}
	}
	return false
}

// feed finds the feed of the path's {id}; ok false means the reply is written.
func (h *handler) feed(ctx context.Context, w http.ResponseWriter, r *http.Request) (store.Feed, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return store.Feed{}, false
	}
	fs, err := h.deps.Store.Feeds(ctx)
	if err != nil {
		h.storeError(w, "feeds", err)
		return store.Feed{}, false
	}
	for _, f := range fs {
		if f.ID == id {
			return f, true
		}
	}
	h.done(w, r, "#feeds") // gone: a double click or another tab
	return store.Feed{}, false
}

func (h *handler) updateFeed(ctx context.Context, w http.ResponseWriter, r *http.Request, f store.Feed, action string) {
	// The CrowdSec preset's URL holds "<integration id>" until the operator fills it in.
	if f.Enabled && strings.Contains(f.URL, "<") {
		http.Error(w, "replace the <…> part of the URL first", http.StatusBadRequest)
		return
	}
	if err := h.deps.Store.UpdateFeed(ctx, f); errors.Is(err, store.ErrExists) {
		http.Error(w, "a list with this name already exists", http.StatusBadRequest)
		return
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		h.storeError(w, "update feed", err)
		return
	}
	h.event("feed_admin", "", "", f.Name+" "+action)
	h.done(w, r, "#feeds")
}

func (h *handler) editFeed(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := writeCtx(r)
	defer cancel()
	f, ok := h.feed(ctx, w, r)
	if !ok {
		return
	}
	if msg := feedForm(r, &f); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	h.updateFeed(ctx, w, r, f, "edit")
}

func (h *handler) feedAction(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action != "toggle" && action != "refresh" && action != "delete" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := writeCtx(r)
	defer cancel()
	f, ok := h.feed(ctx, w, r)
	if !ok {
		return
	}
	switch action {
	case "toggle":
		f.Enabled = !f.Enabled
		h.updateFeed(ctx, w, r, f, "toggle")
	case "refresh":
		if h.deps.Feeds == nil {
			http.Error(w, "list downloads are not available on this relay", http.StatusServiceUnavailable)
			return
		}
		// Outlives the client (the server's write timeout is shorter); the result, error included,
		// is stored with the feed and shown on the next load.
		rctx, rcancel := context.WithTimeout(context.WithoutCancel(r.Context()), refreshTimeout)
		defer rcancel()
		_ = h.deps.Feeds.Refresh(rctx, f.ID)
		h.event("feed_admin", "", "", f.Name+" refresh")
		h.done(w, r, "#feeds")
	case "delete":
		if err := h.deps.Store.DeleteFeed(ctx, f.ID); err != nil {
			h.storeError(w, "delete feed", err)
			return
		}
		if h.deps.Feeds != nil {
			if err := h.deps.Feeds.Forget(f.ID); err != nil { // the row is gone, so the copy is never loaded again
				log.Printf("admin: feed %d: remove copy: %v", f.ID, err)
			}
		}
		h.event("feed_admin", "", "", f.Name+" delete")
		h.done(w, r, "#feeds")
	}
}

// prefix reads an address or a prefix as a masked prefix; an IPv4-mapped address is IPv4.
func prefix(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil || a.Zone() != "" {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if a := p.Addr(); a.Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p.Masked(), p.IsValid()
}

// broadEnough: like the feeds, nothing broader than /8 (IPv4) or /19 (IPv6).
func broadEnough(p netip.Prefix) bool {
	return p.Bits() >= map[bool]int{true: 8, false: 19}[p.Addr().Is4()]
}

// manualValue checks a ban's value and returns it as stored, or "" when it is wrong.
func manualValue(kind, v string) string {
	switch kind {
	case "address":
		if p, ok := prefix(v); ok && p.IsSingleIP() {
			return p.String()
		}
	case "range":
		if p, ok := prefix(v); ok && broadEnough(p) {
			return p.String()
		}
	case "asn":
		if n, err := strconv.ParseUint(strings.TrimPrefix(v, "AS"), 10, 32); err == nil && n > 0 {
			return strconv.FormatUint(n, 10)
		}
	case "country":
		if len(v) == 2 && 'A' <= v[0] && v[0] <= 'Z' && 'A' <= v[1] && v[1] <= 'Z' {
			return v
		}
	}
	return ""
}

func (h *handler) addManual(w http.ResponseWriter, r *http.Request) {
	m := store.ManualBan{Kind: r.PostFormValue("kind"), Since: h.deps.Now()}
	if m.Value = manualValue(m.Kind, strings.TrimSpace(r.PostFormValue("value"))); m.Value == "" {
		http.Error(w, "value: an address, a range (/8 or narrower for IPv4, /19 for IPv6), an ASN or a two-letter country code in capitals", http.StatusBadRequest)
		return
	}
	hours, err := strconv.Atoi(r.PostFormValue("hours"))
	if err != nil || hours < 0 || hours > 8760 {
		http.Error(w, "hours: 0 (permanent) to 8760", http.StatusBadRequest)
		return
	}
	if hours > 0 {
		m.Until = m.Since.Add(time.Duration(hours) * time.Hour)
	}
	if msg := note(r, &m.Note); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	ctx, cancel := writeCtx(r)
	defer cancel()
	if _, err := h.deps.Store.AddManual(ctx, m); err != nil {
		h.storeError(w, "add manual ban", err)
		return
	}
	h.event("manual_add", "", "", m.Kind+" "+m.Value)
	h.done(w, r, "#manual")
}

func (h *handler) addAllow(w http.ResponseWriter, r *http.Request) {
	// An allow-all would silently turn every filter off.
	p, ok := prefix(strings.TrimSpace(r.PostFormValue("value")))
	if !ok || !broadEnough(p) {
		http.Error(w, "value: an address or a range (/8 or narrower for IPv4, /19 for IPv6)", http.StatusBadRequest)
		return
	}
	e := store.AllowEntry{Prefix: p.String(), Added: h.deps.Now()}
	if msg := note(r, &e.Note); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	ctx, cancel := writeCtx(r)
	defer cancel()
	if _, err := h.deps.Store.AddAllow(ctx, e); err != nil {
		h.storeError(w, "add allow", err)
		return
	}
	h.event("allow_add", e.Prefix, "", "")
	h.done(w, r, "#allow")
}

func (h *handler) deleteManual(w http.ResponseWriter, r *http.Request) {
	h.deleteRow(w, r, h.deps.Store.DeleteManual, "#manual", "manual_del", func(ctx context.Context, id int64) (ip, msg string) {
		if ms, err := h.deps.Store.ManualBans(ctx, h.deps.Now()); err == nil {
			for _, m := range ms {
				if m.ID == id {
					return "", m.Kind + " " + m.Value
				}
			}
		}
		return "", "id " + strconv.FormatInt(id, 10)
	})
}

func (h *handler) deleteAllow(w http.ResponseWriter, r *http.Request) {
	h.deleteRow(w, r, h.deps.Store.DeleteAllow, "#allow", "allow_del", func(ctx context.Context, id int64) (ip, msg string) {
		if as, err := h.deps.Store.AllowList(ctx); err == nil {
			for _, a := range as {
				if a.ID == id {
					return a.Prefix, ""
				}
			}
		}
		return "", "id " + strconv.FormatInt(id, 10)
	})
}

// deleteRow deletes the row of the path's {id}; describe, read before the delete, gives the journal line.
func (h *handler) deleteRow(w http.ResponseWriter, r *http.Request, del func(context.Context, int64) error, section, event string,
	describe func(context.Context, int64) (ip, msg string)) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := writeCtx(r)
	defer cancel()
	ip, msg := describe(ctx, id)
	if err := del(ctx, id); err != nil {
		h.storeError(w, "delete "+section[1:], err)
		return
	}
	h.event(event, ip, "", msg)
	h.done(w, r, section)
}
