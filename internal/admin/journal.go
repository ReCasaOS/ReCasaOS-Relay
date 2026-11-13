package admin

import (
	"cmp"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/journal"
)

//go:embed journal.html
var journalHTML string

// journalPage shares page.html's "css" block.
var journalPage = template.Must(template.Must(page.Clone()).New("journal").Parse(journalHTML))

const journalPageSize = 200

// maxStreams bounds the live journals open at once: each polls the log folders.
const maxStreams = 4

// The stream sends at most streamMax lines per streamWindow; heartbeat is a test seam.
var (
	streamMax       = 200
	streamWindow    = time.Second
	streamHeartbeat = 15 * time.Second
)

// streamWriteTimeout bounds one write to a stalled browser.
const streamWriteTimeout = 30 * time.Second

var journalSources = []struct{ Key, Label string }{
	{"share", "Visitors"}, {"front", "Relay requests"}, {"relay", "Events"}, {"log", "Messages"},
}

var journalRanges = []struct {
	Key, Label string
	D          time.Duration
}{
	{"1h", "last hour", time.Hour}, {"6h", "last 6 h", 6 * time.Hour}, {"24h", "last 24 h", 24 * time.Hour}, {"7d", "last 7 days", 7 * 24 * time.Hour},
}

var errQuery = errors.New("search text over 200 characters")

// journalQuery reads the filters of the page and the stream; unknown sources are ignored.
func journalQuery(r *http.Request) (journal.Query, error) {
	v := r.URL.Query()
	q := journal.Query{Text: strings.TrimSpace(v.Get("q")), Problems: v.Get("problems") != ""}
	if len(q.Text) > 200 {
		return q, errQuery
	}
	for _, s := range journalSources {
		if slices.Contains(v["src"], s.Key) {
			q.Src = append(q.Src, s.Key)
		}
	}
	return q, nil
}

// journalLine is an entry as the page shows it; the stream sends it as JSON, so the browser builds
// the same line with textContent only.
type journalLine struct {
	journal.Entry
	When  string `json:"when"`
	Text  string `json:"text"`
	Class string `json:"cls,omitempty"`
}

func millis(ms int64) string {
	switch {
	case ms <= 0:
		return ""
	case ms < 1000:
		return strconv.FormatInt(ms, 10) + " ms"
	}
	return strconv.FormatInt(ms/1000, 10) + " s"
}

func viewLine(e journal.Entry) journalLine {
	l := journalLine{Entry: e, When: e.Time}
	if len(e.Time) >= 19 {
		l.When = e.Time[5:10] + " " + e.Time[11:19]
	}
	var p []string
	add := func(s ...string) {
		for _, x := range s {
			if x != "" {
				p = append(p, x)
			}
		}
	}
	switch e.Src {
	case "front":
		add(strings.TrimSpace(e.Method + " " + e.Path))
		if e.Status != 0 {
			add(strconv.Itoa(e.Status))
		}
		add(millis(e.Ms))
	case "log":
		add(e.Svc)
	}
	add(map[string]string{"pass": "passed", "cut": "cut", "close": "closed"}[e.Act], e.Reason, e.Source)
	if e.Act == "close" {
		add(millis(e.Ms), "↓ "+humanBytes(float64(e.Out))+" ↑ "+humanBytes(float64(e.In)))
	}
	add(e.Event, e.Msg)
	if e.Count != 0 {
		add("count " + strconv.FormatInt(e.Count, 10))
	}
	l.Text = strings.Join(p, " · ")
	switch {
	case e.Act == "cut" || e.Status >= 500:
		l.Class = "bad"
	case e.Status >= 400 || e.Src == "log":
		l.Class = "warn"
	case e.Act == "pass":
		l.Class = "ok"
	}
	return l
}

func (h *handler) journal(w http.ResponseWriter, r *http.Request) {
	q, err := journalQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v := r.URL.Query()
	rg := journalRanges[0]
	for _, x := range journalRanges {
		if x.Key == v.Get("range") {
			rg = x
		}
	}
	// Always bounded: files outlive LOG_KEEP while their writer is stopped, and a Caddy *.log has its own.
	q.From = h.deps.Now().Add(-rg.D)
	before, _ := time.Parse(time.RFC3339Nano, v.Get("before")) // unparsable: the newest page
	type src struct {
		Key, Label string
		On         bool
	}
	srcs := make([]src, len(journalSources))
	for i, s := range journalSources {
		srcs[i] = src{s.Key, s.Label, len(q.Src) == 0 || slices.Contains(q.Src, s.Key)}
	}
	data := map[string]any{"Version": h.cfg.Version, "Sources": srcs, "Q": q.Text, "Problems": q.Problems,
		"Range": rg.Key, "Ranges": journalRanges, "Before": v.Get("before")}
	status := http.StatusOK
	if rd := h.deps.JournalReader; rd == nil {
		data["Off"] = true
	} else {
		entries, more, partial, resume, err := rd.Page(r.Context(), q, before, journalPageSize)
		switch {
		case errors.Is(err, journal.ErrBusy):
			status, data["Busy"] = http.StatusServiceUnavailable, true
		case r.Context().Err() != nil:
			return // the browser left mid-search
		case err != nil:
			log.Printf("admin: journal page: %v", err)
			http.Error(w, "journal error", http.StatusInternalServerError)
			return
		}
		lines := make([]journalLine, len(entries))
		for i, e := range entries {
			lines[i] = viewLine(e)
		}
		data["Lines"] = lines
		data["Live"] = err == nil && rg.Key == "1h" && before.IsZero()
		link := func(before string) string {
			if v.Del("before"); before != "" {
				v.Set("before", before)
			}
			return "?" + v.Encode()
		}
		resumeAt := "" // zero: the stop came before anything was read; search on from the same place
		if !resume.IsZero() {
			resumeAt = resume.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		// After a budget stop the last group may be split: go on from the reader's resume point.
		switch {
		case more && !partial && len(entries) > 0:
			data["Older"] = link(entries[len(entries)-1].Time)
		case partial && len(entries) >= journalPageSize:
			data["Older"] = link(resumeAt)
		case partial:
			data["SearchOn"] = link(resumeAt)
			data["Empty"] = len(entries) == 0
			data["Budget"] = strconv.FormatInt(cmp.Or(rd.MaxBytes, 64<<20)>>20, 10) + " MiB or " + cmp.Or(rd.MaxTime, 5*time.Second).String()
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := journalPage.Execute(w, data); err != nil {
		log.Printf("admin: render journal: %v", err)
	}
}

// journalStream sends the new matching lines as Server-Sent Events, at most streamMax in any
// streamWindow; beyond, it counts them and sends {"dropped":N} once per window.
func (h *handler) journalStream(w http.ResponseWriter, r *http.Request) {
	rd := h.deps.JournalReader
	if rd == nil {
		http.NotFound(w, r)
		return
	}
	q, err := journalQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	select {
	case h.streams <- struct{}{}:
		defer func() { <-h.streams }()
	default:
		http.Error(w, "too many live journals open: close one", http.StatusServiceUnavailable)
		return
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	ctx, cancel := context.WithCancel(r.Context())
	ch, done := make(chan journal.Entry, 256), make(chan struct{})
	go func() { defer close(done); rd.Follow(ctx, q, ch) }()
	defer func() { cancel(); <-done }()
	write := func(s string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout)) // rolling: a stalled browser is let go
		if _, err := io.WriteString(w, s); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !write(": journal\n\n") {
		return
	}
	sent := make([]time.Time, streamMax) // the last streamMax send times, a ring
	next, dropped := 0, 0
	tick, beat := time.NewTicker(streamWindow), time.NewTicker(streamHeartbeat)
	defer tick.Stop()
	defer beat.Stop()
	for {
		var msg string
		select {
		case <-ctx.Done():
			return
		case <-h.deps.Shutdown:
			return
		case e := <-ch:
			now := time.Now()
			if now.Sub(sent[next]) < streamWindow {
				dropped++
				continue
			}
			sent[next], next = now, (next+1)%len(sent)
			b, _ := json.Marshal(viewLine(e))
			msg = "data: " + string(b) + "\n\n"
		case <-tick.C:
			if dropped == 0 {
				continue
			}
			msg = `data: {"dropped":` + strconv.Itoa(dropped) + "}\n\n"
			dropped = 0
		case <-beat.C:
			msg = ": ping\n\n"
		}
		if !write(msg) {
			return
		}
	}
}
