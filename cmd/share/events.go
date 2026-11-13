package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

const (
	seenEvery     = 10 * time.Minute // an accepted (key, node) pair is reported at most this often
	maxEvents     = 10000            // pending items kept while enrolment is unreachable
	eventsPerPost = 2000
)

type seenItem struct {
	Key    string `json:"key"`
	NodeID string `json:"node_id"`
}

type refKey struct{ Hour, Name, Key, Reason, Source string }

type refItem struct {
	Hour   string `json:"hour"`
	Name   string `json:"name"`
	Key    string `json:"key"`
	Reason string `json:"reason"`
	Source string `json:"source"`
	Count  int64  `json:"count"`
}

type eventsBody struct {
	Seen     []seenItem `json:"seen"`
	Refusals []refItem  `json:"refusals"`
}

// events tells enrolment which visitor reached which box (it needs that to accept ban reports) and how
// many visitors were refused. Safe for concurrent use; a nil *events records nothing.
type events struct {
	now func() time.Time

	mu       sync.Mutex
	seenAt   map[seenItem]time.Time // last recorded, pruned on flush
	seenQ    []seenItem             // oldest first
	refs     map[refKey]*refItem
	refOrder []refKey // oldest first
}

func newEvents() *events {
	return &events{now: time.Now, seenAt: map[seenItem]time.Time{}, refs: map[refKey]*refItem{}}
}

// eventKey is the address key of the contract: IPv4 as a.b.c.d/32, IPv6 as its /64. Addresses that are
// not a visitor (loopback, private, link-local, unspecified, multicast, CGNAT) give "".
func eventKey(a netip.Addr) string {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsUnspecified() ||
		a.IsMulticast() || netip.MustParsePrefix("100.64.0.0/10").Contains(a) {
		return ""
	}
	if a.Is4() {
		return netip.PrefixFrom(a, 32).String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

// connKey is eventKey of c's peer.
func connKey(c net.Conn) string {
	a, ok := remoteAddr(c)
	if !ok {
		return ""
	}
	return eventKey(a)
}

// seen records that key reached the box node, unless it was recorded less than 10 minutes ago.
func (e *events) seen(key, nodeID string) {
	if e == nil || key == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	k, now := seenItem{key, nodeID}, e.now()
	if t, ok := e.seenAt[k]; ok && now.Sub(t) < seenEvery {
		return
	}
	e.seenAt[k] = now
	e.seenQ = append(e.seenQ, k)
	e.trim()
}

// refused counts one refusal in the current hour.
func (e *events) refused(name, key, reason, source string) {
	if e == nil || key == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.addRef(refItem{Hour: e.now().UTC().Truncate(time.Hour).Format(time.RFC3339), Name: name, Key: key, Reason: reason, Source: source, Count: 1}, false)
	e.trim()
}

// addRef adds r's count to its row; a new row goes last, or first with front (a batch put back).
func (e *events) addRef(r refItem, front bool) {
	k := refKey{r.Hour, r.Name, r.Key, r.Reason, r.Source}
	if p, ok := e.refs[k]; ok {
		p.Count += r.Count
		return
	}
	e.refs[k] = &r
	if front {
		e.refOrder = append([]refKey{k}, e.refOrder...)
	} else {
		e.refOrder = append(e.refOrder, k)
	}
}

// trim drops the oldest pending items past maxEvents (seen first: a refusal count cannot be rebuilt).
func (e *events) trim() {
	for over := len(e.seenQ) + len(e.refOrder) - maxEvents; over > 0; over-- {
		if len(e.seenQ) > 0 {
			e.seenQ = e.seenQ[1:]
		} else {
			delete(e.refs, e.refOrder[0])
			e.refOrder = e.refOrder[1:]
		}
	}
}

// flush posts everything pending to url in chunks of at most 2000 items. A chunk answered 4xx is dropped
// (retrying a refused batch would block every later one); after a transport error or a 5xx the chunk
// and the rest go back in front of what was recorded meanwhile.
func (e *events) flush(ctx context.Context, url string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	cut := e.now().Add(-seenEvery)
	for k, t := range e.seenAt {
		if t.Before(cut) {
			delete(e.seenAt, k)
		}
	}
	seen, refs := e.seenQ, make([]refItem, 0, len(e.refOrder))
	for _, k := range e.refOrder {
		refs = append(refs, *e.refs[k])
	}
	e.seenQ, e.refs, e.refOrder = nil, map[refKey]*refItem{}, nil
	e.mu.Unlock()

	for len(seen)+len(refs) > 0 {
		var b eventsBody
		n := min(len(seen), eventsPerPost)
		b.Seen, seen = seen[:n], seen[n:]
		m := min(len(refs), eventsPerPost-n)
		b.Refusals, refs = refs[:m], refs[m:]
		code := e.post(ctx, url, b)
		if code == http.StatusNoContent {
			continue
		}
		if code >= 400 && code < 500 {
			log.Printf("share: events: HTTP %d, dropping %d items", code, n+m)
			continue
		}
		e.mu.Lock() // put back: this chunk and the rest, before anything newer
		e.seenQ = append(append(b.Seen, seen...), e.seenQ...)
		for i := len(refs) - 1; i >= 0; i-- {
			e.addRef(refs[i], true)
		}
		for i := len(b.Refusals) - 1; i >= 0; i-- {
			e.addRef(b.Refusals[i], true)
		}
		e.trim()
		e.mu.Unlock()
		return
	}
}

// post sends one body and returns the HTTP status, 0 when there was none.
func (e *events) post(ctx context.Context, url string, b eventsBody) int {
	buf, _ := json.Marshal(b)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return 0
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := do(req)
	if err != nil {
		log.Printf("share: events: %v", err)
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}
