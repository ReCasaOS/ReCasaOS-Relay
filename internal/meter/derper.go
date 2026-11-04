// Package meter turns derper's per-connection byte counters into relayed usage per Headscale node
// and fleet, persisted in the store, plus live rates.
package meter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// pageSize is derper's maximum page (debugClientsMaxLimit): a shorter page is the last one.
const pageSize = 1000

// Conn is one derper connection and its byte counters as derper sees them: Rx is what the client
// sent (its upload), Tx what derper sent it.
type Conn struct {
	Key         string // "nodekey:…", as Headscale writes it
	ConnNum     int64
	ConnectedAt time.Time
	Rx, Tx      int64
}

// Derper reads derper's /debug/clients/ listing.
type Derper struct {
	base, debugKey string
	hc             *http.Client
}

// NewDerper returns a client for the derper at baseURL; hc nil means http.DefaultClient.
func NewDerper(baseURL, debugKey string, hc *http.Client) *Derper {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Derper{base: strings.TrimRight(baseURL, "/"), debugKey: debugKey, hc: hc}
}

// Clients lists every connection, following derper's pagination (sorted by key, then connNum).
// Errors never carry the URL: it holds the debug key.
func (d *Derper) Clients(ctx context.Context) ([]Conn, error) {
	var out []Conn
	v := url.Values{"all": {"1"}, "format": {"json"}, "limit": {strconv.Itoa(pageSize)}, "debugkey": {d.debugKey}}
	for {
		page, err := d.page(ctx, v)
		if err != nil {
			return nil, fmt.Errorf("meter: derper clients: %w", err)
		}
		out = append(out, page...)
		if len(page) < pageSize {
			return out, nil
		}
		// after alone would skip the key's other connections; afterconn resumes among them.
		last := page[len(page)-1]
		after, afterConn := last.Key, strconv.FormatInt(last.ConnNum, 10)
		if v.Get("after") == after && v.Get("afterconn") == afterConn {
			return nil, errors.New("meter: derper clients: pagination does not advance")
		}
		v.Set("after", after)
		v.Set("afterconn", afterConn)
	}
}

func (d *Derper) page(ctx context.Context, v url.Values) ([]Conn, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+"/debug/clients/?"+v.Encode(), nil)
	if err != nil {
		return nil, errors.New("bad derper URL")
	}
	resp, err := d.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // ue.Error() quotes the URL
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// Field names: tailscale.com v1.104.5 derp/derpserver/debugclients.go (debugClientsJSON).
	var body struct {
		Clients []struct {
			Key         string    `json:"key"`
			ConnNum     int64     `json:"connNum"`
			ConnectedAt time.Time `json:"connectedAt"`
			RxBytes     int64     `json:"rxBytes"`
			TxBytes     int64     `json:"txBytes"`
		} `json:"clients"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	out := make([]Conn, len(body.Clients))
	for i, c := range body.Clients {
		out[i] = Conn{Key: c.Key, ConnNum: c.ConnNum, ConnectedAt: c.ConnectedAt, Rx: c.RxBytes, Tx: c.TxBytes}
	}
	return out, nil
}
