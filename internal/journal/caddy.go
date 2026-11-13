package journal

import (
	"encoding/json"
	"math"
	"strings"
	"time"
)

// caddyLine is the part of a Caddy access log line the journal keeps. It has
// no field for request or response headers, so they are never even decoded.
type caddyLine struct {
	TS      float64 `json:"ts"`
	Request *struct {
		ClientIP string `json:"client_ip"`
		Host     string `json:"host"`
		Method   string `json:"method"`
		URI      string `json:"uri"`
	} `json:"request"`
	BytesRead int64   `json:"bytes_read"`
	Duration  float64 `json:"duration"` // seconds
	Size      int64   `json:"size"`
	Status    int     `json:"status"`
}

// ParseCaddy converts one line of Caddy's JSON access log to an Entry.
func ParseCaddy(line []byte) (Entry, bool) {
	var c caddyLine
	if json.Unmarshal(line, &c) != nil || c.TS <= 0 || c.Request == nil {
		return Entry{}, false
	}
	path, _, _ := strings.Cut(c.Request.URI, "?") // the query is not kept: it can carry codes and personal data
	return Entry{
		// Round: 1763030400.123 is 1763030400.12299990654 as a float.
		Time:   time.UnixMilli(int64(math.Round(c.TS * 1000))).UTC().Format(timeLayout),
		Src:    "front",
		Svc:    "front",
		IP:     c.Request.ClientIP,
		Host:   c.Request.Host,
		Method: c.Request.Method,
		Path:   path,
		Status: c.Status,
		Ms:     int64(math.Round(c.Duration * 1000)),
		In:     c.BytesRead,
		Out:    c.Size,
	}, true
}
