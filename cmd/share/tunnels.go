package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/proxyproto"
	"github.com/ReCasaOS/recasaos-relay/internal/sni"
	"github.com/ReCasaOS/recasaos-relay/internal/tunnel"
)

var enrolmentClient = &http.Client{Timeout: 5 * time.Second}

// do runs req, dropping the URL from transport errors: the resolve URL holds the box key.
func do(req *http.Request) (*http.Response, error) {
	resp, err := enrolmentClient.Do(req)
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return resp, err
}

// resolver asks enrolment which box a key belongs to: 404 is tunnel.ErrNotFound, anything else that is
// not a 200 is a transport error.
func resolver(enrolmentURL string) tunnel.Resolver {
	return func(ctx context.Context, key string) (tunnel.Box, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, enrolmentURL+"/internal/share/boxes/"+url.PathEscape(key), nil)
		if err != nil { // its *url.Error would print the URL, which holds the key
			return tunnel.Box{}, errors.New("enrolment: cannot build the resolve request")
		}
		resp, err := do(req)
		if err != nil {
			return tunnel.Box{}, err
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusOK:
		case http.StatusNotFound:
			return tunnel.Box{}, tunnel.ErrNotFound
		default:
			return tunnel.Box{}, fmt.Errorf("enrolment: HTTP %d", resp.StatusCode)
		}
		var b struct {
			Name    string `json:"name"`
			NodeID  string `json:"node_id"`
			FleetID string `json:"fleet_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
			return tunnel.Box{}, fmt.Errorf("enrolment: %w", err)
		}
		return tunnel.Box(b), nil
	}
}

// toTunnel sends the visitor connection c (replay holds its peeked ClientHello) into box's tunnel.
func toTunnel(reg *tunnel.Registry, box string, c, replay net.Conn) {
	t, ok := reg.Get(box)
	if !ok {
		return
	}
	stream, err := t.Open(context.Background())
	if err != nil {
		if !errors.Is(err, tunnel.ErrFull) { // Open logs that one, at most once a minute
			log.Printf("share: open stream to %q: %v", box, err)
		}
		return
	}
	defer stream.Close()
	src, _ := c.RemoteAddr().(*net.TCPAddr)
	dst, _ := c.LocalAddr().(*net.TCPAddr)
	if src == nil || dst == nil || proxyproto.WriteV2(stream, src, dst) != nil {
		return
	}
	// Idle for idleTimeout either way: close both ends, or the stream would stay held forever.
	idle := time.AfterFunc(idleTimeout, func() { c.Close(); stream.SetDeadline(time.Now()) })
	defer idle.Stop()
	sni.Forward(&idleConn{Conn: replay, t: idle}, stream) // the stream counts the bytes into t
}

// idleTimeout closes a visitor connection that moved no byte in either direction for that long.
var idleTimeout = 5 * time.Minute

// idleConn pushes its timer back on every read and write: it carries both directions of the visitor.
type idleConn struct {
	net.Conn
	t *time.Timer
}

func (c *idleConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.t.Reset(idleTimeout)
	return n, err
}

func (c *idleConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.t.Reset(idleTimeout)
	return n, err
}

// sample is one line of POST /internal/share/usage.
type sample struct {
	FleetID string `json:"fleet_id"`
	NodeID  string `json:"node_id"`
	RX      int64  `json:"rx"`
	TX      int64  `json:"tx"`
}

// maxPending bounds the nodes whose bytes wait for enrolment to come back.
const maxPending = 10000

// usage reports the bytes of every tunnel to enrolment, which also takes each line as the node's
// heartbeat (tunnel_online). Bytes a failed post could not deliver are kept for the next one.
type usage struct {
	reg     *tunnel.Registry
	url     string
	pending map[[2]string]sample // by fleet, node
}

func newUsage(reg *tunnel.Registry, enrolmentURL string) *usage {
	return &usage{reg: reg, url: enrolmentURL + "/internal/share/usage", pending: map[[2]string]sample{}}
}

func (u *usage) tick(ctx context.Context) {
	tunnels := u.reg.TakeRetired() // closed since the last tick: their final bytes
	for _, n := range u.reg.Names() {
		if t, ok := u.reg.Get(n); ok {
			tunnels = append(tunnels, t)
		}
	}
	for _, t := range tunnels {
		rx, tx := t.Take()
		k := [2]string{t.FleetID, t.NodeID}
		s, ok := u.pending[k]
		if !ok && len(u.pending) >= maxPending {
			log.Printf("share: usage backlog full, dropping %d bytes", rx+tx)
			continue
		}
		s.FleetID, s.NodeID, s.RX, s.TX = t.FleetID, t.NodeID, s.RX+rx, s.TX+tx
		u.pending[k] = s
	}
	if len(u.pending) == 0 {
		return
	}
	body := make([]sample, 0, len(u.pending))
	for _, s := range u.pending {
		body = append(body, s)
	}
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(b))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := do(req)
	if err != nil {
		log.Printf("share: usage: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		log.Printf("share: usage: HTTP %d", resp.StatusCode)
		return
	}
	clear(u.pending)
}

// every runs f every d until ctx ends.
func every(ctx context.Context, d time.Duration, f func(context.Context)) {
	tk := time.NewTicker(d)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			f(ctx)
		}
	}
}
