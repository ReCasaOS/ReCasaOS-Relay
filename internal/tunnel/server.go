package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/auth"
	"github.com/ReCasaOS/recasaos-relay/internal/ratelimit"
	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// Path is the route a box dials.
const Path = "/v1/share/tunnel"

// ErrNotFound: enrolment does not know the key, or the box has no name. Any other resolve error is a
// transport failure.
var ErrNotFound = errors.New("tunnel: box not found")

// Box is what enrolment knows of a box key.
type Box struct{ Name, NodeID, FleetID string }

// Resolver looks up a box key (the X-Box-Key spelling) at enrolment.
type Resolver func(ctx context.Context, key string) (Box, error)

func yamuxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.LogOutput = io.Discard // its errors are the session closing, which the callers already see
	return c
}

// Handler serves GET Path: it rate-limits the client, verifies the box signature, resolves the key,
// upgrades to a WebSocket and registers the tunnel until the box goes away. Failures before the
// upgrade are plain HTTP statuses (401, 403, 429, 503): the contract's 4401/4403 close codes only
// exist once the WebSocket is up. limit counts every request before the signature check (keys are
// free to mint), keyed by clientKey.
func Handler(reg *Registry, resolve Resolver, limit *ratelimit.Limiter, now func() time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, retry := limit.Allow(clientKey(r)); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(max(int((retry+time.Second-1)/time.Second), 1)))
			httpError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		pub, err := auth.VerifyBox(r, now())
		if err != nil {
			httpError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		key := base64.RawURLEncoding.EncodeToString(pub)
		box, err := resolve(r.Context(), key)
		if errors.Is(err, ErrNotFound) || (err == nil && box.Name == "") { // never register under ""
			httpError(w, http.StatusForbidden, "box not shared")
			return
		}
		if err != nil {
			log.Printf("tunnel: resolve: %v", err)
			httpError(w, http.StatusServiceUnavailable, "enrolment unavailable")
			return
		}

		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true}) // boxes are not browsers
		if err != nil {
			return
		}
		// The relay opens the streams, so it is the yamux client.
		sess, err := yamux.Client(websocket.NetConn(context.Background(), ws, websocket.MessageBinary), yamuxConfig())
		if err != nil {
			ws.CloseNow()
			return
		}
		// Only the relay opens streams. A box that opens one breaks the protocol: end the tunnel. (Closing
		// just the stream is not enough: yamux still buffers a 256 KiB window into a half-closed stream
		// for StreamCloseTimeout, and an accept loop lifts the AcceptBacklog cap on their number.)
		go func() {
			if _, err := sess.Accept(); err == nil {
				log.Printf("tunnel: %q opened a stream: closing it", box.Name)
				sess.Close()
			}
		}()
		t := newTunnel(box, key, ws, sess)
		if old := reg.Put(box.Name, t); old != nil {
			old.Close(StatusReplaced, "replaced")
		}
		log.Printf("tunnel: %q up", box.Name)
		<-sess.CloseChan()
		reg.retire(t) // before Remove: whoever no longer sees it registered finds it retired
		reg.Remove(box.Name, t)
		ws.CloseNow()
		log.Printf("tunnel: %q down", box.Name)
	})
}

// clientKey is the visitor's address: X-Client-IP, which front sets (header_up replaces a client's
// value), else the TCP peer; an IPv6 address counts as its /64, as the enrolment limits do.
func clientKey(r *http.Request) string {
	s := r.Header.Get("X-Client-IP")
	if s == "" {
		s, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "unknown"
	}
	if a = a.Unmap().WithZone(""); a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
