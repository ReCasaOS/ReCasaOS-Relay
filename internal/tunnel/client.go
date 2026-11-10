package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/auth"
	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
)

// DialOptions tunes Dial. HTTPClient (e.g. with a pinned CA) must not set a Timeout: use ctx.
// Now defaults to time.Now; it dates the signature.
type DialOptions struct {
	HTTPClient *http.Client
	Now        func() time.Time
}

// DialError is a refused upgrade: StatusCode is the relay's HTTP answer (0 when there was none),
// 403 meaning the box has no name, 503 that the relay could not check it.
type DialError struct {
	StatusCode int
	Err        error
}

func (e *DialError) Error() string {
	return fmt.Sprintf("tunnel: dial: HTTP %d: %v", e.StatusCode, e.Err)
}
func (e *DialError) Unwrap() error { return e.Err }

// Session is the box side of a tunnel: Accept yields one stream per visitor connection, each starting
// with a PROXY v2 header (proxyproto.ReadProxyV2).
type Session struct {
	sess *yamux.Session
	conn *recordConn
}

// Dial opens a tunnel to relayURL (e.g. https://relay.example.org), signing the upgrade with key.
func Dial(ctx context.Context, relayURL string, key ed25519.PrivateKey, opts DialOptions) (*Session, error) {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	ts := strconv.FormatInt(now().Unix(), 10)
	enc := base64.RawURLEncoding
	h := http.Header{}
	h.Set("X-Box-Key", enc.EncodeToString(key.Public().(ed25519.PublicKey)))
	h.Set("X-Box-Time", ts)
	h.Set("X-Box-Signature", enc.EncodeToString(ed25519.Sign(key, []byte(auth.Message(http.MethodGet, Path, ts)))))

	ws, resp, err := websocket.Dial(ctx, strings.TrimSuffix(relayURL, "/")+Path,
		&websocket.DialOptions{HTTPClient: opts.HTTPClient, HTTPHeader: h})
	if err != nil {
		de := &DialError{Err: err}
		if resp != nil {
			de.StatusCode = resp.StatusCode
		}
		return nil, de
	}
	// Not ctx: it only bounds the dial, the tunnel lives until closed.
	rc := &recordConn{Conn: websocket.NetConn(context.Background(), ws, websocket.MessageBinary)}
	sess, err := yamux.Server(rc, yamuxConfig())
	if err != nil {
		ws.CloseNow()
		return nil, err
	}
	return &Session{sess: sess, conn: rc}, nil
}

// Accept waits for the next stream; it fails once the tunnel is closed (see CloseStatus).
func (s *Session) Accept() (net.Conn, error) { return s.sess.Accept() }

// Close closes the tunnel and its streams.
func (s *Session) Close() error { return s.sess.Close() }

// CloseStatus is the close code the relay sent (4403 revoked, 4409 replaced), or -1: none (yet), or a
// network failure, or a normal closure.
func (s *Session) CloseStatus() websocket.StatusCode {
	s.conn.mu.Lock()
	defer s.conn.mu.Unlock()
	return websocket.CloseStatus(s.conn.err)
}

// recordConn keeps the first read error: yamux swallows it, and it carries the relay's close code.
type recordConn struct {
	net.Conn
	mu  sync.Mutex
	err error
}

func (c *recordConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.mu.Lock()
		if c.err == nil {
			c.err = err
		}
		c.mu.Unlock()
	}
	return n, err
}
