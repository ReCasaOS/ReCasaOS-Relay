// Package sni reads the TLS server name of a connection without terminating TLS, and forwards bytes.
package sni

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"
)

// ErrNotTLS: the first byte is not a TLS handshake record.
var ErrNotTLS = errors.New("sni: not a TLS handshake")

var errPeeked = errors.New("sni: peeked")

// recorder remembers every byte the TLS server reads and swallows what it writes (its alert).
type recorder struct {
	net.Conn
	r   io.Reader
	buf bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.buf.Write(p[:n])
	return n, err
}

func (r *recorder) Write(p []byte) (int, error) { return len(p), nil }

// replayConn yields the buffered bytes first, then the live conn.
type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *replayConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// PeekServerName reads the ClientHello of c and returns its SNI ("" if absent). replay yields the bytes
// read, then the rest of c; it is non-nil even on error so a caller can still hand the connection on.
// The timeout covers the whole peek.
func PeekServerName(c net.Conn, timeout time.Duration) (name string, replay net.Conn, err error) {
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", c, err
	}
	first := make([]byte, 1)
	if _, err := io.ReadFull(c, first); err != nil {
		return "", c, err
	}
	rec := &recorder{Conn: c, r: io.MultiReader(bytes.NewReader(first), c)}
	build := func() net.Conn {
		_ = c.SetDeadline(time.Time{})
		return &replayConn{Conn: c, r: io.MultiReader(bytes.NewReader(rec.buf.Bytes()), c)}
	}
	if first[0] != 0x16 { // TLS handshake record
		rec.buf.Write(first)
		return "", build(), ErrNotTLS
	}
	got := false
	srv := tls.Server(rec, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		name, got = h.ServerName, true
		return nil, errPeeked
	}})
	err = srv.Handshake()
	if !got {
		return "", build(), err
	}
	return name, build(), nil
}
