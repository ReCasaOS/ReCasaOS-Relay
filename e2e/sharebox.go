//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/auth"
	"github.com/ReCasaOS/recasaos-relay/internal/proxyproto"
	"github.com/ReCasaOS/recasaos-relay/internal/tunnel"
)

// fakeBox is a box as the relay sees it: a signing key, a name, a certificate for *.<name>.box.relay.test
// and an HTTPS server answering "hello from <name>" over the tunnel's streams.
type fakeBox struct {
	r       *rig
	name    string
	key     ed25519.PrivateKey
	cert    tls.Certificate
	sess    *tunnel.Session
	streams atomic.Int32

	mu   sync.Mutex
	srcs []*net.TCPAddr    // PROXY sources, in arrival order
	last map[string]string // method+path -> timestamp of the last signed call
}

// startBox links a fresh key to the fleet's node, claims name and dials the tunnel.
func (r *rig) startBox(fleetID, secret, nodeID, name string) *fakeBox {
	t := r.t
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := &fakeBox{r: r, name: name, key: priv}

	body := fmt.Sprintf(`{"box_key":%q}`, base64.RawURLEncoding.EncodeToString(pub))
	req, _ := http.NewRequest("PUT", r.frontURL+"/v1/fleets/"+fleetID+"/nodes/"+nodeID+"/box-key", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+secret)
	if resp, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("box-key %s: %d", name, resp.StatusCode)
		}
	}
	if code, out := b.signed("PUT", "/v1/share/name", `{"name":"`+name+`"}`); code != http.StatusCreated {
		t.Fatalf("claim %s: %d %s", name, code, out)
	}

	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{"*." + name + ".box.relay.test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &ck.PublicKey, ck)
	if err != nil {
		t.Fatal(err)
	}
	b.cert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: ck}

	pem, _ := os.ReadFile(r.caFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", r.shareAddr)
		},
		TLSClientConfig: &tls.Config{ServerName: "relay.test", RootCAs: pool}}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if b.sess, err = tunnel.Dial(ctx, "https://relay.test", priv, tunnel.DialOptions{HTTPClient: hc}); err != nil {
		t.Fatalf("tunnel %s: %v", name, err)
	}

	ln := &chanListener{conns: make(chan net.Conn), done: make(chan struct{})}
	srv := &http.Server{ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "hello from %s", name)
	})}
	go srv.Serve(ln)
	go func() {
		for {
			s, err := b.sess.Accept()
			if err != nil {
				return
			}
			b.streams.Add(1)
			go func() {
				src, _, rest, err := proxyproto.ReadProxyV2(s)
				if err != nil || src == nil {
					s.Close()
					return
				}
				b.mu.Lock()
				b.srcs = append(b.srcs, src)
				b.mu.Unlock()
				select {
				case ln.conns <- tls.Server(&restConn{Conn: s, r: rest}, &tls.Config{Certificates: []tls.Certificate{b.cert}}):
				case <-ln.done:
					s.Close()
				}
			}()
		}
	}()
	t.Cleanup(func() { b.sess.Close(); srv.Close() }) // streams first: Close waits for the connections
	return b
}

// signed calls the API (plain HTTP to front) as this box; spaced by the caller when repeating a path.
func (b *fakeBox) signed(method, path, body string) (int, string) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	if b.last == nil {
		b.last = map[string]string{}
	}
	if b.last[method+path] == ts { // the same signature twice in a second is a replay: wait for the next one
		time.Sleep(1100 * time.Millisecond)
		ts = strconv.FormatInt(time.Now().Unix(), 10)
	}
	b.last[method+path] = ts
	enc := base64.RawURLEncoding
	req, _ := http.NewRequest(method, b.r.frontURL+path, bytes.NewReader([]byte(body)))
	req.Header.Set("X-Box-Key", enc.EncodeToString(b.key.Public().(ed25519.PublicKey)))
	req.Header.Set("X-Box-Time", ts)
	req.Header.Set("X-Box-Signature", enc.EncodeToString(ed25519.Sign(b.key, []byte(auth.Message(method, path, ts)))))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		b.r.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

// sources returns the PROXY source addresses received so far.
func (b *fakeBox) sources() []*net.TCPAddr {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*net.TCPAddr(nil), b.srcs...)
}

// restConn reads from r (the bytes after the PROXY header) and writes to the stream.
type restConn struct {
	net.Conn
	r io.Reader
}

func (c *restConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type chanListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{} }
