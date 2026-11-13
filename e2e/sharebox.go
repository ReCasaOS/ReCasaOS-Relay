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
	"encoding/pem"
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
	"golang.org/x/crypto/acme"
)

// fakeBox is a box as the relay sees it: a signing key, a name, a certificate for *.<name>.box.relay.test
// and an HTTPS server answering "hello from <name>" over the tunnel's streams.
type fakeBox struct {
	r       *rig
	name    string
	key     ed25519.PrivateKey
	cert    tls.Certificate                 // the self-signed one it starts with
	cur     atomic.Pointer[tls.Certificate] // what the TLS server presents; obtainCert swaps it
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
	b.cur.Store(&b.cert)

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
	srv := &http.Server{ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/big" { // 20 MiB, for the shared-volume check on /admin
			io.CopyN(w, zeroReader{}, 20<<20)
			return
		}
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
				case ln.conns <- tls.Server(&restConn{Conn: s, r: rest}, &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return b.cur.Load(), nil }}):
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

// setProtection sets the box's relay filter and ban sharing (PUT /v1/share/protection).
func (b *fakeBox) setProtection(filter, share bool) {
	b.r.t.Helper()
	body := fmt.Sprintf(`{"relay_filter":%t,"share_bans":%t}`, filter, share)
	if code, out := b.signed("PUT", "/v1/share/protection", body); code != http.StatusOK {
		b.r.t.Fatalf("protection %s: %d %s", b.name, code, out)
	}
}

// reportBan shares a ban of key, started now (POST /v1/share/bans). A 204 does not mean it was
// kept: a report the relay cannot back with a seen connection is dropped silently.
func (b *fakeBox) reportBan(key, reason string) {
	b.r.t.Helper()
	body := fmt.Sprintf(`{"bans":[{"key":%q,"reason":%q,"app":"web","since":%q}]}`, key, reason, time.Now().UTC().Format(time.RFC3339))
	if code, out := b.signed("POST", "/v1/share/bans", body); code != http.StatusNoContent {
		b.r.t.Fatalf("report %s: %d %s", b.name, code, out)
	}
}

// sources returns the PROXY source addresses received so far.
func (b *fakeBox) sources() []*net.TCPAddr {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*net.TCPAddr(nil), b.srcs...)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

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

// obtainCert gets a certificate for *.<name>.box.relay.test from the ACME server at directoryURL by DNS-01:
// the TXT goes through the relay (PUT /v1/share/acme), then the box serves the new chain.
func (b *fakeBox) obtainCert(ctx context.Context, directoryURL string) error {
	acctKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cl := &acme.Client{Key: acctKey, DirectoryURL: directoryURL, HTTPClient: &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}} // Pebble's directory has a throwaway certificate
	if _, err := cl.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil {
		return fmt.Errorf("register: %w", err)
	}
	domain := "*." + b.name + ".box.relay.test"
	order, err := cl.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return fmt.Errorf("order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		if err := b.solveDNS01(ctx, cl, u); err != nil {
			return err
		}
	}
	if _, err = cl.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("wait order: %w", err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{domain}}, key)
	if err != nil {
		return err
	}
	chain, _, err := cl.CreateCertFromOrder(ctx, order, csr, true) // CreateOrderCert without the order URI cannot poll it
	if err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	b.cur.Store(&tls.Certificate{Certificate: chain, PrivateKey: key})
	return nil
}

// solveDNS01 publishes the DNS-01 record of one authorization through the relay and waits for validation.
func (b *fakeBox) solveDNS01(ctx context.Context, cl *acme.Client, authzURL string) (err error) {
	az, err := cl.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	var chal *acme.Challenge
	for _, c := range az.Challenges {
		if c.Type == "dns-01" {
			chal = c
		}
	}
	if chal == nil {
		return fmt.Errorf("no dns-01 challenge in %v", az.Challenges)
	}
	val, err := cl.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return err
	}
	if code, out := b.signed("PUT", "/v1/share/acme", fmt.Sprintf(`{"value":%q}`, val)); code != http.StatusNoContent {
		return fmt.Errorf("put acme: %d %s", code, out)
	}
	defer func() { // the TXT must not outlive the attempt, whatever happens
		if code, out := b.signed("DELETE", "/v1/share/acme", ""); code != http.StatusNoContent && err == nil {
			err = fmt.Errorf("delete acme: %d %s", code, out)
		}
	}()
	if _, err := cl.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accept: %w", err)
	}
	if _, err := cl.WaitAuthorization(ctx, authzURL); err != nil {
		return fmt.Errorf("wait authorization: %w", err)
	}
	return nil
}

// pebbleRoots fetches the CA Pebble signs with (it changes at each start) from its management port.
func pebbleRoots(mgmtAddr string) (*x509.CertPool, error) {
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := c.Get("https://" + mgmtAddr + "/roots/0")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	pool := x509.NewCertPool()
	if blk, _ := pem.Decode(b); blk == nil || !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("no PEM root in %q", b)
	}
	return pool, nil
}
