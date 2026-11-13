// Command share sits on the public 80/443 in front of Caddy: it reads the TLS server name of each
// connection and forwards the bytes to Caddy, or into the tunnel the box of that name opened (served on
// ListenTunnel, behind Caddy, at /v1/share/tunnel).
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"

	"github.com/ReCasaOS/recasaos-relay/internal/proxyproto"
	"github.com/ReCasaOS/recasaos-relay/internal/ratelimit"
	"github.com/ReCasaOS/recasaos-relay/internal/sni"
	"github.com/ReCasaOS/recasaos-relay/internal/tunnel"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := ConfigFromEnv()
	if err != nil {
		return err
	}
	lt, err := net.Listen("tcp", cfg.ListenTLS)
	if err != nil {
		return err
	}
	lh, err := net.Listen("tcp", cfg.ListenHTTP)
	if err != nil {
		lt.Close()
		return err
	}
	ltun, err := net.Listen("tcp", cfg.ListenTunnel)
	if err != nil {
		lt.Close()
		lh.Close()
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	reg, resolve := tunnel.NewRegistry(), resolver(cfg.EnrolmentURL)
	mux := http.NewServeMux()
	mux.Handle("GET "+tunnel.Path, tunnel.Handler(reg, resolve, ratelimit.New(cfg.TunnelRatePerHour, time.Now), time.Now))
	tunSrv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	tunErr := make(chan error, 1)
	go func() {
		if err := tunSrv.Serve(ltun); !errors.Is(err, http.ErrServerClosed) {
			log.Printf("share: tunnel listener: %v", err)
			tunErr <- err
			stop() // no tunnels, no share process: shut down and exit with the error
		}
	}()
	go every(ctx, 60*time.Second, func(ctx context.Context) { tunnel.Revalidate(ctx, reg, resolve) })
	fh := &filterHolder{}
	go func() {
		fh.poll(ctx, cfg.EnrolmentURL)
		every(ctx, 30*time.Second, func(ctx context.Context) { fh.poll(ctx, cfg.EnrolmentURL) })
	}()
	go every(ctx, 15*time.Second, newUsage(reg, cfg.EnrolmentURL).tick)
	ev := newEvents()
	go every(ctx, 15*time.Second, func(ctx context.Context) { ev.flush(ctx, cfg.EnrolmentURL+"/internal/share/events") })
	go func() {
		<-ctx.Done()
		lt.Close()
		lh.Close()
		tunSrv.Close() // hijacked tunnels are not closed by it: the boxes are told below
		for _, n := range reg.Names() {
			if t, ok := reg.Get(n); ok {
				go t.Close(websocket.StatusGoingAway, "relay shutting down")
			}
		}
	}()
	log.Printf("share listening on %s (TLS), %s (HTTP) and %s (tunnels)", cfg.ListenTLS, cfg.ListenHTTP, cfg.ListenTunnel)

	// One per-IP count over both ports; a second one bounds what one address takes of a box's tunnel.
	perIP := newConnCap(cfg.ConnsPerIP, "per IP")
	perBox := newConnCap(cfg.ConnsPerIPPerBox, "per IP and box")
	var inflight, acceptors sync.WaitGroup
	acceptors.Add(2)
	go func() {
		defer acceptors.Done()
		accept(lt, &inflight, perIP, ev, func(c net.Conn) { handleTLS(cfg, reg, perBox, fh, ev, c) })
	}()
	go func() {
		defer acceptors.Done()
		accept(lh, &inflight, perIP, ev, func(c net.Conn) { toFront(c, cfg.FrontHTTP, cfg.FrontProxyProtocol) })
	}()
	acceptors.Wait()

	drained := make(chan struct{})
	go func() { inflight.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		log.Printf("shutdown: connections still open after 30s")
	}
	select {
	case err := <-tunErr:
		return err
	default:
		return nil
	}
}

// accept serves l until it is closed. A connection from an address that already holds perIP's max is
// closed at once, before any byte is read.
func accept(l net.Listener, wg *sync.WaitGroup, perIP *connCap, ev *events, handle func(net.Conn)) {
	var delay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// EMFILE, ECONNABORTED...: back off and keep serving, like net/http.Server.Serve.
			if delay == 0 {
				delay = 50 * time.Millisecond
			} else if delay *= 2; delay > time.Second {
				delay = time.Second
			}
			log.Printf("accept: %v; retrying in %v", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		k := ipKey(c.RemoteAddr())
		if !perIP.acquire(k) {
			ev.refused("", connKey(c), "cap", "ip")
			c.Close()
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer perIP.release(k); defer c.Close(); handle(c) }()
	}
}

func handleTLS(cfg Config, reg *tunnel.Registry, perBox *connCap, fh *filterHolder, ev *events, c net.Conn) {
	name, replay, err := sni.PeekServerName(c, cfg.PeekTimeout)
	if err != nil && !errors.Is(err, sni.ErrNotTLS) {
		return
	}
	box, front := route(name, cfg.RelayHost, cfg.ShareDomain)
	switch {
	case front: // non-TLS bytes (err == ErrNotTLS) go to front as well
		toFront(replay, cfg.FrontTLS, cfg.FrontProxyProtocol)
	case box != "":
		// Only share names are filtered: the relay host (enrolment, Headscale, /admin) must stay
		// reachable from any country. A refused visitor gets a plain close.
		if f := fh.get(); f != nil {
			if a, ok := remoteAddr(c); ok {
				if reason, source := f.decide(a, box); reason != "" {
					ev.refused(box, eventKey(a), reason, source)
					return
				}
			}
		}
		toTunnel(reg, perBox, ev, box, c, replay)
	}
}

// toFront forwards c to Caddy at addr. With proxy, a PROXY v2 header carrying the visitor's address
// goes first, before any (replayed) byte, so Caddy's {client_ip} is the visitor.
func toFront(c net.Conn, addr string, proxy bool) {
	f, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Printf("share: dial %s: %v", addr, err)
		return
	}
	defer f.Close()
	if proxy {
		src, ok1 := c.RemoteAddr().(*net.TCPAddr)
		dst, ok2 := c.LocalAddr().(*net.TCPAddr)
		if !ok1 || !ok2 {
			log.Printf("share: PROXY header: %v -> %v are not TCP addresses", c.RemoteAddr(), c.LocalAddr())
			return
		}
		if err := proxyproto.WriteV2(f, src, dst); err != nil {
			log.Printf("share: PROXY header to %s: %v", addr, err)
			return
		}
	}
	sni.Forward(c, f)
}

// route decides where a TLS connection for the server name goes: to Caddy (toFront), to a box's tunnel
// (box, for exactly <label>.<box>.<shareDomain>), or nowhere (both zero: the connection is closed).
func route(name, _, shareDomain string) (box string, toFront bool) {
	name = strings.ToLower(name)
	rest, ok := strings.CutSuffix(name, "."+shareDomain)
	if name == "" || !ok {
		return "", true
	}
	label, b, ok := strings.Cut(rest, ".")
	if !ok || label == "" || b == "" || strings.Contains(b, ".") {
		return "", false
	}
	return b, false
}
