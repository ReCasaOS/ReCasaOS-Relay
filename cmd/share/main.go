// Command share sits on the public 80/443 in front of Caddy: it reads the TLS server name of each
// connection and forwards the bytes to Caddy, or (later) into a tunnel a box opened.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/sni"
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); lt.Close(); lh.Close() }()
	log.Printf("share listening on %s (TLS) and %s (HTTP)", cfg.ListenTLS, cfg.ListenHTTP)

	var inflight, acceptors sync.WaitGroup
	acceptors.Add(2)
	go func() { defer acceptors.Done(); accept(lt, &inflight, func(c net.Conn) { handleTLS(cfg, c) }) }()
	go func() {
		defer acceptors.Done()
		accept(lh, &inflight, func(c net.Conn) { toFront(c, cfg.FrontHTTP) })
	}()
	acceptors.Wait()

	drained := make(chan struct{})
	go func() { inflight.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		log.Printf("shutdown: connections still open after 30s")
	}
	return nil
}

// accept serves l until it is closed.
func accept(l net.Listener, wg *sync.WaitGroup, handle func(net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("accept: %v", err)
			}
			return
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer c.Close(); handle(c) }()
	}
}

func handleTLS(cfg Config, c net.Conn) {
	name, replay, err := sni.PeekServerName(c, cfg.PeekTimeout)
	if err != nil && !errors.Is(err, sni.ErrNotTLS) {
		return
	}
	box, front := route(name, cfg.RelayHost, cfg.ShareDomain)
	switch {
	case front: // non-TLS bytes (err == ErrNotTLS) go to front as well
		toFront(replay, cfg.FrontTLS)
	case box != "":
		log.Printf("share: no tunnel for %s", box) // tunnels come with the tunnel listener
	}
}

func toFront(c net.Conn, addr string) {
	f, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Printf("share: dial %s: %v", addr, err)
		return
	}
	defer f.Close()
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
