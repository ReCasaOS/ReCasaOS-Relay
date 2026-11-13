// Command enrolment runs the recasaos-relay enrolment service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/admin"
	"github.com/ReCasaOS/recasaos-relay/internal/dnszone"
	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/gc"
	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/meter"
	"github.com/ReCasaOS/recasaos-relay/internal/policy"
	"github.com/ReCasaOS/recasaos-relay/internal/server"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// version is set at build time (-ldflags "-X main.version=v1.2.3"); the admin page shows it.
var version = "dev"

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envPositive reads a positive integer, def when unset.
func envPositive(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s: a positive integer", key)
	}
	return n, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := server.ConfigFromEnv()
	if err != nil {
		return err
	}
	apiKey := os.Getenv("HEADSCALE_API_KEY")
	if apiKey == "" {
		return errors.New("HEADSCALE_API_KEY is required (docker compose exec headscale headscale apikeys create)")
	}
	storePath := getenv("STORE_PATH", "/data/relay.db")
	st, err := store.Open(storePath)
	if err != nil {
		return err
	}
	defer st.Close()

	hs := headscale.New(getenv("HEADSCALE_URL", "http://headscale:8080"), apiKey, nil)
	pol := policy.NewWriter(st, hs)
	// One remover (and so one set of per-fleet locks) for the HTTP handlers and the janitor.
	remover := &fleets.Remover{Store: st, Headscale: hs, Policy: pol, Locks: &fleets.Locks{}}
	reference, err := parseBytes(os.Getenv("MONTHLY_TRAFFIC_REFERENCE"))
	if err != nil {
		return fmt.Errorf("MONTHLY_TRAFFIC_REFERENCE: %w", err)
	}
	connsPerIP, err := envPositive("CONNS_PER_IP", 256)
	if err != nil {
		return err
	}
	connsPerBox, err := envPositive("CONNS_PER_IP_PER_BOX", 64)
	if err != nil {
		return err
	}
	// Traffic metering needs the derper's debug key; without it nothing is metered (the key is never logged).
	var mtr *meter.Meter
	if key := os.Getenv("DERPER_DEBUG_KEY"); key != "" {
		mtr = &meter.Meter{Source: meter.NewDerper(getenv("DERPER_URL", "http://derper:8090"), key, nil), Nodes: hs, Store: st}
	} else {
		log.Printf("traffic metering is off: DERPER_DEBUG_KEY is not set")
	}
	// Relay-side protection of shared apps, only with sharing: the filter routes `share` polls exist
	// only then, and without them nothing would use the feeds or DB-IP.
	var prot *protection
	srvDeps := server.Deps{Store: st, Headscale: hs, PolicyHook: pol.Hook, Remover: remover}
	if cfg.ShareDomain != "" {
		prot = newProtection(st, storePath, cfg.FilterMaxEntries, cfg.CommunityMinFleetAge)
		srvDeps.Protect, srvDeps.Community = prot.compiler, prot.engine
	}
	// The operator page, under /admin, only when ADMIN_TOKEN is set (404 otherwise).
	var adminH http.Handler
	if tok := os.Getenv("ADMIN_TOKEN"); tok != "" {
		deps := admin.Deps{Store: st, Headscale: hs, Remover: remover}
		if mtr != nil { // never put a nil *Meter in the interface
			deps.Meter = mtr
		}
		if prot != nil {
			deps.Feeds, deps.Geo, deps.Protect = prot.feeds, prot.geo, prot.compiler
		}
		adminH, err = admin.New(admin.Config{Token: tok, NodesPerFleet: cfg.NodesPerFleet, MaxFleets: cfg.MaxFleets,
			ClientHeader: cfg.TrustedProxyHeader, MonthlyReference: reference, Version: version,
			ConnsPerIP: connsPerIP, ConnsPerIPPerBox: connsPerBox}, deps)
		if err != nil {
			return err
		}
	}
	srvDeps.Admin = adminH
	srv := &http.Server{
		Addr:              getenv("LISTEN_ADDR", ":8081"),
		Handler:           server.New(cfg, srvDeps),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      45 * time.Second, // a create-fleet call may wait on Headscale (20 s) and its rollback
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	// The delegated zone box.<SHARE_DOMAIN>, only when sharing is on; bound now so a bad address or a
	// busy port stops the start instead of failing later.
	var zone *dnszone.Zone
	var dnsPC net.PacketConn
	var dnsL net.Listener
	if cfg.ShareDomain != "" { // validated by ConfigFromEnv
		zone, dnsPC, dnsL, err = listenZone(cfg.ShareDomain, st)
		if err != nil {
			return err
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// ListenAndServe returns as soon as Shutdown starts, not when in-flight handlers finish: wait for
	// Shutdown itself before the deferred store.Close runs.
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()
	// The janitor starts with the server, after the policy is in place, and Run returns only once its
	// tick in flight has: the store must not be closed under it.
	janitorStarted, janitorDone := false, make(chan struct{})
	meterStarted, meterDone := false, make(chan struct{})
	zoneStarted, zoneDone := false, make(chan struct{})
	protectStarted, protectDone := false, make(chan struct{})
	var zoneErr error // written by the zone goroutine, read after zoneDone is closed
	waitJanitor := func() {
		if zone != nil {
			<-zoneDone
		}
		if janitorStarted {
			<-janitorDone
		}
		if protectStarted {
			<-protectDone
		}
		if mtr != nil && meterStarted {
			<-meterDone
		}
	}
	// Headscale allows everything until it has a policy: apply the deny-by-default one first, and
	// refuse to start (exit non-zero) if that cannot be done.
	err = serveAfterPolicy(ctx, func(ctx context.Context) error { return pol.SyncWithRetry(ctx, 8, time.Second) },
		func() error {
			janitorStarted = true
			go func() {
				defer close(janitorDone)
				gc.Run(ctx, gc.Deps{Remover: remover, IdleAfter: cfg.IdleAfter, JoinKeyTTL: cfg.JoinKeyTTL}, cfg.GCEvery)
			}()
			if prot != nil {
				protectStarted = true
				go func() {
					defer close(protectDone)
					prot.run(ctx, time.Minute)
				}()
			}
			if mtr != nil {
				meterStarted = true
				go func() {
					defer close(meterDone)
					mtr.Run(ctx, 15*time.Second)
				}()
			}
			if zone != nil {
				zoneStarted = true
				go func() {
					defer close(zoneDone)
					if err := zone.Serve(ctx, dnsPC, dnsL); err != nil {
						zoneErr = err
						log.Printf("dns: %v", err)
						stop() // shuts the HTTP server down too
					}
				}()
				log.Printf("dns zone %s listening on %s", zone.Origin, dnsPC.LocalAddr())
			}
			log.Printf("enrolment listening on %s", srv.Addr)
			return srv.ListenAndServe()
		})
	if !errors.Is(err, http.ErrServerClosed) {
		if zone != nil && !zoneStarted { // the policy failed first: release the sockets
			dnsPC.Close()
			dnsL.Close()
			close(zoneDone)
		}
		stop() // listen failed: let the goroutines finish instead of leaking
		<-done
		waitJanitor()
		return err
	}
	<-done
	waitJanitor()
	return zoneErr // non-nil only if the DNS server died and took the process down
}

// listenZone builds the zone for domain (SHARE_DOMAIN is the delegated zone itself, e.g. box.recasaos.org; the TXT answers come from the store) and binds UDP and TCP
// on LISTEN_DNS (default :53). SHARE_PUBLIC_IP is required, SHARE_PUBLIC_IP6 optional.
func listenZone(domain string, st store.Store) (*dnszone.Zone, net.PacketConn, net.Listener, error) {
	ip4, err := netip.ParseAddr(os.Getenv("SHARE_PUBLIC_IP"))
	if err != nil || !ip4.Is4() {
		return nil, nil, nil, errors.New("SHARE_PUBLIC_IP is required with SHARE_DOMAIN (the relay's public IPv4)")
	}
	var ip6 netip.Addr
	if v := os.Getenv("SHARE_PUBLIC_IP6"); v != "" {
		if ip6, err = netip.ParseAddr(v); err != nil || !ip6.Is6() || ip6.Is4In6() {
			return nil, nil, nil, fmt.Errorf("SHARE_PUBLIC_IP6: %q is not an IPv6 address", v)
		}
	}
	psl := strings.TrimSpace(os.Getenv("SHARE_PSL_TXT"))
	if len(psl) > 255 { // one TXT character-string
		return nil, nil, nil, fmt.Errorf("SHARE_PSL_TXT: %d bytes, at most 255", len(psl))
	}
	addr := getenv("LISTEN_DNS", ":53")
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, nil, nil, err
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		return nil, nil, nil, err
	}
	z := &dnszone.Zone{Origin: strings.ToLower(strings.TrimSpace(domain)), A: ip4, AAAA: ip6, PSLTXT: psl,
		TXT: func(ctx context.Context, n string) (string, bool, error) { return st.ACMEValue(ctx, n, time.Now()) }}
	return z, pc, l, nil
}

// serveAfterPolicy runs applyPolicy and only then serve; if the policy cannot be applied, serve is
// never called.
func serveAfterPolicy(ctx context.Context, applyPolicy func(context.Context) error, serve func() error) error {
	if err := applyPolicy(ctx); err != nil {
		return fmt.Errorf("applying the access policy (refusing to serve without it): %w", err)
	}
	return serve()
}

// parseBytes reads a byte count with an optional decimal K, M, G or T suffix, any case, and an optional
// trailing B ("100G", "1.5 GB", "2t"); blank is 0.
func parseBytes(in string) (int64, error) {
	s := strings.TrimSpace(in)
	if s == "" {
		return 0, nil
	}
	if n := len(s); s[n-1] == 'B' || s[n-1] == 'b' {
		s = s[:n-1]
	}
	mult := 1.0
	if n := len(s); n > 0 {
		if i := strings.Index("KMGT", strings.ToUpper(s[n-1:])); i >= 0 {
			mult = [...]float64{1e3, 1e6, 1e9, 1e12}[i]
			s = s[:n-1]
		}
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || !(f >= 0 && f*mult < 9e18) { // negated so NaN fails too; the cap keeps int64 from overflowing
		return 0, fmt.Errorf("invalid byte count %q", in)
	}
	return int64(math.Round(f * mult)), nil
}
