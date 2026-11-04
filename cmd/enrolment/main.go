// Command enrolment runs the recasaos-relay enrolment service.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/admin"
	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/gc"
	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/meter"
	"github.com/ReCasaOS/recasaos-relay/internal/policy"
	"github.com/ReCasaOS/recasaos-relay/internal/server"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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
	st, err := store.Open(getenv("STORE_PATH", "/data/relay.db"))
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
	// Traffic metering needs the derper's debug key; without it nothing is metered (the key is never logged).
	var mtr *meter.Meter
	if key := os.Getenv("DERPER_DEBUG_KEY"); key != "" {
		mtr = &meter.Meter{Source: meter.NewDerper(getenv("DERPER_URL", "http://derper:8090"), key, nil), Nodes: hs, Store: st}
	} else {
		log.Printf("traffic metering is off: DERPER_DEBUG_KEY is not set")
	}
	// The operator page, under /admin, only when ADMIN_TOKEN is set (404 otherwise).
	var adminH http.Handler
	if tok := os.Getenv("ADMIN_TOKEN"); tok != "" {
		deps := admin.Deps{Store: st, Headscale: hs, Remover: remover}
		if mtr != nil { // never put a nil *Meter in the interface
			deps.Meter = mtr
		}
		adminH, err = admin.New(admin.Config{Token: tok, NodesPerFleet: cfg.NodesPerFleet, MaxFleets: cfg.MaxFleets,
			ClientHeader: cfg.TrustedProxyHeader, MonthlyReference: reference}, deps)
		if err != nil {
			return err
		}
	}
	srv := &http.Server{
		Addr:              getenv("LISTEN_ADDR", ":8081"),
		Handler:           server.New(cfg, server.Deps{Store: st, Headscale: hs, PolicyHook: pol.Hook, Remover: remover, Admin: adminH}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      45 * time.Second, // a create-fleet call may wait on Headscale (20 s) and its rollback
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
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
	waitJanitor := func() {
		if janitorStarted {
			<-janitorDone
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
			if mtr != nil {
				meterStarted = true
				go func() {
					defer close(meterDone)
					mtr.Run(ctx, 15*time.Second)
				}()
			}
			log.Printf("enrolment listening on %s", srv.Addr)
			return srv.ListenAndServe()
		})
	if !errors.Is(err, http.ErrServerClosed) {
		stop() // listen failed: let the goroutines finish instead of leaking
		<-done
		waitJanitor()
		return err
	}
	<-done
	waitJanitor()
	return nil
}

// serveAfterPolicy runs applyPolicy and only then serve; if the policy cannot be applied, serve is
// never called.
func serveAfterPolicy(ctx context.Context, applyPolicy func(context.Context) error, serve func() error) error {
	if err := applyPolicy(ctx); err != nil {
		return fmt.Errorf("applying the access policy (refusing to serve without it): %w", err)
	}
	return serve()
}

// parseBytes reads a byte count with an optional decimal K, M, G or T suffix ("100G", "1.5G"); "" is 0.
func parseBytes(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	mult := 1.0
	if i := strings.IndexByte("KMGT", s[len(s)-1]); i >= 0 {
		mult = [...]float64{1e3, 1e6, 1e9, 1e12}[i]
		s = s[:len(s)-1]
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || !(f >= 0 && f*mult < 9e18) { // negated so NaN fails too; the cap keeps int64 from overflowing
		return 0, fmt.Errorf("invalid byte count %q", s)
	}
	return int64(f * mult), nil
}
