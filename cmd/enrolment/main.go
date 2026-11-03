// Command enrolment runs the recasaos-relay enrolment service.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
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
	srv := &http.Server{
		Addr:              getenv("LISTEN_ADDR", ":8081"),
		Handler:           server.New(cfg, server.Deps{Store: st, Headscale: hs}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      45 * time.Second, // a create-fleet call may wait on Headscale (20 s) and its rollback
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Printf("enrolment listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
