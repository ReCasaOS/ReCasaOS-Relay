// Package server is the HTTP surface of the enrolment service.
package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

// Config holds the tunables of the service; see ConfigFromEnv for defaults.
type Config struct {
	NodesPerFleet     int
	CreateRatePerHour int // create-fleet requests per hour, per IP
	KeyRatePerHour    int // join-key requests per hour, per fleet
	JoinKeyTTL        time.Duration
	IdleAfter         time.Duration // a fleet idle this long is deleted
	LoginServer       string        // no default: must be set by the operator
}

// Deps carries the collaborators of the handlers (store, Headscale client...), added by later tasks.
type Deps struct{}

// New returns the service's HTTP handler.
func New(cfg Config, deps Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// ConfigFromEnv reads the configuration from the environment; unset or empty variables take the default.
func ConfigFromEnv() (Config, error) {
	var (
		c   Config
		err error
	)
	if c.NodesPerFleet, err = envInt("NODES_PER_FLEET", 50); err != nil {
		return c, err
	}
	if c.CreateRatePerHour, err = envInt("CREATE_RATE_PER_HOUR", 5); err != nil {
		return c, err
	}
	if c.KeyRatePerHour, err = envInt("KEY_RATE_PER_HOUR", 30); err != nil {
		return c, err
	}
	if c.JoinKeyTTL, err = envDuration("JOIN_KEY_TTL", 24*time.Hour); err != nil {
		return c, err
	}
	if c.IdleAfter, err = envDuration("IDLE_AFTER", 720*time.Hour); err != nil {
		return c, err
	}
	c.LoginServer = os.Getenv("LOGIN_SERVER")
	return c, nil
}

func envInt(key string, def int) (int, error) {
	s := os.Getenv(key)
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%s: %q is not a positive integer", key, s)
	}
	return n, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	s := os.Getenv(key)
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: %q is not a positive duration", key, s)
	}
	return d, nil
}
