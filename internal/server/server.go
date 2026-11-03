// Package server is the HTTP surface of the enrolment service.
package server

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/ratelimit"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// Config holds the tunables of the service; see ConfigFromEnv for defaults.
type Config struct {
	NodesPerFleet     int
	CreateRatePerHour int // create-fleet requests per hour, per IP
	KeyRatePerHour    int // join-key requests per hour, per fleet (counted once the secret is verified)
	AuthRatePerHour   int // fleet requests (join key, status) per hour, per IP, counted before the secret is checked
	JoinKeyTTL        time.Duration
	IdleAfter         time.Duration // a fleet idle this long is deleted
	GCEvery           time.Duration // interval of the idle-fleet janitor
	LoginServer       string        // no default: must be set by the operator
	// TrustedProxyHeader names the header (e.g. X-Forwarded-For) in which a trusted reverse proxy
	// appends the client address; its LAST value is then the client IP. Empty: use the TCP peer.
	TrustedProxyHeader string
}

// Deps carries the collaborators of the handlers. Store and Headscale are required for /v1/fleets.
type Deps struct {
	Store     store.Store
	Headscale headscale.API
	// PolicyHook is called with the Headscale users involved after a fleet is created and must
	// make the access policy cover them; an error rolls the creation back. Nil: no-op.
	PolicyHook func(users []string) error
	// Remover deletes fleets and owns the per-fleet locks; share it with the janitor so both take
	// the same locks. Nil: one is built from Store and Headscale (no policy sync, private locks).
	Remover *fleets.Remover
	Now     func() time.Time // default time.Now
}

// New returns the service's HTTP handler.
func New(cfg Config, deps Deps) http.Handler {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	mux := http.NewServeMux()
	if deps.Store != nil && deps.Headscale != nil {
		if deps.Remover == nil {
			deps.Remover = &fleets.Remover{Store: deps.Store, Headscale: deps.Headscale}
		}
		if deps.Remover.Locks == nil {
			deps.Remover.Locks = &fleets.Locks{}
		}
		h := &fleetsHandler{
			cfg: cfg, deps: deps,
			limiter:     ratelimit.New(cfg.CreateRatePerHour, deps.Now),
			authLimiter: ratelimit.New(cfg.AuthRatePerHour, deps.Now),
			keyLimiter:  ratelimit.New(cfg.KeyRatePerHour, deps.Now),
			locks:       deps.Remover.Locks,
		}
		mux.HandleFunc("POST /v1/fleets", h.createFleet)
		mux.HandleFunc("POST /v1/fleets/{id}/keys", h.createKey)
		mux.HandleFunc("GET /v1/fleets/{id}", h.fleetStatus)
		mux.HandleFunc("DELETE /v1/fleets/{id}/nodes/{hostname}", h.removeNode)
		mux.HandleFunc("DELETE /v1/fleets/{id}", h.deleteFleet)
	}
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
	if c.AuthRatePerHour, err = envInt("AUTH_RATE_PER_HOUR", 60); err != nil {
		return c, err
	}
	if c.JoinKeyTTL, err = envDuration("JOIN_KEY_TTL", 24*time.Hour); err != nil {
		return c, err
	}
	if c.IdleAfter, err = envDuration("IDLE_AFTER", 720*time.Hour); err != nil {
		return c, err
	}
	if c.GCEvery, err = envDuration("GC_INTERVAL", 10*time.Minute); err != nil {
		return c, err
	}
	c.LoginServer = os.Getenv("LOGIN_SERVER")
	c.TrustedProxyHeader = os.Getenv("TRUSTED_PROXY_HEADER")
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
