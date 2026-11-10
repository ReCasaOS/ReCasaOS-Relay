// Package server is the HTTP surface of the enrolment service.
package server

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/fleets"
	"github.com/ReCasaOS/recasaos-relay/internal/headscale"
	"github.com/ReCasaOS/recasaos-relay/internal/ratelimit"
	"github.com/ReCasaOS/recasaos-relay/internal/sharename"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

// Config holds the tunables of the service; see ConfigFromEnv for defaults.
type Config struct {
	NodesPerFleet int
	MaxFleets     int // fleets the relay holds at most; creation answers 503 beyond
	// MaxFleetsPerOrigin: fleets one network holds at once, a network being what the creation rate
	// counts (an IPv4 address, an IPv6 /64); MaxFleetsPerPrefix48: the same for an IPv6 /48, across
	// its /64s. Creation answers 429 beyond. The rate bounds how fast a network creates, these how
	// many it keeps: without them one network takes every place of MaxFleets. Zero: no such limit.
	MaxFleetsPerOrigin   int
	MaxFleetsPerPrefix48 int
	MaxDevicesPerFleet   int // phones and PCs a fleet holds; a device code is refused (409) beyond. Zero: no limit
	MaxPendingKeys       int // unused, unexpired join keys a fleet may hold at once (409 beyond)
	CreateRatePerHour    int // create-fleet requests per hour, per IP
	KeyRatePerHour       int // join-key requests per hour, per fleet (counted once the secret is verified)
	AuthRatePerHour      int // fleet requests (join key, status, deletions) per hour, per IP, counted before the secret is checked
	JoinKeyTTL           time.Duration
	IdleAfter            time.Duration // a fleet idle this long is deleted
	GCEvery              time.Duration // interval of the idle-fleet janitor
	LoginServer          string        // required: an https URL with no path, see loginServer
	// TrustedProxyHeader names the header (e.g. X-Forwarded-For) in which a trusted reverse proxy
	// appends the client address; its LAST value is then the client IP. Empty: use the TCP peer.
	TrustedProxyHeader    string
	DeviceCodeTTL         time.Duration // validity of a device code
	MaxPendingDeviceCodes int           // unused device codes a fleet may hold (409 beyond)
	LoginRatePerHour      int           // device-code logins per hour, per IP

	ShareDomain          string        // public sharing: boxes get <name>.<ShareDomain>; empty disables every share route (503)
	ShareACMETTL         time.Duration // validity of an _acme-challenge TXT value
	ShareACMERatePerHour int           // ACME TXT writes per hour, per box
}

// prefix48Factor: an IPv6 /48 may create this many times CREATE_RATE_PER_HOUR fleets per hour in
// all, across its /64s (IPv4: the same address, so the per-address limit is the one that binds).
const prefix48Factor = 10

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
	// Admin, when not nil, is served under /admin/ (and /admin redirects to it).
	Admin http.Handler
	Now   func() time.Time // default time.Now
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
			limiter:   ratelimit.New(cfg.CreateRatePerHour, deps.Now),
			limiter48: ratelimit.New(prefix48Factor*cfg.CreateRatePerHour, deps.Now),
			// open when full: it stands before a secret that cannot be guessed, and refusing every
			// client it does not know would cut the boxes off from their own fleets
			authLimiter: ratelimit.New(cfg.AuthRatePerHour, deps.Now).OpenWhenFull(),
			keyLimiter:  ratelimit.New(cfg.KeyRatePerHour, deps.Now),
			locks:       deps.Remover.Locks,
		}
		mux.HandleFunc("POST /v1/fleets", h.createFleet)
		mux.HandleFunc("POST /v1/fleets/{id}/keys", h.createKey)
		mux.HandleFunc("POST /v1/fleets/{id}/device-codes", h.createDeviceCode)
		mux.HandleFunc("GET /v1/fleets/{id}/devices", h.listDevices)
		mux.HandleFunc("DELETE /v1/fleets/{id}/devices/{node}", h.removeDevice)
		mux.HandleFunc("GET /v1/fleets/{id}", h.fleetStatus)
		mux.HandleFunc("DELETE /v1/fleets/{id}/nodes/{hostname}", h.removeNode)
		mux.HandleFunc("DELETE /v1/fleets/{id}", h.deleteFleet)
		mux.HandleFunc("PUT /v1/fleets/{id}/nodes/{node}/box-key", cfg.shareEnabled(h.setBoxKey))
		beats := &heartbeats{}
		sh := &shareHandler{cfg: cfg, deps: deps, beats: beats,
			authLimiter: ratelimit.New(cfg.AuthRatePerHour, deps.Now).OpenWhenFull(), // before a signature: as for the fleets
			acmeLimiter: ratelimit.New(cfg.ShareACMERatePerHour, deps.Now),
		}
		mux.HandleFunc("PUT /v1/share/name", cfg.shareEnabled(sh.putName))
		mux.HandleFunc("DELETE /v1/share/name", cfg.shareEnabled(sh.deleteName))
		mux.HandleFunc("GET /v1/share", cfg.shareEnabled(sh.status))
		mux.HandleFunc("PUT /v1/share/acme", cfg.shareEnabled(sh.putACME))
		mux.HandleFunc("DELETE /v1/share/acme", cfg.shareEnabled(sh.deleteACME))
		if cfg.ShareDomain != "" { // like the /v1/share routes, absent (404) while sharing is off
			in := &internalHandler{deps: deps, beats: beats}
			mux.Handle("GET /internal/share/boxes/{key}", internalOnly(cfg.TrustedProxyHeader, in.boxByKey))
			mux.Handle("POST /internal/share/usage", internalOnly(cfg.TrustedProxyHeader, in.usage))
		}
		login := &loginHandler{cfg: cfg, deps: deps,
			limiter:   ratelimit.New(cfg.LoginRatePerHour, deps.Now),
			limiter48: ratelimit.New(prefix48Factor*cfg.LoginRatePerHour, deps.Now),
		}
		mux.HandleFunc("GET /register/{authID}", login.form)
		mux.HandleFunc("POST /register/{authID}", login.approve)
	}
	if deps.Admin != nil {
		mux.Handle("/admin/", deps.Admin)
		mux.Handle("/admin", http.RedirectHandler("/admin/", http.StatusMovedPermanently))
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
	if c.MaxFleets, err = envInt("MAX_FLEETS", 1000); err != nil {
		return c, err
	}
	if c.MaxPendingKeys, err = envInt("MAX_PENDING_KEYS", 5); err != nil {
		return c, err
	}
	if c.MaxFleetsPerOrigin, err = envInt("MAX_FLEETS_PER_ORIGIN", 10); err != nil {
		return c, err
	}
	if c.MaxFleetsPerPrefix48, err = envInt("MAX_FLEETS_PER_PREFIX48", 30); err != nil {
		return c, err
	}
	if c.MaxDevicesPerFleet, err = envInt("MAX_DEVICES_PER_FLEET", 50); err != nil {
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
	if c.LoginServer, err = loginServer(os.Getenv("LOGIN_SERVER")); err != nil {
		return c, err
	}
	c.TrustedProxyHeader = os.Getenv("TRUSTED_PROXY_HEADER")
	if c.DeviceCodeTTL, err = envDuration("DEVICE_CODE_TTL", 10*time.Minute); err != nil {
		return c, err
	}
	if c.MaxPendingDeviceCodes, err = envInt("MAX_PENDING_DEVICE_CODES", 5); err != nil {
		return c, err
	}
	if c.LoginRatePerHour, err = envInt("LOGIN_RATE_PER_HOUR", 20); err != nil {
		return c, err
	}
	c.ShareDomain = strings.ToLower(strings.TrimSpace(os.Getenv("SHARE_DOMAIN")))
	if c.ShareDomain != "" && sharename.ValidHost(c.ShareDomain) != nil {
		return c, fmt.Errorf("SHARE_DOMAIN: %q is not a bare DNS name (no scheme, port or trailing dot)", c.ShareDomain)
	}
	if c.ShareACMETTL, err = envDuration("SHARE_ACME_TTL", 10*time.Minute); err != nil {
		return c, err
	}
	if c.ShareACMERatePerHour, err = envInt("SHARE_ACME_RATE_PER_HOUR", 20); err != nil {
		return c, err
	}
	return c, nil
}

// loginServer checks the URL handed to every box as its control server: https (the tailscale client
// insists on TLS, e2e included), a host, nothing after it but an optional "/".
func loginServer(s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("LOGIN_SERVER: %q is not an https URL without a path (required: the public URL of this relay, the same as Headscale's server_url)", s)
	}
	return s, nil
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
