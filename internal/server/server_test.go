package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/policy"
)

func TestHealthz(t *testing.T) {
	h := New(Config{}, Deps{})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz = %d, want 200", rec.Code)
	}
}

func TestConfigFromEnvDefaults(t *testing.T) {
	for _, k := range []string{"NODES_PER_FLEET", "CREATE_RATE_PER_HOUR", "KEY_RATE_PER_HOUR", "AUTH_RATE_PER_HOUR", "JOIN_KEY_TTL", "IDLE_AFTER", "GC_INTERVAL", "TRUSTED_PROXY_HEADER", "MAX_FLEETS", "MAX_PENDING_KEYS", "DEVICE_CODE_TTL", "MAX_PENDING_DEVICE_CODES", "LOGIN_RATE_PER_HOUR"} {
		t.Setenv(k, "")
	}
	t.Setenv("LOGIN_SERVER", "https://relay.example") // required, no default
	got, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		NodesPerFleet:     50,
		CreateRatePerHour: 5,
		KeyRatePerHour:    30,
		AuthRatePerHour:   60,
		JoinKeyTTL:        24 * time.Hour,
		IdleAfter:         720 * time.Hour,
		GCEvery:           10 * time.Minute,
		MaxFleets:         1000,
		MaxPendingKeys:    5,
		LoginServer:       "https://relay.example",
		DeviceCodeTTL:     10 * time.Minute, MaxPendingDeviceCodes: 5, LoginRatePerHour: 20,
	}
	if got != want {
		t.Fatalf("defaults = %+v, want %+v", got, want)
	}
}

func TestConfigFromEnvOverrides(t *testing.T) {
	t.Setenv("NODES_PER_FLEET", "10")
	t.Setenv("CREATE_RATE_PER_HOUR", "2")
	t.Setenv("KEY_RATE_PER_HOUR", "7")
	t.Setenv("AUTH_RATE_PER_HOUR", "9")
	t.Setenv("JOIN_KEY_TTL", "1h")
	t.Setenv("IDLE_AFTER", "48h")
	t.Setenv("GC_INTERVAL", "90s")
	t.Setenv("LOGIN_SERVER", "https://relay.example")
	t.Setenv("TRUSTED_PROXY_HEADER", "X-Forwarded-For")
	t.Setenv("MAX_FLEETS", "3")
	t.Setenv("MAX_PENDING_KEYS", "4")
	got, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := Config{NodesPerFleet: 10, CreateRatePerHour: 2, KeyRatePerHour: 7, AuthRatePerHour: 9, JoinKeyTTL: time.Hour,
		IdleAfter: 48 * time.Hour, GCEvery: 90 * time.Second, LoginServer: "https://relay.example", TrustedProxyHeader: "X-Forwarded-For", MaxFleets: 3, MaxPendingKeys: 4,
		DeviceCodeTTL: 10 * time.Minute, MaxPendingDeviceCodes: 5, LoginRatePerHour: 20}
	if got != want {
		t.Fatalf("overrides = %+v, want %+v", got, want)
	}
}

func TestConfigFromEnvInvalid(t *testing.T) {
	for k, v := range map[string]string{
		"NODES_PER_FLEET":    "abc",
		"KEY_RATE_PER_HOUR":  "0",
		"AUTH_RATE_PER_HOUR": "-5",
		"JOIN_KEY_TTL":       "soon",
		"IDLE_AFTER":         "-1h",
		"GC_INTERVAL":        "0s",
		"MAX_FLEETS":         "0",
		"MAX_PENDING_KEYS":   "-1",
	} {
		t.Run(k, func(t *testing.T) {
			t.Setenv("LOGIN_SERVER", "https://relay.example") // valid: the error must come from k
			t.Setenv(k, v)
			if _, err := ConfigFromEnv(); err == nil {
				t.Fatalf("%s=%q: want error", k, v)
			}
		})
	}
}

// LOGIN_SERVER is handed to every box as its control server: refuse to start without a usable one.
func TestConfigFromEnvLoginServer(t *testing.T) {
	for _, v := range []string{"", "relay.example", "http://relay.example", "https://", "ftp://relay.example", "https://relay.example/path", "https://relay.example?x=1"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("LOGIN_SERVER", v)
			if _, err := ConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "LOGIN_SERVER") {
				t.Fatalf("LOGIN_SERVER=%q: err = %v, want a LOGIN_SERVER error", v, err)
			}
		})
	}
	for _, v := range []string{"https://relay.example", "https://relay.example/", "https://relay.test:8443"} {
		t.Setenv("LOGIN_SERVER", v)
		if _, err := ConfigFromEnv(); err != nil {
			t.Fatalf("LOGIN_SERVER=%q: %v", v, err)
		}
	}
}

// The sizes Headscale has to handle grow with the fleets: its pre-auth key list (listed whole on
// every quota check, each key about 400 B of JSON, measured) and the access policy (pushed whole).
// Both go through Headscale's gRPC layer, which refuses messages over 4 MiB. With the defaults,
// keep both under 3 MiB. The README ("Capacity") states the same numbers.
func TestDefaultsKeepHeadscaleMessagesUnder3MiB(t *testing.T) {
	for _, k := range []string{"MAX_FLEETS", "MAX_PENDING_KEYS", "DEVICE_CODE_TTL", "MAX_PENDING_DEVICE_CODES", "LOGIN_RATE_PER_HOUR"} {
		t.Setenv(k, "")
	}
	t.Setenv("LOGIN_SERVER", "https://relay.example")
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	const keyJSONBytes, limit = 400, 3 << 20
	if keys := c.MaxFleets * c.MaxPendingKeys * keyJSONBytes; keys != 2_000_000 || keys > limit {
		t.Fatalf("worst-case key list %d B (README states 2,000,000 B, limit %d)", keys, limit)
	}
	users := make([]string, c.MaxFleets)
	for i := range users {
		users[i] = fmt.Sprintf("f-%032x", i)
	}
	pol, err := policy.Build(users)
	if err != nil {
		t.Fatal(err)
	}
	if len(pol) > limit {
		t.Fatalf("policy for %d fleets is %d B", c.MaxFleets, len(pol))
	}
	t.Logf("policy for %d fleets: %d B", c.MaxFleets, len(pol))
}
