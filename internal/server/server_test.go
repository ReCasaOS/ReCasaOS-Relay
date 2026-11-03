package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	for _, k := range []string{"NODES_PER_FLEET", "CREATE_RATE_PER_HOUR", "KEY_RATE_PER_HOUR", "AUTH_RATE_PER_HOUR", "JOIN_KEY_TTL", "IDLE_AFTER", "GC_INTERVAL", "LOGIN_SERVER", "TRUSTED_PROXY_HEADER", "MAX_FLEETS"} {
		t.Setenv(k, "")
	}
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
		LoginServer:       "",
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
	got, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := Config{NodesPerFleet: 10, CreateRatePerHour: 2, KeyRatePerHour: 7, AuthRatePerHour: 9, JoinKeyTTL: time.Hour,
		IdleAfter: 48 * time.Hour, GCEvery: 90 * time.Second, LoginServer: "https://relay.example", TrustedProxyHeader: "X-Forwarded-For", MaxFleets: 3}
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
	} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := ConfigFromEnv(); err == nil {
				t.Fatalf("%s=%q: want error", k, v)
			}
		})
	}
}
