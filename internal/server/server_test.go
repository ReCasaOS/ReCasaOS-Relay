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
	for _, k := range []string{"NODES_PER_FLEET", "CREATE_RATE_PER_HOUR", "KEY_RATE_PER_HOUR", "JOIN_KEY_TTL", "IDLE_AFTER", "LOGIN_SERVER", "TRUSTED_PROXY_HEADER"} {
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
		JoinKeyTTL:        24 * time.Hour,
		IdleAfter:         720 * time.Hour,
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
	t.Setenv("JOIN_KEY_TTL", "1h")
	t.Setenv("IDLE_AFTER", "48h")
	t.Setenv("LOGIN_SERVER", "https://relay.example")
	t.Setenv("TRUSTED_PROXY_HEADER", "X-Forwarded-For")
	got, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := Config{10, 2, 7, time.Hour, 48 * time.Hour, "https://relay.example", "X-Forwarded-For"}
	if got != want {
		t.Fatalf("overrides = %+v, want %+v", got, want)
	}
}

func TestConfigFromEnvInvalid(t *testing.T) {
	for k, v := range map[string]string{
		"NODES_PER_FLEET":   "abc",
		"KEY_RATE_PER_HOUR": "0",
		"JOIN_KEY_TTL":      "soon",
		"IDLE_AFTER":        "-1h",
	} {
		t.Run(k, func(t *testing.T) {
			t.Setenv(k, v)
			if _, err := ConfigFromEnv(); err == nil {
				t.Fatalf("%s=%q: want error", k, v)
			}
		})
	}
}
