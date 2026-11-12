package main

import (
	"testing"
	"time"
)

func TestConfigFromEnvDefaults(t *testing.T) {
	t.Setenv("RELAY_HOST", "relay.test")
	t.Setenv("SHARE_DOMAIN", "box.relay.test")
	c, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	want := Config{ListenTLS: ":443", ListenHTTP: ":80", ListenTunnel: ":8082", FrontTLS: "front:443", FrontHTTP: "front:80",
		EnrolmentURL: "http://enrolment:8081", RelayHost: "relay.test", ShareDomain: "box.relay.test", PeekTimeout: 5 * time.Second, TunnelRatePerHour: 60, ConnsPerIP: 256, ConnsPerIPPerBox: 64, FrontProxyProtocol: true}
	if c != want {
		t.Fatalf("got %+v", c)
	}
	t.Setenv("ENROLMENT_URL", "enrolment:8081")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("ENROLMENT_URL without a scheme was accepted")
	}
	t.Setenv("ENROLMENT_URL", "")
	t.Setenv("TUNNEL_RATE_PER_HOUR", "0")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("TUNNEL_RATE_PER_HOUR=0 was accepted")
	}
	t.Setenv("TUNNEL_RATE_PER_HOUR", "")
	for _, k := range []string{"CONNS_PER_IP", "CONNS_PER_IP_PER_BOX"} {
		t.Setenv(k, "0")
		if _, err := ConfigFromEnv(); err == nil {
			t.Fatalf("%s=0 was accepted", k)
		}
		t.Setenv(k, "")
	}
	t.Setenv("SHARE_DOMAIN", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("SHARE_DOMAIN should be required")
	}
}

func TestRouteSplitsNames(t *testing.T) {
	cases := []struct {
		name, box string
		front     bool
	}{
		{"relay.test", "", true},
		{"", "", true},
		{"evil.com", "", true},
		{"app.boxa.box.relay.test", "boxa", false},
		{"boxa.box.relay.test", "", false},
		{"x.y.boxa.box.relay.test", "", false},
		{".boxa.box.relay.test", "", false},
	}
	for _, c := range cases {
		box, front := route(c.name, "relay.test", "box.relay.test")
		if box != c.box || front != c.front {
			t.Errorf("%q: box=%q front=%v", c.name, box, front)
		}
	}
}

func TestConfigFromEnvValidatesHosts(t *testing.T) {
	for _, c := range []struct{ relay, domain string }{
		{"relay.test", "https://box.relay.test"},
		{"relay.test", "box.relay.test."},
		{"relay.test", "box relay.test"},
		{"https://relay.test", "box.relay.test"},
		{"relay.test:443", "box.relay.test"},
		{"a.box.relay.test", "box.relay.test"}, // the relay under the share domain
		{"box.relay.test", "box.relay.test"},
	} {
		t.Setenv("RELAY_HOST", c.relay)
		t.Setenv("SHARE_DOMAIN", c.domain)
		if _, err := ConfigFromEnv(); err == nil {
			t.Errorf("RELAY_HOST=%q SHARE_DOMAIN=%q accepted", c.relay, c.domain)
		}
	}
	t.Setenv("RELAY_HOST", "Relay.Test")
	t.Setenv("SHARE_DOMAIN", "Box.Relay.Test")
	if c, err := ConfigFromEnv(); err != nil || c.RelayHost != "relay.test" || c.ShareDomain != "box.relay.test" {
		t.Fatalf("got %+v, %v", c, err)
	}
}
