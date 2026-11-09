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
		EnrolmentURL: "http://enrolment:8081", RelayHost: "relay.test", ShareDomain: "box.relay.test", PeekTimeout: 5 * time.Second, FrontProxyProtocol: true}
	if c != want {
		t.Fatalf("got %+v", c)
	}
	t.Setenv("ENROLMENT_URL", "enrolment:8081")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("ENROLMENT_URL without a scheme was accepted")
	}
	t.Setenv("ENROLMENT_URL", "")
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
