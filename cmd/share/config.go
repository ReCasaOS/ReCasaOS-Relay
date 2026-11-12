package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/sharename"
)

// Config is the share process's environment.
type Config struct {
	ListenTLS, ListenHTTP, ListenTunnel string
	FrontTLS, FrontHTTP                 string
	EnrolmentURL                        string
	RelayHost, ShareDomain              string
	PeekTimeout                         time.Duration
	TunnelRatePerHour                   int  // tunnel dials per hour, per client IP, counted before the signature check
	ConnsPerIP                          int  // open connections per client IP (IPv6: per /64), on 80 and 443 together
	ConnsPerIPPerBox                    int  // open visitor streams per client IP into one box's tunnel
	FrontProxyProtocol                  bool // send a PROXY v2 header to FrontTLS/FrontHTTP
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ConfigFromEnv reads the configuration; RELAY_HOST and SHARE_DOMAIN are required.
func ConfigFromEnv() (Config, error) {
	c := Config{
		ListenTLS:    getenv("LISTEN_TLS", ":443"),
		ListenHTTP:   getenv("LISTEN_HTTP", ":80"),
		ListenTunnel: getenv("LISTEN_TUNNEL", ":8082"),
		FrontTLS:     getenv("FRONT_TLS", "front:443"),
		FrontHTTP:    getenv("FRONT_HTTP", "front:80"),
		EnrolmentURL: getenv("ENROLMENT_URL", "http://enrolment:8081"),
		RelayHost:    strings.ToLower(strings.TrimSpace(os.Getenv("RELAY_HOST"))),
		ShareDomain:  strings.ToLower(strings.TrimSpace(os.Getenv("SHARE_DOMAIN"))),
	}
	if c.RelayHost == "" || c.ShareDomain == "" {
		return Config{}, errors.New("RELAY_HOST and SHARE_DOMAIN are required")
	}
	for k, v := range map[string]string{"RELAY_HOST": c.RelayHost, "SHARE_DOMAIN": c.ShareDomain} {
		if sharename.ValidHost(v) != nil {
			return Config{}, fmt.Errorf("%s: %q is not a bare DNS name (no scheme, port or trailing dot)", k, v)
		}
	}
	// A relay host under the share domain would be routed as a box name.
	if c.RelayHost == c.ShareDomain || strings.HasSuffix(c.RelayHost, "."+c.ShareDomain) {
		return Config{}, fmt.Errorf("RELAY_HOST %q must not be under SHARE_DOMAIN %q", c.RelayHost, c.ShareDomain)
	}
	// Checked once here: resolve requests carry the box key in their path, and a URL that fails to parse
	// later would print it in the error.
	if u, err := url.Parse(c.EnrolmentURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Config{}, errors.New("ENROLMENT_URL: want an http(s) URL with a host")
	}
	var err error
	if c.PeekTimeout, err = time.ParseDuration(getenv("PEEK_TIMEOUT", "5s")); err != nil || c.PeekTimeout <= 0 {
		return Config{}, fmt.Errorf("PEEK_TIMEOUT: want a positive duration, got %q", os.Getenv("PEEK_TIMEOUT"))
	}
	if c.TunnelRatePerHour, err = strconv.Atoi(getenv("TUNNEL_RATE_PER_HOUR", "60")); err != nil || c.TunnelRatePerHour <= 0 {
		return Config{}, fmt.Errorf("TUNNEL_RATE_PER_HOUR: want a positive integer, got %q", os.Getenv("TUNNEL_RATE_PER_HOUR"))
	}
	if c.ConnsPerIP, err = strconv.Atoi(getenv("CONNS_PER_IP", "256")); err != nil || c.ConnsPerIP <= 0 {
		return Config{}, fmt.Errorf("CONNS_PER_IP: want a positive integer, got %q", os.Getenv("CONNS_PER_IP"))
	}
	if c.ConnsPerIPPerBox, err = strconv.Atoi(getenv("CONNS_PER_IP_PER_BOX", "64")); err != nil || c.ConnsPerIPPerBox <= 0 {
		return Config{}, fmt.Errorf("CONNS_PER_IP_PER_BOX: want a positive integer, got %q", os.Getenv("CONNS_PER_IP_PER_BOX"))
	}
	if c.FrontProxyProtocol, err = strconv.ParseBool(getenv("FRONT_PROXY_PROTOCOL", "true")); err != nil {
		return Config{}, fmt.Errorf("FRONT_PROXY_PROTOCOL: want true or false, got %q", os.Getenv("FRONT_PROXY_PROTOCOL"))
	}
	return c, nil
}
