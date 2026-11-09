package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is the share process's environment.
type Config struct {
	ListenTLS, ListenHTTP, ListenTunnel string
	FrontTLS, FrontHTTP                 string
	EnrolmentURL                        string
	RelayHost, ShareDomain              string
	PeekTimeout                         time.Duration
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
		RelayHost:    os.Getenv("RELAY_HOST"),
		ShareDomain:  strings.ToLower(os.Getenv("SHARE_DOMAIN")),
	}
	if c.RelayHost == "" || c.ShareDomain == "" {
		return Config{}, errors.New("RELAY_HOST and SHARE_DOMAIN are required")
	}
	var err error
	if c.PeekTimeout, err = time.ParseDuration(getenv("PEEK_TIMEOUT", "5s")); err != nil || c.PeekTimeout <= 0 {
		return Config{}, fmt.Errorf("PEEK_TIMEOUT: want a positive duration, got %q", os.Getenv("PEEK_TIMEOUT"))
	}
	return c, nil
}
