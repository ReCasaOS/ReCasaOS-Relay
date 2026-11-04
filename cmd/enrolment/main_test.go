package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPolicyIsAppliedBeforeServing(t *testing.T) {
	var order []string
	err := serveAfterPolicy(context.Background(),
		func(context.Context) error { order = append(order, "policy"); return nil },
		func() error { order = append(order, "serve"); return nil })
	if err != nil || len(order) != 2 || order[0] != "policy" || order[1] != "serve" {
		t.Fatalf("order = %v, err = %v", order, err)
	}
}

func TestNeverServesWithoutPolicy(t *testing.T) {
	served := false
	err := serveAfterPolicy(context.Background(),
		func(context.Context) error { return errors.New("headscale down") },
		func() error { served = true; return nil })
	if err == nil || served {
		t.Fatalf("startup must fail without serving (err=%v, served=%v)", err, served)
	}
}

func TestParseBytes(t *testing.T) {
	for in, want := range map[string]int64{
		"": 0, "  ": 0, "1500": 1500, "100G": 100e9, "2T": 2e12, "1.5G": 1.5e9,
		"100g": 100e9, "2t": 2e12, "5k": 5e3, "7m": 7e6, "100GB": 100e9, "100gb": 100e9, "100B": 100,
		" 1 G ": 1e9, "1 GB": 1e9, "1.9": 2, // rounded, not truncated
	} {
		if got, err := parseBytes(in); err != nil || got != want {
			t.Errorf("parseBytes(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"-1", "-1G", "10X", "G", "GB", "B", "1GBB", "10000000T", "9.3e18", "NaN", "Inf", "+Inf", "-Inf", "NaNG", "InfT"} {
		if _, err := parseBytes(in); err == nil {
			t.Errorf("parseBytes(%q) must fail", in)
		}
	}
	if _, err := parseBytes(" 10 XB"); err == nil || !strings.Contains(err.Error(), `" 10 XB"`) {
		t.Errorf("error %v must quote the original input", err)
	}
}
