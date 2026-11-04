package main

import (
	"context"
	"errors"
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
	for in, want := range map[string]int64{"": 0, "1500": 1500, "100G": 100e9, "2T": 2e12, "1.5G": 1.5e9} {
		if got, err := parseBytes(in); err != nil || got != want {
			t.Errorf("parseBytes(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"-1", "10X", "G"} {
		if _, err := parseBytes(in); err == nil {
			t.Errorf("parseBytes(%q) must fail", in)
		}
	}
}
