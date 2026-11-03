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
