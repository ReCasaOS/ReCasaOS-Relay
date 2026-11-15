package main

import (
	"testing"
	"time"
)

func TestAutoBanFromEnv(t *testing.T) {
	set := func(on, n404, names, win string) {
		t.Setenv("AUTOBAN", on)
		t.Setenv("AUTOBAN_404", n404)
		t.Setenv("AUTOBAN_NAMES", names)
		t.Setenv("AUTOBAN_WINDOW", win)
	}
	set("", "", "", "") // what compose passes when the operator sets nothing
	cfg, on, err := autoBanFromEnv()
	if err != nil || !on || cfg.NotFound != 20 || cfg.Names != 10 || cfg.Window != 10*time.Minute {
		t.Errorf("empty: %+v %v %v", cfg, on, err)
	}
	set("off", "", "", "")
	if _, on, err := autoBanFromEnv(); on || err != nil {
		t.Errorf("off: %v %v", on, err)
	}
	set("", "5", "3", "2m")
	if cfg, on, err := autoBanFromEnv(); err != nil || !on || cfg.NotFound != 5 || cfg.Names != 3 || cfg.Window != 2*time.Minute {
		t.Errorf("set: %+v %v %v", cfg, on, err)
	}
	for _, bad := range [][4]string{{"", "0", "", ""}, {"", "", "x", ""}, {"", "", "", "-1m"}, {"", "", "", "abc"}} {
		set(bad[0], bad[1], bad[2], bad[3])
		if _, _, err := autoBanFromEnv(); err == nil {
			t.Errorf("%v: want an error", bad)
		}
	}
}
