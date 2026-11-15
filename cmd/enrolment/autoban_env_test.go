package main

import (
	"strings"
	"testing"
	"time"
)

func TestAutoBanFromEnv(t *testing.T) {
	set := func(on, n404, names, win string, traps ...string) {
		t.Setenv("AUTOBAN_TRAPS", append(traps, "")[0])
		t.Setenv("AUTOBAN", on)
		t.Setenv("AUTOBAN_404", n404)
		t.Setenv("AUTOBAN_NAMES", names)
		t.Setenv("AUTOBAN_WINDOW", win)
	}
	set("", "", "", "") // what compose passes when the operator sets nothing
	cfg, on, err := autoBanFromEnv()
	if err != nil || !on || cfg.NotFound != 20 || cfg.Names != 10 || cfg.Traps != 3 || cfg.Window != 10*time.Minute {
		t.Errorf("empty: %+v %v %v", cfg, on, err)
	}
	set("off", "", "", "")
	if _, on, err := autoBanFromEnv(); on || err != nil {
		t.Errorf("off: %v %v", on, err)
	}
	for _, v := range []string{"on", " ON ", "Off"} {
		set(v, "", "", "")
		if _, on, err := autoBanFromEnv(); err != nil || on != (strings.TrimSpace(strings.ToLower(v)) == "on") {
			t.Errorf("%q: %v %v", v, on, err)
		}
	}
	set("maybe", "", "", "")
	if _, _, err := autoBanFromEnv(); err == nil {
		t.Error("maybe: want an error")
	}
	set("", "5", "3", "2m", "7")
	if cfg, on, err := autoBanFromEnv(); err != nil || !on || cfg.Traps != 7 || cfg.NotFound != 5 || cfg.Names != 3 || cfg.Window != 2*time.Minute {
		t.Errorf("set: %+v %v %v", cfg, on, err)
	}
	for _, bad := range [][5]string{{"", "0", "", "", ""}, {"", "", "x", "", ""}, {"", "", "", "-1m", ""}, {"", "", "", "abc", ""}, {"", "", "", "", "0"}, {"", "", "", "", "x"}} {
		set(bad[0], bad[1], bad[2], bad[3], bad[4])
		if _, _, err := autoBanFromEnv(); err == nil {
			t.Errorf("%v: want an error", bad)
		}
	}
}
