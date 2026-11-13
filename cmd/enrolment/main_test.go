package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestLookupenvKeepsEmpty(t *testing.T) {
	t.Setenv("RELAY_TEST_SWITCH", "")
	if got := lookupenv("RELAY_TEST_SWITCH", "on"); got != "" {
		t.Fatalf("set empty: %q, want empty (off)", got)
	}
	if got := lookupenv("RELAY_TEST_UNSET_SWITCH", "on"); got != "on" {
		t.Fatalf("unset: %q, want the default", got)
	}
}

func TestReadDirs(t *testing.T) {
	if got := readDirs(" /data/logs , ,/logs/share,"); strings.Join(got, "|") != "/data/logs|/logs/share" {
		t.Fatalf("%q", got)
	}
	if readDirs(" ") != nil {
		t.Fatal("blank is not off")
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

// A TXT character-string holds at most 255 bytes: refuse a longer SHARE_PSL_TXT at start-up.
func TestListenZoneRefusesLongPSLTXT(t *testing.T) {
	t.Setenv("SHARE_PUBLIC_IP", "192.0.2.1")
	t.Setenv("LISTEN_DNS", "127.0.0.1:0")
	t.Setenv("SHARE_PSL_TXT", strings.Repeat("a", 256))
	if _, _, _, err := listenZone("box.example", nil); err == nil || !strings.Contains(err.Error(), "SHARE_PSL_TXT") {
		t.Fatalf("err = %v, want a SHARE_PSL_TXT error", err)
	}
	t.Setenv("SHARE_PSL_TXT", strings.Repeat("a", 255))
	_, pc, l, err := listenZone("box.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
	l.Close()
}

func TestOpenJournalFailureGivesNil(t *testing.T) {
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if jw := openJournal(f, "enrolment", time.Hour, 1<<20); jw != nil {
		t.Fatal("want nil journal")
	}
}
