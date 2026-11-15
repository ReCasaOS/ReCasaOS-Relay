package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/autoban"
	"github.com/ReCasaOS/recasaos-relay/internal/community"
	"github.com/ReCasaOS/recasaos-relay/internal/journal"
	"github.com/ReCasaOS/recasaos-relay/internal/protect"
	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

const maxBanNote = 200

// autoBan turns what the detector sees (front's access lines, unknown share names, boxes) into ban rows.
type autoBan struct {
	det      *autoban.Detector
	store    store.Store
	compiler *protect.Compiler
	journal  *journal.Writer // nil: no journal
	now      func() time.Time
	shareDom string // lower case: lines for a shared app are not the relay's own traffic
	dir      string // holds autoban.json (thresholds set on /admin) and autoban-state.json; "": nothing is kept
}

const (
	thresholdsFile = "autoban.json"
	stateFile      = "autoban-state.json"
)

// Thresholds returns the thresholds in force.
func (a *autoBan) Thresholds() autoban.Config { return a.det.Config() }

// SetThresholds applies cfg and keeps it over the environment's values at the next starts.
func (a *autoBan) SetThresholds(cfg autoban.Config) error {
	if a.dir != "" {
		b, err := json.Marshal(cfg)
		if err != nil {
			return err
		}
		if err := writeFile(filepath.Join(a.dir, thresholdsFile), b); err != nil {
			return err
		}
	}
	a.det.SetConfig(cfg)
	return nil
}

// restore reads what SetThresholds and save left. A missing file is the normal first start; a broken
// one is logged and ignored: the detector then runs on the environment's thresholds, from zero.
func (a *autoBan) restore() {
	if a.dir == "" {
		return
	}
	if b, err := os.ReadFile(filepath.Join(a.dir, thresholdsFile)); err == nil {
		var cfg autoban.Config
		if err := json.Unmarshal(b, &cfg); err != nil {
			log.Printf("autoban: %s: %v", thresholdsFile, err)
		} else {
			a.det.SetConfig(cfg)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		log.Printf("autoban: %v", err)
	}
	f, err := os.Open(filepath.Join(a.dir, stateFile))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("autoban: %v", err)
		}
		return
	}
	defer f.Close()
	if err := a.det.Load(f); err != nil {
		log.Printf("autoban: %s: %v", stateFile, err)
	}
}

// save keeps the counters for the next start.
func (a *autoBan) save() {
	if a.dir == "" {
		return
	}
	var b strings.Builder
	if err := a.det.Save(&b); err != nil {
		log.Printf("autoban: save: %v", err)
		return
	}
	if err := writeFile(filepath.Join(a.dir, stateFile), []byte(b.String())); err != nil {
		log.Printf("autoban: save: %v", err)
	}
}

// writeFile replaces path in one step: a crash never leaves half a file. 0600: the state holds addresses.
func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Front takes one parsed front access line.
func (a *autoBan) Front(e journal.Entry) {
	key, ok := community.Key(e.IP)
	if !ok || a.sharedHost(e.Host) {
		return
	}
	if fault, detail := a.det.Front(key, e.Path, e.Status); fault != "" {
		a.ban(context.Background(), key, fault, detail)
	}
}

// sharedHost: share sends all of port 80 to front, so a plain-HTTP request to a shared app is a line too.
func (a *autoBan) sharedHost(host string) bool {
	if a.shareDom == "" {
		return false
	}
	h := strings.ToLower(host)
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return h == a.shareDom || strings.HasSuffix(h, "."+a.shareDom)
}

// Unknown takes one try of a share name that has no tunnel; a held name is not a guess.
func (a *autoBan) Unknown(ctx context.Context, key, name string) {
	key, ok := community.Key(key)
	if !ok {
		return
	}
	name = strings.ToLower(name) // NameClaimed is case-sensitive, names are stored in lower case
	if held, err := a.store.NameClaimed(ctx, name); err != nil {
		log.Printf("autoban: name lookup: %v", err)
		return
	} else if held {
		return
	}
	if fault, detail := a.det.Unknown(key, name); fault != "" {
		a.ban(ctx, key, fault, detail)
	}
}

// Box exempts the address of an authenticated box.
func (a *autoBan) Box(key string) {
	if key, ok := community.Key(key); ok {
		a.det.Box(key)
	}
}

func (a *autoBan) ban(ctx context.Context, key, fault, detail string) {
	if p, err := netip.ParsePrefix(key); err != nil || (a.compiler != nil && a.compiler.Allowed(p)) {
		return
	}
	note := []rune(store.AutoNote + fault + " · " + detail)
	if len(note) > maxBanNote {
		note = note[:maxBanNote]
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, ok, err := a.store.AddAutoBan(ctx, key, string(note), a.now())
	if err != nil { // no address in the log line: logs are read by third parties
		log.Printf("autoban: %v", err)
		return
	}
	if !ok {
		return
	}
	if a.compiler != nil {
		a.compiler.Invalidate()
	}
	a.journal.Write(journal.Entry{Src: "relay", Event: "ban_auto", IP: key,
		Msg: fmt.Sprintf("%s · %s · %d h", fault, detail, int(b.Until.Sub(b.Since).Round(time.Hour)/time.Hour))})
}

// autoBanFromEnv reads AUTOBAN ("on" or "off"), AUTOBAN_404, AUTOBAN_NAMES, AUTOBAN_TRAPS and AUTOBAN_WINDOW.
func autoBanFromEnv() (cfg autoban.Config, on bool, err error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AUTOBAN"))) {
	case "", "on":
	case "off":
		return cfg, false, nil
	default:
		return cfg, false, errors.New("AUTOBAN: on or off")
	}
	if cfg.NotFound, err = envPositive("AUTOBAN_404", 20); err != nil {
		return cfg, false, err
	}
	if cfg.Names, err = envPositive("AUTOBAN_NAMES", 10); err != nil {
		return cfg, false, err
	}
	if cfg.Traps, err = envPositive("AUTOBAN_TRAPS", 3); err != nil {
		return cfg, false, err
	}
	cfg.Window = 10 * time.Minute
	if v := os.Getenv("AUTOBAN_WINDOW"); v != "" {
		if cfg.Window, err = time.ParseDuration(v); err != nil || cfg.Window <= 0 {
			return cfg, false, errors.New("AUTOBAN_WINDOW: a positive duration such as 10m")
		}
	}
	return cfg, true, nil
}
