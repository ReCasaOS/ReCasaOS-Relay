package feeds

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ReCasaOS/recasaos-relay/internal/store"
)

const (
	maxBody = 64 << 20
	timeout = 60 * time.Second
)

// Fetcher keeps one canonical copy of each enabled feed under Dir.
type Fetcher struct {
	Store    store.Store
	Dir      string
	Client   *http.Client
	Now      func() time.Time
	TotalMax int // total of enabled feeds' entries; <= 0 means no cap
}

func (f *Fetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// Tick downloads every enabled feed whose last_try + every_s has passed and reports whether a
// copy was replaced. A failure also moves last_try, so a broken feed is not retried every minute.
func (f *Fetcher) Tick(ctx context.Context) (replaced bool) {
	feeds, err := f.Store.Feeds(ctx)
	if err != nil {
		log.Printf("feeds: list: %v", err)
		return false
	}
	for _, fd := range feeds {
		if ctx.Err() != nil {
			return replaced
		}
		if fd.Enabled && !f.now().Before(fd.LastTry.Add(time.Duration(fd.EverySec)*time.Second)) {
			if ok, _ := f.fetch(ctx, fd, feeds); ok { // error already recorded in last_error
				replaced = true
			}
		}
	}
	return replaced
}

// Refresh downloads feed id now.
func (f *Fetcher) Refresh(ctx context.Context, id int64) error {
	feeds, err := f.Store.Feeds(ctx)
	if err != nil {
		return err
	}
	for _, fd := range feeds {
		if fd.ID == id {
			_, err := f.fetch(ctx, fd, feeds)
			return err
		}
	}
	return store.ErrNotFound
}

// Load reads the last good copy of feed id.
func (f *Fetcher) Load(id int64) ([]netip.Prefix, error) {
	file, err := os.Open(f.path(id))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return Parse(file, "text", 0, 0)
}

// Forget removes the copy of feed id; a missing copy is no error.
func (f *Fetcher) Forget(id int64) error {
	if err := os.Remove(f.path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (f *Fetcher) path(id int64) string {
	return filepath.Join(f.Dir, strconv.FormatInt(id, 10)+".txt")
}

// fetch downloads fd and records the attempt; replaced is true once the new copy is in place,
// even if recording the result then fails.
func (f *Fetcher) fetch(ctx context.Context, fd store.Feed, all []store.Feed) (replaced bool, err error) {
	at := f.now()
	n, err := f.download(ctx, fd, all)
	replaced = err == nil
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if rerr := f.Store.FeedResult(ctx, fd.ID, at, n, msg); rerr != nil && err == nil {
		err = rerr
	}
	return replaced, err
}

func (f *Fetcher) download(ctx context.Context, fd store.Feed, all []store.Feed) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fd.URL, nil)
	if err != nil { // its *url.Error would print the URL, which may hold a key
		return 0, errors.New("invalid feed URL")
	}
	req.Header.Set("User-Agent", "recasaos-relay")
	switch {
	case fd.AuthName == "Authorization-Basic":
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(fd.AuthValue)))
	case fd.AuthName != "":
		req.Header.Set(fd.AuthName, fd.AuthValue)
	}
	if fd.Preset == "abuseipdb" || fd.Preset == "abuseipdb-free" {
		req.Header.Set("Accept", "text/plain")
	}
	client := http.Client{Timeout: timeout}
	if f.Client != nil {
		client = *f.Client
	}
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		// The previous URL may hold a key; a list download needs no Referer.
		r.Header.Del("Referer")
		if r.URL.Host != via[0].URL.Host { // the key is for the list's own host, port included
			r.Header.Del("Authorization")
			if fd.AuthName != "" && fd.AuthName != "Authorization-Basic" {
				r.Header.Del(fd.AuthName)
			}
		}
		return httpsOnly(r, via)
	}
	resp, err := client.Do(req)
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, err
	}
	if len(body) > maxBody {
		return 0, errors.New("list larger than 64 MiB")
	}
	list, err := Parse(bytes.NewReader(body), fd.Format, fd.Column, fd.MaxEntries)
	if err != nil {
		return 0, err
	}
	if f.TotalMax > 0 {
		sum := len(list)
		for _, o := range all {
			if o.ID != fd.ID && o.Enabled {
				sum += o.Count
			}
		}
		if sum > f.TotalMax {
			return 0, errors.New("total cap reached")
		}
	}
	var out bytes.Buffer
	for _, p := range list {
		out.WriteString(p.String())
		out.WriteByte('\n')
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return 0, err
	}
	tmp, err := os.CreateTemp(f.Dir, "feed-*.tmp")
	if err != nil {
		return 0, err
	}
	_, werr := tmp.Write(out.Bytes())
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), f.path(fd.ID))
	}
	if werr != nil {
		os.Remove(tmp.Name())
		return 0, werr
	}
	return len(list), nil
}

// httpsOnly is the redirect policy of the downloads: https only, 10 hops at most. Its errors carry
// no URL: one may hold a key.
func httpsOnly(r *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if r.URL.Scheme != "https" {
		return errors.New("redirect to a non-https address refused")
	}
	return nil
}
