package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

var t0 = time.Unix(1_800_000_000, 0)

// signed builds a create-fleet request signed for the given box time.
func signed(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, at time.Time) *http.Request {
	t.Helper()
	ts := strconv.FormatInt(at.Unix(), 10)
	r := httptest.NewRequest(http.MethodPost, "/v1/fleets", nil)
	r.Header.Set("X-Box-Key", enc.EncodeToString(pub))
	r.Header.Set("X-Box-Time", ts)
	r.Header.Set("X-Box-Signature", enc.EncodeToString(ed25519.Sign(priv, []byte("POST /v1/fleets\n"+ts))))
	return r
}

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifyBoxAccepts(t *testing.T) {
	resetSeen()
	pub, priv := keys(t)
	got, err := VerifyBox(signed(t, pub, priv, t0), t0)
	if err != nil || !got.Equal(pub) {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestCreateFleetRejectsReplayAndSkew(t *testing.T) {
	resetSeen()
	pub, priv := keys(t)

	if _, err := VerifyBox(signed(t, pub, priv, t0.Add(-5*time.Minute)), t0); err == nil {
		t.Fatal("5 min old accepted")
	}
	if _, err := VerifyBox(signed(t, pub, priv, t0.Add(5*time.Minute)), t0); err == nil {
		t.Fatal("5 min in the future accepted")
	}
	// Boundary: exactly 120 s either way is still fine.
	if _, err := VerifyBox(signed(t, pub, priv, t0.Add(-120*time.Second)), t0); err != nil {
		t.Fatalf("-120s rejected: %v", err)
	}
	if _, err := VerifyBox(signed(t, pub, priv, t0.Add(120*time.Second)), t0); err != nil {
		t.Fatalf("+120s rejected: %v", err)
	}

	r := signed(t, pub, priv, t0)
	if _, err := VerifyBox(r, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBox(r, t0.Add(30*time.Second)); err == nil {
		t.Fatal("replay accepted")
	}
}

func TestSeenSetIsPruned(t *testing.T) {
	resetSeen()
	pub, priv := keys(t)
	if _, err := VerifyBox(signed(t, pub, priv, t0), t0); err != nil {
		t.Fatal(err)
	}
	// A later call, once t0's signature can no longer pass the time check, prunes it.
	later := t0.Add(5 * time.Minute)
	if _, err := VerifyBox(signed(t, pub, priv, later), later); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("seen has %d entries, want 1", n)
	}
}

func TestVerifyBoxRejectsBadInput(t *testing.T) {
	pub, priv := keys(t)
	otherPub, _ := keys(t)

	cases := map[string]func(r *http.Request){
		"tampered signature": func(r *http.Request) {
			sig, _ := enc.DecodeString(r.Header.Get("X-Box-Signature"))
			sig[0] ^= 1
			r.Header.Set("X-Box-Signature", enc.EncodeToString(sig))
		},
		"other key": func(r *http.Request) { r.Header.Set("X-Box-Key", enc.EncodeToString(otherPub)) },
		"short key": func(r *http.Request) { r.Header.Set("X-Box-Key", enc.EncodeToString(pub[:16])) },
		"long key": func(r *http.Request) {
			r.Header.Set("X-Box-Key", enc.EncodeToString(append(append([]byte{}, pub...), 0)))
		},
		"bad base64 key":   func(r *http.Request) { r.Header.Set("X-Box-Key", "!!!") },
		"padded key":       func(r *http.Request) { r.Header.Set("X-Box-Key", base64.URLEncoding.EncodeToString(pub)) },
		"bad base64 sig":   func(r *http.Request) { r.Header.Set("X-Box-Signature", "!!!") },
		"missing key":      func(r *http.Request) { r.Header.Del("X-Box-Key") },
		"missing time":     func(r *http.Request) { r.Header.Del("X-Box-Time") },
		"missing sig":      func(r *http.Request) { r.Header.Del("X-Box-Signature") },
		"non-numeric time": func(r *http.Request) { r.Header.Set("X-Box-Time", "soon") },
		"time not signed":  func(r *http.Request) { r.Header.Set("X-Box-Time", strconv.FormatInt(t0.Unix()+1, 10)) },
		"wrong method":     func(r *http.Request) { r.Method = http.MethodGet },
		"wrong path":       func(r *http.Request) { r.URL.Path = "/v1/other" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			resetSeen()
			r := signed(t, pub, priv, t0)
			mutate(r)
			if _, err := VerifyBox(r, t0); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestSecret(t *testing.T) {
	s, h, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 64 || len(h) != 64 || s == h {
		t.Fatalf("unexpected lengths %d/%d", len(s), len(h))
	}
	if !CheckSecret(s, h) {
		t.Fatal("own secret rejected")
	}
	s2, h2, _ := NewSecret()
	if s == s2 || h == h2 {
		t.Fatal("secrets repeat")
	}
	for _, c := range [][2]string{{s2, h}, {s, ""}, {"", h}, {"", ""}, {s, "short"}, {s, h + "00"}} {
		if CheckSecret(c[0], c[1]) {
			t.Fatalf("CheckSecret(%q,%q) = true", c[0], c[1])
		}
	}
}
