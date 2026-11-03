// Package auth verifies box signatures and handles fleet secrets.
package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const skew = 120 * time.Second

var (
	errBadRequest = errors.New("auth: not a create-fleet request")
	errBadHeaders = errors.New("auth: missing or malformed box headers")
	errSkew       = errors.New("auth: box time outside accepted window")
	errBadSig     = errors.New("auth: bad box signature")
	errReplay     = errors.New("auth: signature already used")
	errWeakKey    = errors.New("auth: small-order box key")

	// Strict rejects non-canonical spellings (non-zero trailing bits), which would
	// otherwise let one signature be replayed under 15 alternate encodings.
	enc = base64.RawURLEncoding.Strict()

	// seen maps a used signature (decoded bytes, not the header text) to the moment
	// it can no longer pass the time check. TLS is mandatory in front of this
	// service (a signature is bearer-like within the window) and a restart empties
	// seen, so a replay is possible for up to 120 s after one.
	mu        sync.Mutex
	seen      = map[string]time.Time{}
	lastSweep time.Time
	sweeps    int // test hook: number of full sweeps run
)

// smallOrderKeys are the encodings of the edwards25519 points of small order. A box key equal to one
// of them lets anyone forge signatures without a secret (identity point: R = identity, S = 0 verifies
// for a fraction of messages), so they are refused before verification.
var smallOrderKeys = func() [][]byte {
	var out [][]byte
	for _, h := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	} {
		b, _ := hex.DecodeString(h)
		out = append(out, b)
	}
	return out
}()

// sweepEvery bounds how often seen is scanned, keeping verification amortised O(1).
const sweepEvery = time.Second

func resetSeen() {
	mu.Lock()
	seen = map[string]time.Time{}
	lastSweep = time.Time{}
	sweeps = 0
	mu.Unlock()
}

// VerifyBox authenticates a POST /v1/fleets request signed by a box and returns
// the box's public key. A signature is accepted once, within ±120 s of now.
// Callers that key anything by box identity must use the returned decoded key
// bytes, never the X-Box-Key header text.
func VerifyBox(r *http.Request, now time.Time) (ed25519.PublicKey, error) {
	if r.Method != http.MethodPost || r.URL.Path != "/v1/fleets" {
		return nil, errBadRequest
	}
	pub, err := enc.DecodeString(r.Header.Get("X-Box-Key"))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errBadHeaders
	}
	for _, weak := range smallOrderKeys {
		if bytes.Equal(pub, weak) {
			return nil, errWeakKey
		}
	}
	sig, err := enc.DecodeString(r.Header.Get("X-Box-Signature"))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errBadHeaders
	}
	tsStr := r.Header.Get("X-Box-Time")
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, errBadHeaders
	}
	boxTime := time.Unix(ts, 0)
	if d := now.Sub(boxTime); d > skew || d < -skew {
		return nil, errSkew
	}
	if !ed25519.Verify(pub, []byte("POST /v1/fleets\n"+tsStr), sig) {
		return nil, errBadSig
	}

	mu.Lock()
	defer mu.Unlock()
	if now.Sub(lastSweep) >= sweepEvery {
		for k, exp := range seen {
			if now.After(exp) {
				delete(seen, k)
			}
		}
		lastSweep = now
		sweeps++
	}
	if _, dup := seen[string(sig)]; dup {
		return nil, errReplay
	}
	seen[string(sig)] = boxTime.Add(skew)
	return ed25519.PublicKey(pub), nil
}

// NewSecret returns a random fleet secret and its sha256 hex hash (the only form stored).
func NewSecret() (secret, hash string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret = hex.EncodeToString(b)
	return secret, hashOf(secret), nil
}

// CheckSecret reports whether secret matches hash, in constant time.
func CheckSecret(secret, hash string) bool {
	if secret == "" || hash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashOf(secret)), []byte(hash)) == 1
}

func hashOf(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}
