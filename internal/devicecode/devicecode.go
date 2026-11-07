// Package devicecode makes and normalises the short codes a phone types to join a fleet.
package devicecode

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// alphabet drops 0 1 I L O, which are easily confused.
const alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

const length = 8

// New returns a fresh code shaped XXXX-XXXX.
func New() (string, error) {
	// Rejection sampling: bytes >= max would favour the first chars of the alphabet.
	const max = 256 - 256%len(alphabet)
	out := make([]byte, 0, length+1)
	buf := make([]byte, 16)
	for len(out) < cap(out)-1 {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) < max && len(out) < length {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}

// Normalize drops spaces and one dash style, upper-cases, and reports whether 8 alphabet chars remain.
func Normalize(in string) (string, bool) {
	s := strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(in)))
	if len(s) != length {
		return "", false
	}
	for _, c := range s {
		if !strings.ContainsRune(alphabet, c) {
			return "", false
		}
	}
	return s, true
}

// Hash is the hex SHA-256 of a normalized code: all the store keeps.
func Hash(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
