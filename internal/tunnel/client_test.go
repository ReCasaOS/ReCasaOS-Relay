package tunnel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
)

// Enrolment unreachable: the box is told to retry (503), not that it lost its name (403).
func TestEnrolmentDownIs503(t *testing.T) {
	reg, f, url := newRelay(t)
	key := newBox(t, f, "alpha")
	f.set("", nil, errors.New("connection refused"))
	_, err := Dial(context.Background(), url, key, DialOptions{})
	var de *DialError
	if !errors.As(err, &de) || de.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("Dial with enrolment down: %v, want 503", err)
	}
	if len(reg.Names()) != 0 {
		t.Fatal("tunnel registered")
	}
}

// A key enrolment knows without a name must never register under "".
func TestNamelessBoxIs403(t *testing.T) {
	reg, f, url := newRelay(t)
	key := newBox(t, f, "")
	f.set(base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), &Box{NodeID: "7", FleetID: "f1"}, nil)
	_, err := Dial(context.Background(), url, key, DialOptions{})
	var de *DialError
	if !errors.As(err, &de) || de.StatusCode != http.StatusForbidden {
		t.Fatalf("Dial for a nameless box: %v, want 403", err)
	}
	if len(reg.Names()) != 0 {
		t.Fatal("tunnel registered")
	}
}
