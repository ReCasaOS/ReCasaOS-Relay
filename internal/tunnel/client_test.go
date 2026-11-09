package tunnel

import (
	"context"
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
