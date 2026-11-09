package sharename

import (
	"errors"
	"strings"
	"testing"
)

func TestSharenameValid(t *testing.T) {
	for name, want := range map[string]error{
		"abc": nil, "my-box": nil, "a--b": nil, "box1": nil, "123": nil,
		strings.Repeat("a", 32): nil,
		"Boxa":                  ErrInvalid, "a": ErrInvalid, "ab": ErrInvalid, "-ab": ErrInvalid, "ab-": ErrInvalid, "": ErrInvalid,
		"a_b": ErrInvalid, "a.b": ErrInvalid, strings.Repeat("a", 33): ErrInvalid,
		"www": ErrReserved, "relay": ErrReserved, "admin": ErrReserved, "api": ErrReserved, "mail": ErrReserved,
		"ns1": ErrReserved, "box": ErrReserved, "tunnel": ErrReserved, "recasaos": ErrReserved, "casaos": ErrReserved, "localhost": ErrReserved,
	} {
		if got := Valid(name); !errors.Is(got, want) || (want == nil) != (got == nil) {
			t.Errorf("Valid(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestValidHost(t *testing.T) {
	for _, h := range []string{"box.recasaos.org", "relay.test", "a-b.c1", strings.Repeat("a", 63) + ".x"} {
		if ValidHost(h) != nil {
			t.Errorf("ValidHost(%q) refused", h)
		}
	}
	for _, h := range []string{"", "Box.org", "https://box.org", "box.org.", "box .org", "box..org", "-box.org", "box-.org", "box_1.org", "box.org:443", strings.Repeat("a", 64) + ".x"} {
		if ValidHost(h) == nil {
			t.Errorf("ValidHost(%q) accepted", h)
		}
	}
}
