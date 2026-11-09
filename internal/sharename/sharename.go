// Package sharename validates the public names a box claims for sharing (<name>.<share domain>).
package sharename

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

var (
	ErrInvalid  = errors.New("sharename: invalid name")
	ErrReserved = errors.New("sharename: reserved name")
)

// 3 to 32 characters of [a-z0-9-], not starting or ending with "-"; "a--b" is a valid DNS label.
var re = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

var reserved = []string{"www", "relay", "admin", "api", "mail", "ns", "ns1", "box", "tunnel", "recasaos", "casaos", "localhost"}

// ValidLabel checks the syntax only (a reserved word passes): the operator may forbid one.
func ValidLabel(name string) error {
	if !re.MatchString(name) {
		return ErrInvalid
	}
	return nil
}

// Valid returns ErrInvalid when name is not an acceptable label and ErrReserved when it is on the built-in list.
func Valid(name string) error {
	if err := ValidLabel(name); err != nil {
		return err
	}
	if slices.Contains(reserved, name) {
		return ErrReserved
	}
	return nil
}

var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidHost checks an operator-given host name (SHARE_DOMAIN, RELAY_HOST): lowercase DNS labels
// joined by dots, no scheme, port, trailing dot or space.
func ValidHost(h string) error {
	if h == "" || len(h) > 253 {
		return ErrInvalid
	}
	for _, l := range strings.Split(h, ".") {
		if !hostLabel.MatchString(l) {
			return ErrInvalid
		}
	}
	return nil
}
