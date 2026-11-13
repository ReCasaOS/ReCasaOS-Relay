// Package feeds downloads and parses the external block lists the operator picked.
package feeds

import (
	"bufio"
	"errors"
	"io"
	"net/netip"
	"slices"
	"strings"
)

var (
	ErrTooMany = errors.New("too many entries")
	ErrEmpty   = errors.New("no address in the list")
)

// Parse reads one list. format is "text" (first field of the line) or "csv" (1-based column).
// Entries broader than /8 (IPv4) or /19 (IPv6) are skipped, so a broken list cannot ban everyone.
// max <= 0 means no limit.
func Parse(r io.Reader, format string, column, max int) ([]netip.Prefix, error) {
	if column < 1 {
		column = 1
	}
	seen := map[netip.Prefix]struct{}{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		var field string
		if format == "csv" {
			cols := strings.Split(line, ",")
			if column > len(cols) {
				continue
			}
			field = strings.Trim(strings.TrimSpace(cols[column-1]), `"`)
		} else if f := strings.Fields(line); len(f) > 0 {
			field = f[0]
		}
		if p, ok := entry(field); ok {
			seen[p] = struct{}{}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(seen) == 0 {
		return nil, ErrEmpty
	}
	if max > 0 && len(seen) > max {
		return nil, ErrTooMany
	}
	out := make([]netip.Prefix, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out, nil
}

func entry(s string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return netip.Prefix{}, false
		}
		a = a.WithZone("")
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if a := p.Addr(); a.Is4In6() { // ::ffff:a.b.c.d/N is IPv4
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	if !p.IsValid() || p.Addr().Zone() != "" {
		return netip.Prefix{}, false
	}
	if min := map[bool]int{true: 8, false: 19}[p.Addr().Is4()]; p.Bits() < min {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}
