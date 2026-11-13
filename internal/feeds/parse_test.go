package feeds

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func prefixes(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func eq(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseText(t *testing.T) {
	in := "1.2.3.4\n5.6.7.0/24 ; SBL123\n# comment\n2001:db8::1\njunk\n1.2.3.4\n"
	got, err := Parse(strings.NewReader(in), "text", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if want := prefixes("1.2.3.4/32", "5.6.7.0/24", "2001:db8::1/128"); !eq(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseCSVColumn(t *testing.T) {
	got, err := Parse(strings.NewReader("ip,score\n9.9.9.9,100\n"), "csv", 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if want := prefixes("9.9.9.9/32"); !eq(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestParseTooMany(t *testing.T) {
	_, err := Parse(strings.NewReader("1.1.1.1\n2.2.2.2\n3.3.3.3\n"), "text", 0, 2)
	if !errors.Is(err, ErrTooMany) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseEmpty(t *testing.T) {
	_, err := Parse(strings.NewReader("<html>nope</html>\n"), "text", 0, 2)
	if !errors.Is(err, ErrEmpty) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseSkipsHugePrefixes(t *testing.T) {
	got, err := Parse(strings.NewReader("0.0.0.0/0\n10.0.0.0/7\n2000::/3\n1.0.0.0/8\n"), "text", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if want := prefixes("1.0.0.0/8"); !eq(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestPresetsAreHTTPS(t *testing.T) {
	if len(Presets) != 8 {
		t.Fatalf("%d presets", len(Presets))
	}
	for _, p := range Presets {
		if !strings.HasPrefix(p.URL, "https://") {
			t.Errorf("%s: %s", p.Key, p.URL)
		}
	}
}
