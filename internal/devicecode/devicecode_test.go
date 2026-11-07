package devicecode

import (
	"regexp"
	"testing"
)

func TestNew(t *testing.T) {
	re := regexp.MustCompile(`^[2-9A-HJ-NP-Z]{4}-[2-9A-HJ-NP-Z]{4}$`)
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		c, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(c) || seen[c] {
			t.Fatalf("bad or duplicate code %q", c)
		}
		seen[c] = true
	}
}

func TestNormalize(t *testing.T) {
	for _, in := range []string{"abcd efgh", "ABCD-EFGH", " abcdefgh "} {
		if got, ok := Normalize(in); !ok || got != "ABCDEFGH" {
			t.Errorf("Normalize(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"ABCD-EFG", "ABCD-EFGO", "ABCD-EFG1", "ABCDEFGHJ"} {
		if _, ok := Normalize(in); ok {
			t.Errorf("Normalize(%q) accepted", in)
		}
	}
}

func TestHash(t *testing.T) {
	// sha256("ABCDEFGH")
	if got := Hash("ABCDEFGH"); len(got) != 64 || got != Hash("ABCDEFGH") || got == Hash("ABCDEFGJ") {
		t.Fatalf("Hash = %q", got)
	}
}
