package tunnel

import (
	"slices"
	"testing"
)

func TestRegistryPutGetRemove(t *testing.T) {
	r := NewRegistry()
	a, b := &Tunnel{Name: "a"}, &Tunnel{Name: "a"}
	if old := r.Put("a", a); old != nil {
		t.Fatalf("first Put replaced %v", old)
	}
	if old := r.Put("a", b); old != a {
		t.Fatalf("second Put replaced %v, want the first tunnel", old)
	}
	r.Put("z", &Tunnel{Name: "z"})
	if got := r.Names(); !slices.Equal(got, []string{"a", "z"}) {
		t.Fatalf("Names = %v", got)
	}
	r.Remove("a", a) // a was replaced: b stays
	if got, ok := r.Get("a"); !ok || got != b {
		t.Fatalf("Get after removing the replaced tunnel = %v, %v; want b", got, ok)
	}
	r.Remove("a", b)
	if _, ok := r.Get("a"); ok {
		t.Fatal("a still registered after Remove")
	}
}
