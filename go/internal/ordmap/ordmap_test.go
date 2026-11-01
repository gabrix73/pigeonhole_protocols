package ordmap

import (
	"slices"
	"testing"
)

func TestOrder(t *testing.T) {
	var m Map[string, int]
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("c", 3)
	m.Set("a", 9)
	if got := m.Keys(); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("keys %v", got)
	}
	if v, _ := m.Get("a"); v != 9 {
		t.Fatalf("a = %d", v)
	}
	m.Delete("b")
	m.Set("b", 4)
	if got := m.Keys(); !slices.Equal(got, []string{"a", "c", "b"}) {
		t.Fatalf("keys %v", got)
	}
	m.SetDefault("c", 0)
	m.Modify("c", func(v int) int { return v + 1 })
	if got := m.Values(); !slices.Equal(got, []int{9, 4, 4}) {
		t.Fatalf("values %v", got)
	}
	m.Filter(func(k string, v int) bool { return k != "a" })
	if got := m.Keys(); !slices.Equal(got, []string{"c", "b"}) || !m.Has("b") || m.Has("a") {
		t.Fatalf("keys %v", got)
	}
	if v, _ := m.Get("b"); v != 4 {
		t.Fatalf("b = %d after filter", v)
	}
	c := m.Clone()
	c.Set("z", 1)
	if m.Has("z") || c.Len() != 3 {
		t.Fatal("clone shares state")
	}
}
