// Package ordmap is a map that keeps insertion order: setting a present key replaces its value
// in place, setting a new key appends it, and deleting keeps the order of the rest.
package ordmap

type entry[K comparable, V any] struct {
	key K
	val V
}

type Map[K comparable, V any] struct {
	entries []entry[K, V]
	index   map[K]int
}

func (m *Map[K, V]) Len() int { return len(m.entries) }

func (m *Map[K, V]) Get(k K) (V, bool) {
	if i, ok := m.index[k]; ok {
		return m.entries[i].val, true
	}
	var zero V
	return zero, false
}

func (m *Map[K, V]) GetOr(k K, def V) V {
	if v, ok := m.Get(k); ok {
		return v
	}
	return def
}

func (m *Map[K, V]) Has(k K) bool {
	_, ok := m.index[k]
	return ok
}

func (m *Map[K, V]) Set(k K, v V) {
	if i, ok := m.index[k]; ok {
		m.entries[i].val = v
		return
	}
	if m.index == nil {
		m.index = make(map[K]int)
	}
	m.index[k] = len(m.entries)
	m.entries = append(m.entries, entry[K, V]{k, v})
}

// SetDefault sets k only if it is absent.
func (m *Map[K, V]) SetDefault(k K, v V) {
	if !m.Has(k) {
		m.Set(k, v)
	}
}

// Modify replaces the value of k, if present, with f of it.
func (m *Map[K, V]) Modify(k K, f func(V) V) {
	if i, ok := m.index[k]; ok {
		m.entries[i].val = f(m.entries[i].val)
	}
}

func (m *Map[K, V]) Delete(k K) {
	i, ok := m.index[k]
	if !ok {
		return
	}
	m.entries = append(m.entries[:i], m.entries[i+1:]...)
	delete(m.index, k)
	for j := i; j < len(m.entries); j++ {
		m.index[m.entries[j].key] = j
	}
}

// Filter keeps the entries for which keep is true, in order.
func (m *Map[K, V]) Filter(keep func(K, V) bool) {
	kept := m.entries[:0]
	for _, e := range m.entries {
		if keep(e.key, e.val) {
			kept = append(kept, e)
		} else {
			delete(m.index, e.key)
		}
	}
	clear(m.entries[len(kept):])
	m.entries = kept
	for i, e := range m.entries {
		m.index[e.key] = i
	}
}

// All iterates over the entries in order.
func (m *Map[K, V]) All(yield func(K, V) bool) {
	for _, e := range m.entries {
		if !yield(e.key, e.val) {
			return
		}
	}
}

func (m *Map[K, V]) Keys() []K {
	ks := make([]K, len(m.entries))
	for i, e := range m.entries {
		ks[i] = e.key
	}
	return ks
}

func (m *Map[K, V]) Values() []V {
	vs := make([]V, len(m.entries))
	for i, e := range m.entries {
		vs[i] = e.val
	}
	return vs
}

// Clone copies the map; values are copied shallowly.
func (m *Map[K, V]) Clone() Map[K, V] {
	c := Map[K, V]{entries: append([]entry[K, V](nil), m.entries...)}
	if len(m.entries) > 0 {
		c.index = make(map[K]int, len(m.entries))
		for k, i := range m.index {
			c.index[k] = i
		}
	}
	return c
}
