package member

import (
	"bytes"
	"slices"
	"strings"

	"github.com/katzenpost/pigeonhole_protocols/go/internal/ordmap"
)

// Rosters with explicit numbering: every roster index is announced explicitly, so a missed
// message leaves an index unresolved and never shifts others. A roster that began as its
// introducer's reads its early entries from that roster.

type Entry struct {
	Key *Key
	// Prefix is the start of the member's key, as a Numbers field names it.
	Prefix []byte
}

// Started says a member's roster began as Introducer's, through index Top.
type Started struct {
	Introducer Key
	Top        int
}

type Roster = ordmap.Map[int, Entry]

type Rosters struct {
	Entries ordmap.Map[Key, *Roster]
	Started ordmap.Map[Key, Started]
	// Introductions are the members introduced, by Introduction.
	Introductions ordmap.Map[At, Key]
	// Keys is every member whose key this member knows: whom a prefix can name.
	Keys   []Key
	keySet map[Key]bool
}

func (r *Rosters) learn(k Key) {
	if r.keySet == nil {
		r.keySet = make(map[Key]bool, len(r.Keys))
		for _, k := range r.Keys {
			r.keySet[k] = true
		}
	}
	if !r.keySet[k] {
		r.keySet[k] = true
		r.Keys = append(r.Keys, k)
	}
}

// named is the one member known whose key starts with p.
func (r *Rosters) named(p []byte) (Key, bool) {
	var found Key
	n := 0
	for _, k := range r.Keys {
		if strings.HasPrefix(string(k), string(p)) {
			found = k
			n++
		}
	}
	return found, n == 1
}

func (r *Rosters) roster(owner Key) *Roster {
	if ro, ok := r.Entries.Get(owner); ok {
		return ro
	}
	return &Roster{}
}

// found starts a group: every founder's roster is all founders in ascending order of key.
func (r *Rosters) found(founders []Key) {
	sorted := slices.Clone(founders)
	slices.SortStableFunc(sorted, func(a, b Key) int { return bytes.Compare([]byte(a), []byte(b)) })
	var roster Roster
	for i, k := range sorted {
		roster.Set(i, Entry{Key: &k})
	}
	for _, f := range founders {
		c := roster.Clone()
		r.Entries.Set(f, &c)
		r.learn(f)
	}
}

// resolve is who owner numbered index, following where rosters began, if this member can tell.
func (r *Rosters) resolve(owner Key, index int) (Key, bool) {
	fuel := r.Started.Len() + 1
	var seen []Key
	for {
		if e, ok := r.roster(owner).Get(index); ok {
			switch {
			case e.Key != nil:
				return *e.Key, true
			case e.Prefix != nil:
				if len(e.Prefix) == 0 {
					return "", false
				}
				return r.named(e.Prefix)
			}
			return "", false
		}
		if fuel == 0 {
			return "", false
		}
		fuel--
		s, ok := r.Started.Get(owner)
		if !ok || index > s.Top || slices.Contains(seen, owner) {
			return "", false
		}
		seen = append(seen, owner)
		owner = s.Introducer
	}
}

func (r *Rosters) indexes(fuel int, seen []Key, owner Key) []int {
	own := r.roster(owner).Keys()
	s, ok := r.Started.Get(owner)
	if fuel == 0 || !ok || slices.Contains(seen, owner) {
		return own
	}
	for _, i := range r.indexes(fuel-1, append(seen, owner), s.Introducer) {
		if i <= s.Top {
			own = append(own, i)
		}
	}
	return own
}

// KnownEntry is an index an owner assigned and to whom, if this member can tell.
type KnownEntry struct {
	Index int
	Key   *Key
}

// known is every index owner is known to have assigned, in ascending order, and to whom.
func (r *Rosters) known(owner Key) []KnownEntry {
	is := r.indexes(r.Started.Len()+1, nil, owner)
	slices.Sort(is)
	is = slices.Compact(is)
	out := make([]KnownEntry, len(is))
	for n, i := range is {
		out[n] = KnownEntry{Index: i}
		if k, ok := r.resolve(owner, i); ok {
			out[n].Key = &k
		}
	}
	return out
}

func (r *Rosters) size(owner Key) int {
	k := r.known(owner)
	if len(k) == 0 {
		return 0
	}
	return k[len(k)-1].Index + 1
}

func (r *Rosters) indexOf(owner, member Key) (int, bool) {
	for _, e := range r.known(owner) {
		if e.Key != nil && *e.Key == member {
			return e.Index, true
		}
	}
	return 0, false
}

// number records that owner numbered index as entry says; an entry already held is kept.
func (r *Rosters) number(owner Key, index int, e Entry) {
	ro, ok := r.Entries.Get(owner)
	if !ok {
		ro = &Roster{}
	}
	ro.SetDefault(index, e)
	r.Entries.Set(owner, ro)
}

// retire forgets member's key, keeping every place it holds, under token. A place named by a
// prefix is member's only if the prefix names no other member known. token stands in a place,
// never among the keys a prefix can name.
func (r *Rosters) retire(member, token Key) {
	renamed := func(k Key) Key {
		if k == member {
			return token
		}
		return k
	}
	var entries ordmap.Map[Key, *Roster]
	for owner, ro := range r.Entries.All {
		var nr Roster
		for i, e := range ro.All {
			hit := e.Key != nil && *e.Key == member
			if !hit && e.Prefix != nil && len(e.Prefix) != 0 {
				n, ok := r.named(e.Prefix)
				hit = ok && n == member
			}
			if hit {
				t := token
				e = Entry{Key: &t}
			}
			nr.Set(i, e)
		}
		entries.Set(owner, &nr)
	}
	if ro, ok := entries.Get(member); ok {
		entries.Delete(member)
		entries.Set(token, ro)
	}
	var started ordmap.Map[Key, Started]
	for o, s := range r.Started.All {
		started.Set(renamed(o), Started{renamed(s.Introducer), s.Top})
	}
	var intros ordmap.Map[At, Key]
	for a, k := range r.Introductions.All {
		intros.Set(At{renamed(a.Introducer), a.Index}, renamed(k))
	}
	keys := slices.DeleteFunc(slices.Clone(r.Keys), func(k Key) bool { return k == member })
	*r = Rosters{Entries: entries, Started: started, Introductions: intros, Keys: keys}
}
