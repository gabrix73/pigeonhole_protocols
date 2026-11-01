package wire

import (
	"bytes"
	"unicode/utf8"
)

// The reply to a new member: what an introducer seals into a contact voucher's reply, as
// katzenqt's GroupChatReplyWho. Its roster in order, each member as a display name and a read cap
// starting where the new member is to start reading, then the rest of a JoinReply, each member
// written as its place in that list.

// Member is a member's read cap and the index the new member starts reading it at.
type Member struct {
	ReadCap []byte
	Start   []byte
}

// RosterEntry is a roster index and the place of the member at it, nil when unknown.
type RosterEntry struct {
	Index int
	Place *int
}

// Roster is a member's roster as its entries.
type Roster struct {
	Entries []RosterEntry
}

// IntroAt is an Introduction a new member is told of: the introducer's place, its box and the
// introduced member's place.
type IntroAt struct {
	By     int
	Index  []byte
	Member int
}

// JoinReply is what an introducer hands a new member. Members are named by their place in
// Members, the introducer's roster; the new member takes place Newcomer. A nil member is a slot
// not filled, a nil roster one unknown.
type JoinReply struct {
	Members       []*Member
	Rosters       []*Roster
	Introductions []IntroAt
	Introducer    int
	Newcomer      int
}

type PleaseAdd struct {
	Name    string
	ReadCap []byte
}

type ReplyWho struct {
	PleaseAdds    []*PleaseAdd
	Rosters       []*Roster
	HasRosters    bool
	Introductions []IntroAt
	HasIntros     bool
	Introducer    *int
	Newcomer      *int
}

// OfJoinReply is the reply for r, naming each member by name; a member with no name takes no
// place, as katzenqt leaves out a member it does not know.
func OfJoinReply(r *JoinReply, name func(key []byte) (string, bool)) *ReplyWho {
	w := &ReplyWho{
		Rosters: r.Rosters, HasRosters: true,
		Introductions: r.Introductions, HasIntros: true,
		Introducer: &r.Introducer, Newcomer: &r.Newcomer,
	}
	for _, m := range r.Members {
		var p *PleaseAdd
		if m != nil {
			key := KeyOf(m.ReadCap)
			if n, ok := name(key); ok {
				p = &PleaseAdd{Name: n, ReadCap: append(bytes.Clone(key), m.Start...)}
			}
		}
		w.PleaseAdds = append(w.PleaseAdds, p)
	}
	return w
}

// ToJoinReply is the JoinReply a reply carries, or nil when it carries no rosters or cannot be
// read.
func (w *ReplyWho) ToJoinReply() *JoinReply {
	places := len(w.PleaseAdds)
	if !w.HasRosters || w.Introducer == nil || w.Newcomer == nil {
		return nil
	}
	introducer, newcomer := *w.Introducer, *w.Newcomer
	if newcomer != places || !(introducer < places && places < RosterMax) {
		return nil
	}
	if w.PleaseAdds[introducer] == nil || len(w.Rosters) != places {
		return nil
	}
	seen := map[string]bool{}
	for _, p := range w.PleaseAdds {
		if p == nil {
			continue
		}
		k := string(KeyOf(p.ReadCap))
		if seen[k] {
			return nil
		}
		seen[k] = true
	}
	for _, r := range w.Rosters {
		if r == nil {
			continue
		}
		for _, e := range r.Entries {
			if e.Index >= RosterMax || e.Place != nil && *e.Place >= places {
				return nil
			}
		}
	}
	r := &JoinReply{Rosters: w.Rosters, Introducer: introducer, Newcomer: newcomer}
	for _, i := range w.Introductions {
		if i.By < places && i.Member < places && len(i.Index) == IndexSize {
			r.Introductions = append(r.Introductions, i)
		}
	}
	for _, p := range w.PleaseAdds {
		var m *Member
		if p != nil {
			m = &Member{ReadCap: p.ReadCap, Start: StartOf(p.ReadCap)}
		}
		r.Members = append(r.Members, m)
	}
	return r
}

// WithoutRosters is the JoinReply of a reply that carries no rosters, as katzenqt sends for a
// conversation that keeps none: the members it names, the introducer first, with every roster
// unknown. It is nil when the reply carries rosters or cannot be read.
func (w *ReplyWho) WithoutRosters() *JoinReply {
	if w.HasRosters {
		return nil
	}
	r := &JoinReply{}
	seen := map[string]bool{}
	for _, p := range w.PleaseAdds {
		if p == nil {
			continue
		}
		k := string(KeyOf(p.ReadCap))
		if seen[k] {
			return nil
		}
		seen[k] = true
		r.Members = append(r.Members, &Member{ReadCap: p.ReadCap, Start: StartOf(p.ReadCap)})
	}
	places := len(r.Members)
	if places < 1 || places >= RosterMax {
		return nil
	}
	r.Rosters = make([]*Roster, places)
	r.Newcomer = places
	return r
}

func (w *ReplyWho) term() term {
	t := term{kind: termMap}
	add := func(k string, v term) {
		t.keys = append(t.keys, term{kind: termText, text: k})
		t.list = append(t.list, v)
	}
	pas := term{kind: termList}
	for _, p := range w.PleaseAdds {
		if p == nil {
			pas.list = append(pas.list, term{kind: termNull})
			continue
		}
		pas.list = append(pas.list, term{kind: termMap,
			keys: []term{{kind: termText, text: "display_name"}, {kind: termText, text: "read_cap"}},
			list: []term{{kind: termText, text: p.Name}, {kind: termBytes, bytes: p.ReadCap}}})
	}
	add("please_adds", pas)
	if w.HasRosters {
		rs := term{kind: termList}
		for _, r := range w.Rosters {
			if r == nil {
				rs.list = append(rs.list, term{kind: termNull})
				continue
			}
			rt := term{kind: termList, list: []term{}}
			for _, e := range r.Entries {
				slot := term{kind: termNull}
				if e.Place != nil {
					slot = natTerm(*e.Place)
				}
				rt.list = append(rt.list, term{kind: termList, list: []term{natTerm(e.Index), slot}})
			}
			rs.list = append(rs.list, rt)
		}
		add("rosters", rs)
	}
	if w.HasIntros {
		is := term{kind: termList}
		for _, i := range w.Introductions {
			is.list = append(is.list, term{kind: termList,
				list: []term{natTerm(i.By), {kind: termBytes, bytes: i.Index}, natTerm(i.Member)}})
		}
		add("introductions", is)
	}
	if w.Introducer != nil {
		add("introducer", natTerm(*w.Introducer))
	}
	if w.Newcomer != nil {
		add("newcomer", natTerm(*w.Newcomer))
	}
	return t
}

func (w *ReplyWho) Encode() []byte { return w.term().encode(nil) }

func readPleaseAdd(t term) (*PleaseAdd, bool) {
	if t.kind != termMap {
		return nil, false
	}
	n, ok1 := t.field("display_name")
	c, ok2 := t.field("read_cap")
	if !ok1 || !ok2 || n.kind != termText || c.kind != termBytes {
		return nil, false
	}
	chars := utf8.RuneCountInString(n.text)
	if chars < 1 || chars > maxNameChars || len(c.bytes) != ReadCapSize {
		return nil, false
	}
	return &PleaseAdd{Name: n.text, ReadCap: c.bytes}, true
}

func readRoster(t term) (*Roster, bool) {
	if t.kind != termList {
		return nil, false
	}
	r := &Roster{Entries: []RosterEntry{}}
	for _, e := range t.list {
		if e.kind != termList || len(e.list) != 2 {
			return nil, false
		}
		i, ok := e.list[0].nat()
		if !ok {
			return nil, false
		}
		var place *int
		if !e.list[1].isNull() {
			p, ok := e.list[1].nat()
			if !ok {
				return nil, false
			}
			place = &p
		}
		r.Entries = append(r.Entries, RosterEntry{Index: i, Place: place})
	}
	return r, true
}

// optNat reads a value that may be absent or null.
func optNat(t term, present bool) (*int, bool) {
	if !present || t.isNull() {
		return nil, true
	}
	n, ok := t.nat()
	if !ok {
		return nil, false
	}
	return &n, true
}

func DecodeReplyWho(b []byte) *ReplyWho {
	t, ok := decodeTerm(b)
	if !ok || t.kind != termMap {
		return nil
	}
	w := &ReplyWho{}
	pas, ok := t.field("please_adds")
	if !ok || pas.kind != termList {
		return nil
	}
	for _, e := range pas.list {
		if e.isNull() {
			w.PleaseAdds = append(w.PleaseAdds, nil)
			continue
		}
		p, ok := readPleaseAdd(e)
		if !ok {
			return nil
		}
		w.PleaseAdds = append(w.PleaseAdds, p)
	}
	if rs, ok := t.field("rosters"); ok && !rs.isNull() {
		if rs.kind != termList {
			return nil
		}
		w.HasRosters = true
		for _, e := range rs.list {
			if e.isNull() {
				w.Rosters = append(w.Rosters, nil)
				continue
			}
			r, ok := readRoster(e)
			if !ok {
				return nil
			}
			w.Rosters = append(w.Rosters, r)
		}
	}
	if is, ok := t.field("introductions"); ok && !is.isNull() {
		if is.kind != termList {
			return nil
		}
		w.HasIntros = true
		for _, e := range is.list {
			if e.kind != termList || len(e.list) != 3 || e.list[1].kind != termBytes {
				return nil
			}
			by, ok1 := e.list[0].nat()
			m, ok2 := e.list[2].nat()
			if !ok1 || !ok2 {
				return nil
			}
			w.Introductions = append(w.Introductions, IntroAt{By: by, Index: e.list[1].bytes, Member: m})
		}
	}
	var ok1, ok2 bool
	v, present := t.field("introducer")
	if w.Introducer, ok1 = optNat(v, present); !ok1 {
		return nil
	}
	v, present = t.field("newcomer")
	if w.Newcomer, ok2 = optNat(v, present); !ok2 {
		return nil
	}
	return w
}
