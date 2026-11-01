// Package wire holds katzenqt1's wire formats: the fields of a group chat message, the
// GroupChatMessage CBOR and its box framing, the reply to a new member and the membership hash.
package wire

import (
	"bytes"
	"encoding/binary"
)

const (
	KeySize     = 32
	IndexSize   = 104
	ReadCapSize = 136
	HashSize    = 32
	// RosterMax is the most entries a roster holds: roster indexes are one byte.
	RosterMax = 256
	// PrefixSize is how much of a member's key a Numbers field names it by.
	PrefixSize = 8
)

// KeyOf is a member's identity: the public key its read cap begins with.
func KeyOf(readCap []byte) []byte { return readCap[:min(KeySize, len(readCap))] }

func PrefixOf(key []byte) []byte { return key[:min(PrefixSize, len(key))] }

// StartOf is the index a read cap starts at.
func StartOf(readCap []byte) []byte { return readCap[min(KeySize, len(readCap)):] }

// Counter is the BACAP Idx64 of an index: its first 8 bytes, little-endian.
func Counter(index []byte) uint64 {
	var b [8]byte
	copy(b[:], index)
	return binary.LittleEndian.Uint64(b[:])
}

// IntroRef names an Introduction: its introducer's roster index in the sender's roster, and its
// box.
type IntroRef struct {
	Introducer int
	Index      []byte
}

type Introduction struct {
	Name    string
	ReadCap []byte
}

// Number assigns a roster index to the member whose key starts with Prefix; a nil Prefix is the
// member the message's own Introduction introduces.
type Number struct {
	Index  int
	Prefix []byte
}

// Ack acknowledges the box with Idx64 of the member at roster index Member.
type Ack struct {
	Member int
	Idx64  uint64
}

// Message is what a member reads of a message. It carries content or control, never both; Acks
// are in ascending order of roster index. A message the member makes itself carries the
// membership hash it was composed with, so that a rewrite writes the same box; content carries
// its own.
type Message struct {
	Content        []byte
	Introduction   *Introduction
	Numbers        []Number
	IntroducedAt   *IntroRef
	Acks           []Ack
	MembershipHash []byte
}

func (m *Message) Equal(o *Message) bool {
	if m == nil || o == nil {
		return m == o
	}
	if (m.Content == nil) != (o.Content == nil) || !bytes.Equal(m.Content, o.Content) {
		return false
	}
	if (m.Introduction == nil) != (o.Introduction == nil) ||
		m.Introduction != nil && (m.Introduction.Name != o.Introduction.Name ||
			!bytes.Equal(m.Introduction.ReadCap, o.Introduction.ReadCap)) {
		return false
	}
	if len(m.Numbers) != len(o.Numbers) {
		return false
	}
	for i, n := range m.Numbers {
		p := o.Numbers[i]
		if n.Index != p.Index || (n.Prefix == nil) != (p.Prefix == nil) || !bytes.Equal(n.Prefix, p.Prefix) {
			return false
		}
	}
	if (m.IntroducedAt == nil) != (o.IntroducedAt == nil) ||
		m.IntroducedAt != nil && (m.IntroducedAt.Introducer != o.IntroducedAt.Introducer ||
			!bytes.Equal(m.IntroducedAt.Index, o.IntroducedAt.Index)) {
		return false
	}
	if len(m.Acks) != len(o.Acks) {
		return false
	}
	for i, a := range m.Acks {
		if a != o.Acks[i] {
			return false
		}
	}
	return (m.MembershipHash == nil) == (o.MembershipHash == nil) &&
		bytes.Equal(m.MembershipHash, o.MembershipHash)
}

// EncodeNumbers writes the first index assigned, then the key prefix of each member, one per
// consecutive index; a lone byte for the member an Introduction introduces.
func EncodeNumbers(ns []Number) []byte {
	switch {
	case len(ns) == 0:
		return nil
	case len(ns) == 1 && ns[0].Prefix == nil:
		return []byte{byte(ns[0].Index)}
	}
	out := []byte{byte(ns[0].Index)}
	for _, n := range ns {
		out = append(out, n.Prefix...)
	}
	return out
}

// DecodeNumbers returns nothing when the field is malformed.
func DecodeNumbers(field []byte) []Number {
	switch len(field) {
	case 0:
		return nil
	case 1:
		return []Number{{Index: int(field[0])}}
	}
	first, rest := int(field[0]), field[1:]
	if len(rest)%PrefixSize != 0 {
		return nil
	}
	n := len(rest) / PrefixSize
	if first+n > RosterMax {
		return nil
	}
	seen := make(map[string]bool, n)
	ns := make([]Number, n)
	for i := range n {
		p := rest[i*PrefixSize : (i+1)*PrefixSize]
		if seen[string(p)] {
			return nil
		}
		seen[string(p)] = true
		ns[i] = Number{Index: first + i, Prefix: bytes.Clone(p)}
	}
	return ns
}

func EncodeIntroducedAt(r IntroRef) []byte {
	return append([]byte{byte(r.Introducer)}, r.Index...)
}

func DecodeIntroducedAt(field []byte) *IntroRef {
	if len(field) != 1+IndexSize {
		return nil
	}
	return &IntroRef{Introducer: int(field[0]), Index: bytes.Clone(field[1:])}
}
