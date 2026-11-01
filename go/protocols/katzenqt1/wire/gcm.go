package wire

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"
)

// A box of a member's stream holds 'F' followed by the CBOR map of one GroupChatMessage, as
// katzenqt's models.py writes it: its fields in declaration order, absent ones left out. A
// message too long for a box goes to a substream of 'C' chunks ending in an 'F' chunk, announced
// in the member's stream by an 'I' chunk carrying the substream's read cap.
//
// Gcm holds what this client reads of a message. The fields between introduction and acks
// (file_upload, who, reply_who, tally) are kept as their CBOR, unread; keys katzenqt does not know
// are dropped, as its decoder drops them.

// CurrentVersion is the newest message version this client reads; it writes no other.
const CurrentVersion = 3

const maxNameChars = 30

const (
	MsgText         = 0
	MsgIntroduction = 1
	MsgFileUpload   = 2
	MsgWho          = 3
	MsgReplyWho     = 4
	MsgControl      = 10
)

// OtherKeys are the fields this client keeps without reading, in the order they are written.
var OtherKeys = []string{"file_upload", "who", "reply_who", "tally"}

// RawField is a field kept as its CBOR.
type RawField struct {
	Key string
	Raw []byte
}

// Gcm is a GroupChatMessage. A nil byte slice is an absent field; a non-nil empty one is present
// and empty.
type Gcm struct {
	Version        uint64
	MembershipHash []byte
	MsgType        uint64
	Text           *string
	Introduction   *Introduction
	Other          []RawField
	Acks           []byte
	Numbers        []byte
	IntroducedAt   []byte
}

func (g *Gcm) Encode() []byte {
	n := 3 + len(g.Other)
	for _, present := range []bool{g.Text != nil, g.Introduction != nil, g.Acks != nil, g.Numbers != nil, g.IntroducedAt != nil} {
		if present {
			n++
		}
	}
	out := appendHeader(nil, 5, uint64(n))
	out = appendUint(appendText(out, "version"), g.Version)
	out = appendBytes(appendText(out, "membership_hash"), g.MembershipHash)
	out = appendUint(appendText(out, "msg_type"), g.MsgType)
	if g.Text != nil {
		out = appendText(appendText(out, "text"), *g.Text)
	}
	if i := g.Introduction; i != nil {
		out = appendHeader(appendText(out, "introduction"), 5, 2)
		out = appendText(appendText(out, "display_name"), i.Name)
		out = appendBytes(appendText(out, "read_cap"), i.ReadCap)
	}
	for _, o := range g.Other {
		out = append(appendText(out, o.Key), o.Raw...)
	}
	if g.Acks != nil {
		out = appendBytes(appendText(out, "acks"), g.Acks)
	}
	if g.Numbers != nil {
		out = appendBytes(appendText(out, "numbers"), g.Numbers)
	}
	if g.IntroducedAt != nil {
		out = appendBytes(appendText(out, "introduced_at"), g.IntroducedAt)
	}
	return out
}

// readIntro reads an introduction katzenqt accepts: a name of 1 to 30 characters and a whole read
// cap.
func readIntro(l []byte) (*Introduction, []byte, bool) {
	major, n, l, ok := readHeader(l)
	if !ok || major != 5 {
		return nil, nil, false
	}
	var name *string
	var readCap []byte
	for ; n > 0; n-- {
		var k string
		if k, l, ok = readText(l); !ok {
			return nil, nil, false
		}
		switch k {
		case "display_name":
			var s string
			if s, l, ok = readText(l); !ok {
				return nil, nil, false
			}
			name = &s
		case "read_cap":
			if readCap, l, ok = readBytes(l); !ok {
				return nil, nil, false
			}
		default:
			if l, ok = skipItems(len(l)+1, 1, l); !ok {
				return nil, nil, false
			}
		}
	}
	if name == nil || readCap == nil {
		return nil, nil, false
	}
	chars := utf8.RuneCountInString(*name)
	if chars < 1 || chars > maxNameChars || len(readCap) != ReadCapSize {
		return nil, nil, false
	}
	return &Introduction{Name: *name, ReadCap: readCap}, l, true
}

type gcmAcc struct {
	version, hash, msgType bool
	g                      Gcm
}

func (a *gcmAcc) other(k string) (int, bool) {
	for i, o := range a.g.Other {
		if o.Key == k {
			return i, true
		}
	}
	return 0, false
}

// readField takes in one map entry; a repeated key keeps its last value, as a Python dict does,
// and null counts as absent.
func (a *gcmAcc) readField(l []byte) ([]byte, bool) {
	k, l, ok := readText(l)
	if !ok {
		return nil, false
	}
	null := isNull(l)
	switch k {
	case "version":
		var n uint64
		if n, l, ok = readUint(l); ok {
			a.version, a.g.Version = true, n
		}
		return l, ok
	case "membership_hash":
		var b []byte
		if b, l, ok = readBytes(l); ok {
			a.hash, a.g.MembershipHash = true, b
		}
		return l, ok
	}
	if null && (k == "msg_type" || k == "text" || k == "introduction" || k == "acks" ||
		k == "numbers" || k == "introduced_at" || isOther(k)) {
		return l[1:], true
	}
	switch k {
	case "msg_type":
		var n uint64
		if n, l, ok = readUint(l); ok {
			a.msgType, a.g.MsgType = true, n
		}
	case "text":
		var s string
		if s, l, ok = readText(l); ok {
			a.g.Text = &s
		}
	case "introduction":
		var i *Introduction
		if i, l, ok = readIntro(l); ok {
			a.g.Introduction = i
		}
	case "acks":
		a.g.Acks, l, ok = readBytes(l)
	case "numbers":
		a.g.Numbers, l, ok = readBytes(l)
	case "introduced_at":
		a.g.IntroducedAt, l, ok = readBytes(l)
	default:
		if isOther(k) {
			var raw []byte
			if raw, l, ok = readRaw(l); ok {
				if i, found := a.other(k); found {
					a.g.Other = append(a.g.Other[:i], a.g.Other[i+1:]...)
				}
				a.g.Other = append(a.g.Other, RawField{k, raw})
			}
		} else {
			l, ok = skipItems(len(l)+1, 1, l)
		}
	}
	return l, ok
}

func isOther(k string) bool {
	for _, o := range OtherKeys {
		if o == k {
			return true
		}
	}
	return false
}

// inferType is the type of a message written before msg_type was, from the field it carries.
func (a *gcmAcc) inferType() uint64 {
	if a.g.Introduction != nil {
		return MsgIntroduction
	}
	for _, t := range []struct {
		k string
		t uint64
	}{{"file_upload", MsgFileUpload}, {"who", MsgWho}, {"reply_who", MsgReplyWho}} {
		if _, ok := a.other(t.k); ok {
			return t.t
		}
	}
	return MsgText
}

// DecodeGcm reads the message a CBOR map holds, or returns nil when katzenqt would refuse it.
// What follows the map is ignored, as cbor2.loads ignores it.
func DecodeGcm(b []byte) *Gcm {
	major, n, l, ok := readHeader(b)
	if !ok || major != 5 {
		return nil
	}
	var a gcmAcc
	for ; n > 0; n-- {
		if l, ok = a.readField(l); !ok {
			return nil
		}
	}
	if !a.version || !a.hash {
		return nil
	}
	if !a.msgType {
		a.g.MsgType = a.inferType()
	}
	if a.g.Version > CurrentVersion || len(a.g.MembershipHash) != HashSize || a.g.MsgType > MsgControl {
		return nil
	}
	var other []RawField
	for _, k := range OtherKeys {
		if i, found := a.other(k); found {
			other = append(other, a.g.Other[i])
		}
	}
	a.g.Other = other
	return &a.g
}

// Chunk is what a box of a stream holds.
type Chunk struct {
	Kind ChunkKind
	// Data is the CBOR of a final chunk, the part of a continued one, or the read cap of an
	// indirection.
	Data []byte
	// Total is how many chunks an indirection's substream holds, when the writer said.
	Total *uint32
}

type ChunkKind int

const (
	ChunkUnknown ChunkKind = iota
	// ChunkFinal is the last or only chunk of a message.
	ChunkFinal
	// ChunkContinued is a chunk of a message that continues in the next box.
	ChunkContinued
	// ChunkIndirection says where a long message is.
	ChunkIndirection
)

func Frame(cbor []byte) []byte { return append([]byte{'F'}, cbor...) }

func Unframe(box []byte) Chunk {
	if len(box) == 0 {
		return Chunk{}
	}
	rest := box[1:]
	switch box[0] {
	case 'F':
		return Chunk{Kind: ChunkFinal, Data: rest}
	case 'C':
		return Chunk{Kind: ChunkContinued, Data: rest}
	case 'I':
		switch len(rest) {
		case 4 + ReadCapSize:
			total := binary.BigEndian.Uint32(rest)
			return Chunk{Kind: ChunkIndirection, Data: rest[4:], Total: &total}
		case ReadCapSize:
			return Chunk{Kind: ChunkIndirection, Data: rest}
		}
	}
	return Chunk{}
}

// Sentinel is the hash a control message or an introduction carries in place of the membership
// hash.
var Sentinel = make([]byte, HashSize)

// oldSentinel is the one older clients send.
var oldSentinel = []byte("TODOTODOTODOTODOTODOTODOTODOTODO")

// IsSentinel is whether h says no membership hash.
func IsSentinel(h []byte) bool { return bytes.Equal(h, Sentinel) || bytes.Equal(h, oldSentinel) }

func (g *Gcm) isControl() bool { return g.MsgType == MsgControl || g.MsgType == MsgIntroduction }

// ToMessage is what a member reads of a message's CBOR, or nil when it is not a message. As
// katzenqt's GcmCodec, a content message's whole CBOR travels as its content.
func ToMessage(cbor []byte) *Message {
	g := DecodeGcm(cbor)
	if g == nil {
		return nil
	}
	m := &Message{
		Numbers:      DecodeNumbers(g.Numbers),
		IntroducedAt: DecodeIntroducedAt(g.IntroducedAt),
	}
	if !g.isControl() {
		m.Content = bytes.Clone(cbor)
	}
	if g.MsgType == MsgIntroduction {
		m.Introduction = g.Introduction
	}
	if g.isControl() && !IsSentinel(g.MembershipHash) {
		m.MembershipHash = bytes.Clone(g.MembershipHash)
	}
	m.Acks, _ = DecodeAcks(g.Acks)
	return m
}

func nonEmpty(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

// OfMessage is the message whose CBOR a member's m is written as; nil when its content is not a
// message. Control messages and introductions are written afresh.
func OfMessage(m *Message) *Gcm {
	var g *Gcm
	switch {
	case m.Content != nil:
		if g = DecodeGcm(m.Content); g == nil {
			return nil
		}
	case m.Introduction != nil:
		g = &Gcm{Version: CurrentVersion, MembershipHash: stamped(m), MsgType: MsgIntroduction, Introduction: m.Introduction}
	default:
		g = &Gcm{Version: CurrentVersion, MembershipHash: stamped(m), MsgType: MsgControl}
	}
	g.Acks = nonEmpty(EncodeAcks(m.Acks))
	g.Numbers = nonEmpty(EncodeNumbers(m.Numbers))
	g.IntroducedAt = nil
	if m.IntroducedAt != nil {
		g.IntroducedAt = EncodeIntroducedAt(*m.IntroducedAt)
	}
	return g
}

func stamped(m *Message) []byte {
	if m.MembershipHash != nil {
		return m.MembershipHash
	}
	return Sentinel
}

// Box is the box for a member's m.
func Box(m *Message) []byte {
	g := OfMessage(m)
	if g == nil {
		return nil
	}
	return Frame(g.Encode())
}

// TextContent is a text message, as a member's content.
func TextContent(membershipHash []byte, s string) []byte {
	g := Gcm{Version: CurrentVersion, MembershipHash: membershipHash, MsgType: MsgText, Text: &s}
	return g.Encode()
}
