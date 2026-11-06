package wire

import (
	"bytes"
	"encoding/binary"
	"unicode/utf8"
)

// A box of a member's stream holds 'F' followed by the CBOR of one GroupChatMessage: since
// version 4 the array [version, membership_hash, msg_type, body, acks, numbers, introduced_at]
// with trailing nulls left out; up to version 3 the map katzenqt's models.py writes, its fields
// in declaration order, absent ones left out. The first byte's major type tells the forms apart.
// A ping, msg_type 11, is content with a null body: [4, membership_hash, 11, null] and, as for
// any message, acks and the rest after it. Its readers play their ping sound. A reader refuses
// a type it does not know; the engine then tells the user who sent it, its type and version.
// Version 5 adds MsgPacked, several text messages in one box, the texts' array as body.
// A message too long for a box goes to a substream of 'C' chunks ending in an 'F' chunk, announced
// in the member's stream by an 'I' chunk carrying the substream's read cap.
//
// Gcm holds what this client reads of a message. The bodies it does not read (file_upload, who,
// reply_who, tally) are kept as their CBOR in the map form's shape, under the map form's key;
// keys katzenqt does not know are dropped, as its decoder drops them.

// CurrentVersion is the version written. ArrayVersion is the first of the array form; MapVersion,
// the map form, is read as well and written for a Gcm whose Version is below ArrayVersion. A
// reader refuses a version above CurrentVersion: see Unsupported.
const (
	CurrentVersion = 5
	ArrayVersion   = 4
	MapVersion     = 3
)

// PackedVersion is the first version with MsgPacked.
const PackedVersion = 5

const maxNameChars = 30

const (
	MsgText         = 0
	MsgIntroduction = 1
	MsgFileUpload   = 2
	MsgWho          = 3
	MsgReplyWho     = 4
	MsgControl      = 10
	// MsgPing asks its readers to play their ping sound. It is content with a null body.
	MsgPing = 11
	// MsgPacked is several text messages in one box, the array of the texts in the order sent
	// as body. A reader of version 4 refuses it as a type it does not know.
	MsgPacked = 12
)

// OtherKeys are the fields this client keeps without reading, in the order they are written.
var OtherKeys = []string{"file_upload", "who", "reply_who", "tally"}

// RawField is a field kept as its CBOR.
type RawField struct {
	Key string
	Raw []byte
}

// bodyKey is the field a message type's body is in the map form and in Other; "" for a type
// whose body is read.
func bodyKey(msgType uint64) string {
	switch {
	case msgType == MsgFileUpload:
		return "file_upload"
	case msgType == MsgWho:
		return "who"
	case msgType == MsgReplyWho:
		return "reply_who"
	case msgType > MsgReplyWho && msgType < MsgControl:
		return "tally"
	}
	return ""
}

// Gcm is a GroupChatMessage. A nil byte slice is an absent field; a non-nil empty one is present
// and empty.
type Gcm struct {
	Version        uint64
	MembershipHash []byte
	MsgType        uint64
	Text           *string
	// Texts is a packed message's.
	Texts        []string
	Introduction *Introduction
	Other        []RawField
	Acks         []byte
	Numbers      []byte
	IntroducedAt []byte
}

func (g *Gcm) other(k string) (int, bool) {
	for i, o := range g.Other {
		if o.Key == k {
			return i, true
		}
	}
	return 0, false
}

func (g *Gcm) Encode() []byte {
	if g.Version < ArrayVersion {
		return g.encodeMap()
	}
	tail := [][]byte{g.Acks, g.Numbers, g.IntroducedAt}
	n := len(tail)
	for n > 0 && tail[n-1] == nil {
		n--
	}
	out := appendHeader(nil, 4, uint64(4+n))
	out = appendUint(out, g.Version)
	out = appendBytes(out, g.MembershipHash)
	out = g.appendBody(appendUint(out, g.MsgType))
	for _, f := range tail[:n] {
		if f == nil {
			out = appendNull(out)
		} else {
			out = appendBytes(out, f)
		}
	}
	return out
}

// appendBody writes the type's payload in the array form: the text, [display_name, read_cap],
// [payload, filetype, basename], the app's value as it was kept, or null.
func (g *Gcm) appendBody(out []byte) []byte {
	switch g.MsgType {
	case MsgPacked:
		out = appendHeader(out, 4, uint64(len(g.Texts)))
		for _, t := range g.Texts {
			out = appendText(out, t)
		}
		return out
	case MsgText:
		if g.Text != nil {
			return appendText(out, *g.Text)
		}
		return appendText(out, "")
	case MsgIntroduction:
		if i := g.Introduction; i != nil {
			return appendBytes(appendText(appendHeader(out, 4, 2), i.Name), i.ReadCap)
		}
		return appendNull(out)
	}
	i, ok := g.other(bodyKey(g.MsgType))
	if !ok {
		return appendNull(out)
	}
	raw := g.Other[i].Raw
	if g.MsgType == MsgFileUpload {
		if f, ok := decodeUpload(raw); ok {
			return appendText(appendText(appendBytes(appendHeader(out, 4, 3), f.Payload), f.Filetype), f.Basename)
		}
	}
	return append(out, raw...)
}

// encodeMap writes the map form.
func (g *Gcm) encodeMap() []byte {
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

// newIntro is an introduction katzenqt accepts: a name of 1 to 30 characters and a whole read
// cap.
func newIntro(name string, readCap []byte) (*Introduction, bool) {
	chars := utf8.RuneCountInString(name)
	if chars < 1 || chars > maxNameChars || len(readCap) != ReadCapSize {
		return nil, false
	}
	return &Introduction{Name: name, ReadCap: readCap}, true
}

// readIntro reads the map form's introduction.
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
	i, ok := newIntro(*name, readCap)
	return i, l, ok
}

type gcmAcc struct {
	version, hash, msgType bool
	g                      Gcm
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
				if i, found := a.g.other(k); found {
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
		if _, ok := a.g.other(t.k); ok {
			return t.t
		}
	}
	return MsgText
}

// DecodeGcm reads the message a box's CBOR holds, in either form, or returns nil when it is
// refused. What follows the item is ignored, as cbor2.loads ignores it.
func DecodeGcm(b []byte) *Gcm {
	major, n, l, ok := readHeader(b)
	switch {
	case !ok:
		return nil
	case major == 4:
		return decodeArray(n, l)
	case major != 5:
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
	if a.g.Version > MapVersion || len(a.g.MembershipHash) != HashSize || a.g.MsgType > MsgPing {
		return nil
	}
	var other []RawField
	for _, k := range OtherKeys {
		if i, found := a.g.other(k); found {
			other = append(other, a.g.Other[i])
		}
	}
	a.g.Other = other
	return &a.g
}

// decodeArray reads the array form, given its length and what follows its header: 4 to 7
// elements, a version from ArrayVersion to CurrentVersion, and acks, numbers and introduced_at each a
// byte string or null.
func decodeArray(n uint64, l []byte) *Gcm {
	if n < 4 || n > 7 {
		return nil
	}
	g := &Gcm{}
	var ok bool
	if g.Version, l, ok = readUint(l); !ok || g.Version < ArrayVersion || g.Version > CurrentVersion {
		return nil
	}
	if g.MembershipHash, l, ok = readBytes(l); !ok || len(g.MembershipHash) != HashSize {
		return nil
	}
	if g.MsgType, l, ok = readUint(l); !ok || !knownType(g.MsgType, g.Version) {
		return nil
	}
	if l, ok = g.readBody(l); !ok {
		return nil
	}
	for _, f := range []*[]byte{&g.Acks, &g.Numbers, &g.IntroducedAt}[:n-4] {
		if isNull(l) {
			l = l[1:]
			continue
		}
		if *f, l, ok = readBytes(l); !ok {
			return nil
		}
	}
	return g
}

// readBody reads the array form's body for g's type; see appendBody. A file upload is kept in
// the map form's shape, so that files.go reads it either way.
func (g *Gcm) readBody(l []byte) ([]byte, bool) {
	var ok bool
	switch g.MsgType {
	case MsgPacked:
		major, n, l, ok := readHeader(l)
		if !ok || major != 4 || n == 0 || n > uint64(len(l)) {
			return nil, false
		}
		for ; n > 0; n-- {
			var s string
			if s, l, ok = readText(l); !ok {
				return nil, false
			}
			g.Texts = append(g.Texts, s)
		}
		return l, true
	case MsgText:
		var s string
		if s, l, ok = readText(l); !ok {
			return nil, false
		}
		g.Text = &s
		return l, true
	case MsgIntroduction:
		major, n, l, ok := readHeader(l)
		if !ok || major != 4 || n != 2 {
			return nil, false
		}
		var name string
		var readCap []byte
		if name, l, ok = readText(l); !ok {
			return nil, false
		}
		if readCap, l, ok = readBytes(l); !ok {
			return nil, false
		}
		if g.Introduction, ok = newIntro(name, readCap); !ok {
			return nil, false
		}
		return l, true
	case MsgFileUpload:
		major, n, l, ok := readHeader(l)
		if !ok || major != 4 || n != 3 {
			return nil, false
		}
		var f FileUpload
		if f.Payload, l, ok = readBytes(l); !ok {
			return nil, false
		}
		if f.Filetype, l, ok = readText(l); !ok {
			return nil, false
		}
		if f.Basename, l, ok = readText(l); !ok {
			return nil, false
		}
		g.Other = []RawField{{"file_upload", encodeUpload(f)}}
		return l, true
	case MsgControl, MsgPing:
		if !isNull(l) {
			return nil, false
		}
		return l[1:], true
	}
	if isNull(l) {
		return l[1:], true
	}
	var raw []byte
	if raw, l, ok = readRaw(l); !ok {
		return nil, false
	}
	g.Other = []RawField{{bodyKey(g.MsgType), raw}}
	return l, true
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
// message. Control messages and introductions are written afresh, in version; content keeps the
// version it carries.
func OfMessage(m *Message, version uint64) *Gcm {
	var g *Gcm
	switch {
	case m.Content != nil:
		if g = DecodeGcm(m.Content); g == nil {
			return nil
		}
	case m.Introduction != nil:
		g = &Gcm{Version: version, MembershipHash: stamped(m), MsgType: MsgIntroduction, Introduction: m.Introduction}
	default:
		g = &Gcm{Version: version, MembershipHash: stamped(m), MsgType: MsgControl}
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

// Box is the box for a member's m, a message made afresh in version.
func Box(m *Message, version uint64) []byte {
	g := OfMessage(m, version)
	if g == nil {
		return nil
	}
	return Frame(g.Encode())
}

// PingContent is a ping in version, as a member's content.
func PingContent(membershipHash []byte, version uint64) []byte {
	g := Gcm{Version: version, MembershipHash: membershipHash, MsgType: MsgPing}
	return g.Encode()
}

// Unsupported says whether the array form cbor, which DecodeGcm refuses, is a message of a newer
// version or of a type this client does not know, and which.
func Unsupported(cbor []byte) (version, msgType uint64, ok bool) {
	major, n, l, ok := readHeader(cbor)
	if !ok || major != 4 || n < 3 {
		return 0, 0, false
	}
	if version, l, ok = readUint(l); !ok {
		return 0, 0, false
	}
	if _, l, ok = readBytes(l); !ok {
		return 0, 0, false
	}
	if msgType, _, ok = readUint(l); !ok {
		return 0, 0, false
	}
	return version, msgType, version > CurrentVersion || !knownType(msgType, version)
}

// knownType says whether this client reads msgType in version.
func knownType(msgType, version uint64) bool {
	return msgType <= MsgPing || msgType == MsgPacked && version >= PackedVersion
}

// TextContent is a text message in version, as a member's content.
func TextContent(membershipHash []byte, s string, version uint64) []byte {
	g := Gcm{Version: version, MembershipHash: membershipHash, MsgType: MsgText, Text: &s}
	return g.Encode()
}

// Pack is a text or packed message's CBOR with text packed in after what it holds; nil when it is
// neither, or of the map form.
func Pack(cbor []byte, text string) []byte {
	g := DecodeGcm(cbor)
	if g == nil || g.Version < ArrayVersion || g.MsgType != MsgText && g.MsgType != MsgPacked {
		return nil
	}
	if g.MsgType == MsgText {
		g.Version, g.MsgType, g.Texts, g.Text = max(g.Version, PackedVersion), MsgPacked, []string{*g.Text}, nil
	}
	g.Texts = append(g.Texts, text)
	return g.Encode()
}
