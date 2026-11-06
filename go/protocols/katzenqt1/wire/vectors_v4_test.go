package wire

import (
	"bytes"
	"reflect"
	"testing"
)

func TestWireVectorsV4(t *testing.T) {
	v := load(t, "groupchat_wire_vectors_v4.json")
	count := 0
	for _, e := range v["messages"].([]any) {
		e := e.(map[string]any)
		name := e["name"].(string)
		cbor := unhex(t, e["cbor"])
		if cbor[0]>>5 != 4 {
			t.Errorf("%s: not an array", name)
		}
		got := ToMessage(cbor)
		if !reflect.DeepEqual(messageJSON(got), e["message"]) {
			t.Errorf("%s: read as %v, want %v", name, messageJSON(got), e["message"])
			continue
		}
		want := unhex(t, e["rewritten"])
		if g := OfMessage(got, CurrentVersion); g == nil || !bytes.Equal(g.Encode(), want) {
			t.Errorf("%s: written back differently", name)
		}
		if bytes.Equal(want, cbor) {
			if g := DecodeGcm(cbor); g == nil || !bytes.Equal(g.Encode(), cbor) {
				t.Errorf("%s: does not decode and encode to itself", name)
			}
		}
		count++
	}
	for _, e := range v["written"].([]any) {
		e := e.(map[string]any)
		box := Box(readMessage(t, e["message"]), CurrentVersion)
		if !bytes.Equal(box, unhex(t, e["box"])) {
			t.Errorf("%s: written as another box", e["name"])
		}
		if box[0] != 'F' || box[1]>>5 != 4 {
			t.Errorf("%s: not F then an array", e["name"])
		}
		count++
	}
	for _, e := range v["membership"].([]any) {
		e := e.(map[string]any)
		var caps [][]byte
		for _, c := range e["read_caps"].([]any) {
			caps = append(caps, unhex(t, c))
		}
		if !bytes.Equal(MembershipHash(caps), unhex(t, e["hash"])) {
			t.Errorf("membership of %d: a different hash", len(caps))
		}
		count++
	}
	for _, e := range v["replies"].([]any) {
		e := e.(map[string]any)
		name := e["name"].(string)
		w := DecodeReplyWho(unhex(t, e["cbor"]))
		if w == nil {
			t.Errorf("%s: does not decode", name)
			continue
		}
		r, want := w.ToJoinReply(), e["join_reply"]
		if (r == nil) != (want == nil) {
			t.Errorf("%s: carries %v, want %v", name, r, want)
		} else if want != nil {
			want := want.(map[string]any)
			if r.Introducer != intOf(t, want["introducer"]) || r.Newcomer != intOf(t, want["newcomer"]) {
				t.Errorf("%s: places %d %d", name, r.Introducer, r.Newcomer)
			}
		}
		if again := DecodeReplyWho(w.Encode()); !reflect.DeepEqual(again, w) {
			t.Errorf("%s: reads back as %+v", name, again)
		}
		count++
	}
	for _, e := range v["malformed"].([]any) {
		e := e.(map[string]any)
		if g := DecodeGcm(unhex(t, e["cbor"])); g != nil {
			t.Errorf("%s: accepted as %+v", e["name"], g)
		}
		count++
	}
	for _, e := range v["unsupported"].([]any) {
		e := e.(map[string]any)
		ver, typ, ok := Unsupported(unhex(t, e["cbor"]))
		if want := e["version"] != nil; ok != want || ok && (numOf(ver) != e["version"] || numOf(typ) != e["msg_type"]) {
			t.Errorf("%s: unsupported %v, version %d, type %d", e["name"], ok, ver, typ)
		}
		count++
	}
	if count != 17+7+6+5+11+6 {
		t.Errorf("%d vectors", count)
	}
}

var (
	zeroHash = make([]byte, HashSize)
	testCap  = bytes.Repeat([]byte{1}, ReadCapSize)
)

func TestDefaultIsArrayAndMapStillReads(t *testing.T) {
	text := TextContent(zeroHash, "hello", CurrentVersion)
	if text[0]>>5 != 4 || DecodeGcm(text).Version != 4 {
		t.Fatalf("written as %x", text)
	}
	s := "hello"
	m3 := (&Gcm{Version: 3, MembershipHash: zeroHash, Text: &s}).Encode()
	if m3[0]>>5 != 5 || TextOf(m3) != "hello" || TextOf(text) != "hello" {
		t.Fatalf("map form: %x", m3)
	}
	if !bytes.Equal(ToMessage(m3).Content, m3) || !bytes.Equal(ToMessage(text).Content, text) {
		t.Fatal("content")
	}
	if g := DecodeGcm(m3); g.Version != 3 || !bytes.Equal(g.Encode(), m3) {
		t.Fatal("the map form does not write back as itself")
	}
	if len(text) != 38+5 || len((&Gcm{Version: 3, MembershipHash: zeroHash, Text: &s}).Encode()) != 76+5 {
		t.Fatal("sizes against the map form")
	}
}

func TestSizes(t *testing.T) {
	// Array header 1, version 1, hash 2 + 32, type 1 = 37; then the body.
	for _, c := range []struct {
		g    Gcm
		want int
	}{
		{Gcm{Text: new(string)}, 37 + 1},
		{Gcm{Text: ptr(string(bytes.Repeat([]byte{'a'}, 23)))}, 37 + 1 + 23},
		{Gcm{Text: ptr(string(bytes.Repeat([]byte{'a'}, 24)))}, 37 + 2 + 24},
		{Gcm{MsgType: MsgIntroduction, Introduction: &Introduction{Name: "bob", ReadCap: testCap}}, 37 + 1 + (1 + 3) + (2 + 136)},
		{Gcm{MsgType: MsgControl, Acks: make([]byte, 10)}, 37 + 1 + 1 + 10},
		{Gcm{MsgType: MsgControl}, 37 + 1},
	} {
		c.g.Version, c.g.MembershipHash = CurrentVersion, zeroHash
		if got := len(c.g.Encode()); got != c.want {
			t.Errorf("type %d: %d bytes, want %d", c.g.MsgType, got, c.want)
		}
	}
}

func ptr(s string) *string { return &s }

func TestBodiesRoundTrip(t *testing.T) {
	f := FileUpload{Payload: []byte{1, 2}, Filetype: "image/png", Basename: "a.png"}
	content := FileContent(zeroHash, f, CurrentVersion)
	if g := DecodeGcm(content); g == nil || !bytes.Equal(g.Encode(), content) {
		t.Fatal("file upload")
	} else if got, ok := FileOf(g); !ok || !reflect.DeepEqual(got, f) {
		t.Fatalf("file of: %+v", got)
	}
	// Its body is [payload, filetype, basename].
	if want := append([]byte{0x83, 0x42, 1, 2, 0x69}, "image/png\x65a.png"...); !bytes.Equal(content[37:], want) {
		t.Fatalf("body %x", content[37:])
	}
	for _, g := range []*Gcm{
		{MsgType: MsgWho, Other: []RawField{{"who", appendText(nil, "w")}}},
		{MsgType: MsgReplyWho, Other: []RawField{{"reply_who", appendText(nil, "r")}}},
		{MsgType: 5, Other: []RawField{{"tally", appendUint(appendText(appendHeader(nil, 5, 1), "version"), 1)}}},
		{MsgType: 9},
		{MsgType: MsgControl, Numbers: []byte{4}, IntroducedAt: make([]byte, 105)},
		{MsgType: MsgControl, Acks: make([]byte, 10)},
	} {
		g.Version, g.MembershipHash = CurrentVersion, zeroHash
		b := g.Encode()
		if back := DecodeGcm(b); !reflect.DeepEqual(back, g) {
			t.Errorf("type %d: back as %+v", g.MsgType, back)
		}
	}
	// A control with numbers and introduced_at carries a null in acks' place; one with acks only
	// stops there.
	if b := (&Gcm{Version: 4, MembershipHash: zeroHash, MsgType: MsgControl, Numbers: []byte{4}}).Encode(); b[0] != 0x86 || !bytes.Equal(b[37:], []byte{0xf6, 0xf6, 0x41, 4}) {
		t.Errorf("control with numbers: %x", b)
	}
	if b := (&Gcm{Version: 4, MembershipHash: zeroHash, MsgType: MsgControl, Acks: []byte{0}}).Encode(); b[0] != 0x85 || !bytes.Equal(b[37:], []byte{0xf6, 0x41, 0}) {
		t.Errorf("control with acks: %x", b)
	}
}

func TestReplyWhoArrayForms(t *testing.T) {
	one := (&ReplyWho{PleaseAdds: []*PleaseAdd{{Name: "alice", ReadCap: testCap}}}).Encode()
	if want := append([]byte{0x81, 0x81, 0x82, 0x65, 'a', 'l', 'i', 'c', 'e', 0x58, 0x88}, testCap...); !bytes.Equal(one, want) {
		t.Fatalf("one: %x", one)
	}
	w := DecodeReplyWho(one)
	if w == nil || w.HasRosters || w.WithoutRosters() == nil {
		t.Fatalf("one reads as %+v", w)
	}
	zero, two := 0, 2
	full := &ReplyWho{
		PleaseAdds: []*PleaseAdd{{Name: "alice", ReadCap: testCap}, nil},
		Rosters:    []*Roster{{Entries: []RosterEntry{{Index: 0, Place: &zero}, {Index: 1}}}, nil}, HasRosters: true,
		Introductions: []IntroAt{{By: 0, Index: make([]byte, IndexSize), Member: 1}}, HasIntros: true,
		Introducer: &zero, Newcomer: &two,
	}
	for _, b := range [][]byte{full.Encode(), full.EncodeMap()} {
		w := DecodeReplyWho(b)
		if !reflect.DeepEqual(w, full) || w.ToJoinReply() == nil {
			t.Fatalf("full reads as %+v", w)
		}
	}
	if full.Encode()[0] != 0x85 || full.EncodeMap()[0] != 0xa5 {
		t.Fatal("forms")
	}
	for _, bad := range [][]byte{
		{0x80},                        // no elements
		{0x81, 0x81, 0x81, 0x61, 'x'}, // a please_add of one element
		append([]byte{0x81, 0x81, 0x82, 0x61, 'a', 0x58, 0x87}, testCap[1:]...),                // a short read cap
		append(append([]byte{0x82, 0x81, 0x82, 0x61, 'a', 0x58, 0x88}, testCap...), 0x61, 'r'), // rosters not a list
		{0x00},
		append(append([]byte{0x81, 0x81, 0xa2, 0x6c}, "display_name\x61a\x68read_cap\x58\x88"...), testCap...), // a map in the array form
	} {
		if DecodeReplyWho(bad) != nil {
			t.Errorf("%x accepted", bad)
		}
	}
}
