package wire

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNumbers(t *testing.T) {
	p := func(b byte) []byte { return bytes.Repeat([]byte{b}, PrefixSize) }
	for _, ns := range [][]Number{
		nil,
		{{Index: 7}},
		{{Index: 3, Prefix: p(1)}},
		{{Index: 3, Prefix: p(1)}, {Index: 4, Prefix: p(2)}, {Index: 5, Prefix: p(3)}},
	} {
		got := DecodeNumbers(EncodeNumbers(ns))
		if !reflect.DeepEqual(got, ns) {
			t.Errorf("%v decodes back as %v", ns, got)
		}
	}
	if EncodeNumbers([]Number{{Index: 7}})[0] != 7 || len(EncodeNumbers([]Number{{Index: 7}})) != 1 {
		t.Error("an introducee is not a lone byte")
	}
	for name, field := range map[string][]byte{
		"ragged":    append([]byte{0}, make([]byte, PrefixSize+1)...),
		"repeated":  append(append([]byte{0}, p(1)...), p(1)...),
		"past 255":  append(append([]byte{255}, p(1)...), p(2)...),
		"lone zero": append([]byte{0}, make([]byte, 0)...),
	} {
		got := DecodeNumbers(field)
		if name == "lone zero" {
			if len(got) != 1 || got[0].Prefix != nil {
				t.Errorf("%s: %v", name, got)
			}
			continue
		}
		if got != nil {
			t.Errorf("%s accepted as %v", name, got)
		}
	}
	if got := DecodeNumbers(append([]byte{254}, append(p(1), p(2)...)...)); len(got) != 2 || got[1].Index != 255 {
		t.Errorf("up to 255 refused: %v", got)
	}
}

func TestIntroducedAt(t *testing.T) {
	r := IntroRef{Introducer: 9, Index: bytes.Repeat([]byte{5}, IndexSize)}
	if got := DecodeIntroducedAt(EncodeIntroducedAt(r)); got == nil || !reflect.DeepEqual(*got, r) {
		t.Errorf("decodes back as %v", got)
	}
	if DecodeIntroducedAt(make([]byte, IndexSize)) != nil || DecodeIntroducedAt(nil) != nil {
		t.Error("short field accepted")
	}
}

func TestUnframe(t *testing.T) {
	rc := bytes.Repeat([]byte{1}, ReadCapSize)
	if c := Unframe(append([]byte{'I', 0, 0, 1, 2}, rc...)); c.Kind != ChunkIndirection || *c.Total != 258 || !bytes.Equal(c.Data, rc) {
		t.Errorf("I with total: %+v", c)
	}
	if c := Unframe(append([]byte{'I'}, rc...)); c.Kind != ChunkIndirection || c.Total != nil {
		t.Errorf("I without total: %+v", c)
	}
	if c := Unframe(append([]byte{'I'}, rc[1:]...)); c.Kind != ChunkUnknown {
		t.Errorf("short I: %+v", c)
	}
	if c := Unframe([]byte("Cab")); c.Kind != ChunkContinued || string(c.Data) != "ab" {
		t.Errorf("C: %+v", c)
	}
	if Unframe(nil).Kind != ChunkUnknown || Unframe([]byte("X")).Kind != ChunkUnknown {
		t.Error("unknown accepted")
	}
}

func TestMessageEqual(t *testing.T) {
	a := &Message{Numbers: []Number{{Index: 1}}, Acks: []Ack{{1, 2}}}
	b := &Message{Numbers: []Number{{Index: 2}}, Acks: []Ack{{1, 2}}}
	if !a.Equal(a) || a.Equal(b) || a.Equal(nil) {
		t.Error("Equal")
	}
}

// A key repeated in a map keeps its last value, as a Python dict does.
func TestRepeatedKeys(t *testing.T) {
	var m []byte
	m = appendHeader(m, 5, 5)
	m = appendUint(appendText(m, "version"), 3)
	m = appendBytes(appendText(m, "membership_hash"), make([]byte, 32))
	m = appendUint(appendText(m, "msg_type"), MsgFileUpload)
	m = appendUint(appendText(m, "file_upload"), 1)
	m = appendUint(appendText(m, "file_upload"), 2)
	g := DecodeGcm(m)
	if g == nil || len(g.Other) != 1 || !bytes.Equal(g.Other[0].Raw, []byte{2}) {
		t.Fatalf("repeated field: %+v", g)
	}
	var r []byte
	r = appendHeader(r, 5, 3)
	r = appendHeader(appendText(r, "please_adds"), 4, 0)
	r = appendUint(appendText(r, "introducer"), 1)
	r = appendUint(appendText(r, "introducer"), 2)
	w := DecodeReplyWho(r)
	if w == nil || w.Introducer == nil || *w.Introducer != 2 {
		t.Fatalf("repeated reply field: %+v", w)
	}
}
