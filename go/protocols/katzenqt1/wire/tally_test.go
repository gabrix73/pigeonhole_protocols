package wire

import (
	"bytes"
	"reflect"
	"strconv"
	"testing"
)

func tallyOfJSON(t *testing.T, v any) *Tally {
	if v == nil {
		return nil
	}
	m := v.(map[string]any)
	r := &Tally{Kind: uint64(intOf(t, m["msg_type"])), SurveyID: unhex(t, m["survey_id"])}
	var err error
	if r.Version, err = strconv.ParseUint(string(num(m["version"])), 10, 64); err != nil {
		t.Fatal(err)
	}
	if c, ok := m["choice"].([]any); ok {
		r.Choice = []Choice{}
		for _, p := range c {
			p := p.([]any)
			r.Choice = append(r.Choice, Choice{p[0].(string), p[1].(string)})
		}
	}
	if m["crdt"] != nil {
		r.Crdt = unhex(t, m["crdt"])
	}
	return r
}

// TestTallyVectors: tallies as katzenqt writes them, and as other writers may.
func TestTallyVectors(t *testing.T) {
	v := load(t, "tally_vectors.json")
	count := 0
	for _, e := range v["tallies"].([]any) {
		e := e.(map[string]any)
		name, want, cbor := e["name"].(string), tallyOfJSON(t, e["tally"]), unhex(t, e["cbor"])
		if got := TallyContent(zeroHash, want, uint64(intOf(t, e["wire_version"]))); !bytes.Equal(got, cbor) {
			t.Errorf("%s: written as %x", name, got)
		}
		g := DecodeGcm(cbor)
		if g == nil {
			t.Errorf("%s: refused", name)
			continue
		}
		if got, ok := TallyOf(g); !ok || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: read as %+v", name, got)
		}
		if !bytes.Equal(g.Encode(), cbor) {
			t.Errorf("%s: does not encode to itself", name)
		}
		count++
	}
	for _, e := range v["read"].([]any) {
		e := e.(map[string]any)
		want := tallyOfJSON(t, e["tally"])
		var got *Tally
		if g := DecodeGcm(unhex(t, e["cbor"])); g != nil {
			got, _ = TallyOf(g)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: read as %+v", e["name"], got)
		}
		count++
	}
	if count != 8+17 {
		t.Errorf("%d vectors", count)
	}
}

func TestTallyRefusals(t *testing.T) {
	tl := &Tally{Kind: MsgTallyCreate, SurveyID: bytes.Repeat([]byte{9}, 16), Crdt: []byte{1, 2, 3}}
	if g := DecodeGcm(TallyContent(zeroHash, tl, CurrentVersion)); g == nil {
		t.Fatal("current version refused")
	} else if got, ok := TallyOf(g); !ok || !reflect.DeepEqual(got, tl) {
		t.Fatalf("current version read as %+v", got)
	}
	if _, ok := TallyOfBody(MsgReplyWho, tl.Body()); ok {
		t.Error("read as a tally of type 4")
	}
	if _, ok := TallyOfBody(MsgControl, tl.Body()); ok {
		t.Error("read as a tally of type 10")
	}
	if _, ok := TallyOfBody(MsgTallyCreate, tl.Body()[:5]); ok {
		t.Error("read cut short")
	}
	if _, ok := TallyOf(DecodeGcm(TextContent(zeroHash, "hi", CurrentVersion))); ok {
		t.Error("read a text as a tally")
	}
}
