package wire

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestWireVectorsV5(t *testing.T) {
	v := load(t, "groupchat_wire_vectors_v5.json")
	count := 0
	for _, e := range v["packed"].([]any) {
		e := e.(map[string]any)
		name := e["name"].(string)
		cbor := unhex(t, e["start"])
		for _, s := range e["added"].([]any) {
			cbor = Pack(cbor, s.(string))
		}
		if !bytes.Equal(cbor, unhex(t, e["cbor"])) {
			t.Errorf("%s: packed as %x", name, cbor)
			continue
		}
		var texts []string
		for _, s := range e["texts"].([]any) {
			texts = append(texts, s.(string))
		}
		if got := TextsOf(cbor); !reflect.DeepEqual(got, texts) || TextOf(cbor) != strings.Join(texts, "\n") {
			t.Errorf("%s: reads as %q", name, got)
		}
		if got := messageJSON(ToMessage(cbor)); !reflect.DeepEqual(got, e["message"]) {
			t.Errorf("%s: read as %v", name, got)
		}
		if g := DecodeGcm(cbor); g == nil || !bytes.Equal(g.Encode(), cbor) {
			t.Errorf("%s: does not encode to itself", name)
		}
		if _, _, ok := Unsupported(cbor); ok {
			t.Errorf("%s: taken for unsupported", name)
		}
		count++
	}
	for _, e := range v["unsupported"].([]any) {
		e := e.(map[string]any)
		cbor := unhex(t, e["cbor"])
		ver, typ, ok := Unsupported(cbor)
		if DecodeGcm(cbor) != nil || !ok || ver != uint64(intOf(t, e["version"])) || typ != uint64(intOf(t, e["msg_type"])) {
			t.Errorf("%s: version %d, type %d, %v", e["name"], ver, typ, ok)
		}
		count++
	}
	for _, e := range v["malformed"].([]any) {
		e := e.(map[string]any)
		cbor := unhex(t, e["cbor"])
		if _, _, ok := Unsupported(cbor); DecodeGcm(cbor) != nil || ok {
			t.Errorf("%s: accepted", e["name"])
		}
		count++
	}
	if count != 5+5+6 {
		t.Errorf("%d vectors", count)
	}
}

func TestPacksOnlyTextOfTheArrayForm(t *testing.T) {
	if Pack(TextContent(zeroHash, "a", MapVersion), "b") != nil {
		t.Error("packed the map form")
	}
	if Pack(FileContent(zeroHash, FileUpload{Payload: []byte("x"), Filetype: "arbitrary", Basename: "x"}, CurrentVersion), "b") != nil {
		t.Error("packed a file")
	}
}
