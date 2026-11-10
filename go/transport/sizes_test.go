package transport_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
	"github.com/katzenpost/pigeonhole_protocols/go/transport"
)

type sizesVectors struct {
	Min, Max   int
	Substreams []struct {
		Size    string
		Message string
		Boxes   []string
	}
}

func load(t *testing.T) (sizesVectors, map[string]any) {
	b, err := os.ReadFile("../../testdata/box_sizes.json")
	if err != nil {
		t.Fatal(err)
	}
	var v sizesVectors
	var raw map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	return v, raw
}

func unhex(t *testing.T, s any) []byte {
	b, err := hex.DecodeString(s.(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSizesMatchVectors(t *testing.T) {
	v, raw := load(t)
	want := map[string]int{}
	for _, s := range raw["sizes"].([]any) {
		m := s.(map[string]any)
		want[m["name"].(string)] = int(m["plaintext"].(float64))
	}
	if len(want) != len(transport.BoxSizes) || want["mesh"] != transport.BoxSizes["mesh"] || want["mixnet"] != transport.BoxSizes["mixnet"] {
		t.Fatalf("sizes %v, vectors %v", transport.BoxSizes, want)
	}
	if v.Min != transport.MinBoxSize || v.Max != transport.MaxBoxSize || transport.MinBoxSize != wire.MinBox {
		t.Fatal("bounds")
	}
	for s, n := range map[string]int{"mesh": 256, "mixnet": 1549, "1000": 1000, "141": 141} {
		if got, err := transport.BoxSize(s); err != nil || got != n {
			t.Fatalf("BoxSize(%q) = %d, %v", s, got, err)
		}
	}
	for _, s := range []string{"huge", "140", "16385", "0"} {
		if _, err := transport.BoxSize(s); err == nil {
			t.Fatalf("BoxSize(%q) took it", s)
		}
	}
	if a, err := transport.AllowedSizes(512, 256); err != nil || !slices.Equal(a, []int{256, 512, 1549}) {
		t.Fatalf("AllowedSizes: %v %v", a, err)
	}
	if _, err := transport.AllowedSizes(100); err == nil {
		t.Fatal("AllowedSizes took 100")
	}
	for _, c := range v.Substreams {
		size, blob := transport.BoxSizes[c.Size], unhex(t, c.Message)
		var got [][]byte
		for i := range wire.ChunkCount(len(blob), size) {
			b := wire.SubstreamBox(blob, size, i)
			if !bytes.Equal(b, unhex(t, c.Boxes[i])) {
				t.Fatalf("%d bytes at %d: box %d differs", len(blob), size, i)
			}
			got = append(got, b)
		}
		if len(got) != len(c.Boxes) {
			t.Fatalf("%d boxes, want %d", len(got), len(c.Boxes))
		}
	}
}

// TestMixedStream opens one stream whose boxes are of different sizes; each is of an allowed
// size, the extra among them, and together they hold one substream.
func TestMixedStream(t *testing.T) {
	_, raw := load(t)
	m := raw["mixed_stream"].(map[string]any)
	rc, err := bacap.ReadCapFromBytes(unhex(t, m["read_cap"]))
	if err != nil {
		t.Fatal(err)
	}
	var extra []int
	for _, n := range m["extra_sizes"].([]any) {
		extra = append(extra, int(n.(float64)))
	}
	with, _ := transport.AllowedSizes(extra...)
	without, _ := transport.AllowedSizes()
	var got [][]byte
	for i, x := range m["boxes"].([]any) {
		b := x.(map[string]any)
		idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(unhex(t, b["index"]))
		if err != nil {
			t.Fatal(err)
		}
		pos, err := rc.PositionAt(idx)
		if err != nil {
			t.Fatal(err)
		}
		padded, err := pos.Open([]byte("pigeonhole context"), [32]byte(unhex(t, b["box_id"])), unhex(t, b["ciphertext"]), unhex(t, b["signature"]))
		if err != nil {
			t.Fatalf("box %d: %v", i, err)
		}
		size := len(padded) - 4
		if size != int(b["size"].(float64)) || !slices.Contains(with, size) || slices.Contains(without, size) == slices.Contains(extra, size) {
			t.Fatalf("box %d of %d bytes", i, size)
		}
		n := binary.BigEndian.Uint32(padded)
		got = append(got, padded[4:4+n])
		if !bytes.Equal(got[i], unhex(t, m["plaintexts"].([]any)[i])) {
			t.Fatalf("box %d holds other bytes", i)
		}
	}
	if blob, ok := wire.Assemble(got); !ok || !bytes.Equal(blob, unhex(t, m["message"])) {
		t.Fatal("the mixed stream does not assemble")
	}
}
