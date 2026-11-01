package wire

import (
	"bytes"
	"testing"
)

func TestSubstream(t *testing.T) {
	for _, max := range []int{3, 10, 1530} {
		for _, n := range []int{0, 1, max - 2, max - 1, max, 3*max + 7} {
			blob := bytes.Repeat([]byte{7}, n)
			total := ChunkCount(n, max)
			var boxes [][]byte
			for i := range total {
				b := SubstreamBox(blob, max, i)
				if len(b) > max {
					t.Fatalf("box of %d bytes for max %d", len(b), max)
				}
				boxes = append(boxes, b)
			}
			got, ok := Assemble(boxes)
			if n > 0 && (!ok || !bytes.Equal(got, blob)) {
				t.Fatalf("n=%d max=%d: reassembled %d bytes, %v", n, max, len(got), ok)
			}
			if total > 1 {
				if _, ok := Assemble(boxes[:total-1]); ok {
					t.Fatal("assembled without the last box")
				}
			}
		}
	}
	if len(Indirection(3, make([]byte, ReadCapSize))) != 141 {
		t.Fatal("I box size")
	}
}

func TestPayloadSplice(t *testing.T) {
	f := FileUpload{Payload: []byte{}, Filetype: "image/png", Basename: "a.png"}
	content := FileContent(make([]byte, 32), f)
	full, ok := PutPayload(content, bytes.Repeat([]byte{9}, 70000))
	if !ok {
		t.Fatal("put")
	}
	without, payload, ok := TakePayload(full)
	if !ok || !bytes.Equal(without, content) || len(payload) != 70000 {
		t.Fatalf("take: %v %d", ok, len(payload))
	}
	g := DecodeGcm(full)
	got, ok := FileOf(g)
	if !ok || got.Basename != "a.png" || len(got.Payload) != 70000 {
		t.Fatalf("file of: %+v", got)
	}
}

func TestSafeName(t *testing.T) {
	for in, want := range map[string]string{"...x.png": "x.png", "": "unnamed", "a/b\\c": "a_b_c", "é.txt": "_.txt", "...": "unnamed"} {
		if got := SafeName(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
	if FiletypeOf("A.JPG") != "image/jpeg" || FiletypeOf("png") != "arbitrary" {
		t.Error("filetype")
	}
}
