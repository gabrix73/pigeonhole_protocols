package wire

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// A file travels as katzenqt's file_upload: a map of its bytes, its type and its name. A message
// too long for one box is written to a substream of its own, 'C' chunks then an 'F' chunk, and
// the member's stream gets an 'I' box: the number of chunks, four bytes big-endian, then the
// substream's read cap.

// MaxFile is the largest file sent or fetched.
const MaxFile = 16 * 1024 * 1024

type FileUpload struct {
	Payload []byte
	// Filetype is image/png, audio/opus or arbitrary, as katzenqt tags it.
	Filetype string
	Basename string
}

func encodeUpload(f FileUpload) []byte {
	out := appendHeader(nil, 5, 3)
	out = appendBytes(appendText(out, "payload"), f.Payload)
	out = appendText(appendText(out, "filetype"), f.Filetype)
	return appendText(appendText(out, "basename"), f.Basename)
}

func decodeUpload(raw []byte) (FileUpload, bool) {
	major, n, l, ok := readHeader(raw)
	if !ok || major != 5 {
		return FileUpload{}, false
	}
	var p []byte
	var t, b *string
	for ; n > 0; n-- {
		var k string
		if k, l, ok = readText(l); !ok {
			return FileUpload{}, false
		}
		switch k {
		case "payload":
			if p, l, ok = readBytes(l); !ok {
				return FileUpload{}, false
			}
		case "filetype", "basename":
			var s string
			if s, l, ok = readText(l); !ok {
				return FileUpload{}, false
			}
			if k == "filetype" {
				t = &s
			} else {
				b = &s
			}
		default:
			if l, ok = skipItems(len(l)+1, 1, l); !ok {
				return FileUpload{}, false
			}
		}
	}
	if p == nil || t == nil || b == nil {
		return FileUpload{}, false
	}
	return FileUpload{Payload: p, Filetype: *t, Basename: *b}, true
}

// FileOf is the file a message carries.
func FileOf(g *Gcm) (FileUpload, bool) {
	if g.MsgType != MsgFileUpload {
		return FileUpload{}, false
	}
	for _, o := range g.Other {
		if o.Key == "file_upload" {
			return decodeUpload(o.Raw)
		}
	}
	return FileUpload{}, false
}

// FileContent is a file, as a member's content.
func FileContent(membershipHash []byte, f FileUpload) []byte {
	g := Gcm{Version: CurrentVersion, MembershipHash: membershipHash, MsgType: MsgFileUpload,
		Other: []RawField{{"file_upload", encodeUpload(f)}}}
	return g.Encode()
}

// SafeName is a name from elsewhere as a file may be called here: printable ASCII from
// katzenqt's list, no leading dots, at most 200 characters.
func SafeName(name string) string {
	var b strings.Builder
	for _, c := range name {
		ok := c < 128 && (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.ContainsRune(" ._-+()[]", c))
		if ok {
			b.WriteRune(c)
		} else {
			b.WriteByte('_')
		}
	}
	s := strings.TrimLeft(b.String(), ".")
	if s == "" {
		return "unnamed"
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func extension(name string) string {
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.ToLower(parts[len(parts)-1])
}

// FiletypeOf is the type katzenqt tags a file with, from its name.
func FiletypeOf(name string) string {
	switch extension(name) {
	case "png":
		return "image/png"
	case "jpg", "jpeg":
		return "image/jpeg"
	case "gif":
		return "image/gif"
	case "webp":
		return "image/webp"
	case "bmp":
		return "image/bmp"
	case "opus":
		return "audio/opus"
	}
	return "arbitrary"
}

// A file's bytes are kept out of a message as it is read and written: the message carries an
// empty payload, and the bytes are spliced in as it is written and out as it is read.

// headerAt is an item's major type, its argument, and where what follows its header begins.
func headerAt(b []byte, pos int) (byte, uint64, int, bool) {
	if pos >= len(b) {
		return 0, 0, 0, false
	}
	major, n, rest, ok := readHeader(b[pos:])
	return major, n, len(b) - len(rest), ok
}

// skipAt is where the item at pos ends.
func skipAt(b []byte, fuel, pos int) (int, bool) {
	rest, ok := skipItems(fuel, 1, b[min(pos, len(b)):])
	if !ok || pos > len(b) {
		return 0, false
	}
	return len(b) - len(rest), true
}

// lookupAt is where the value of the entry under key of the map at pos begins.
func lookupAt(b []byte, pos int, key string) (int, bool) {
	major, n, at, ok := headerAt(b, pos)
	if !ok || major != 5 {
		return 0, false
	}
	for ; n > 0; n-- {
		name, rest, ok := readText(b[at:])
		if !ok {
			return 0, false
		}
		value := len(b) - len(rest)
		if name == key {
			return value, true
		}
		if at, ok = skipAt(b, len(b)+1, value); !ok {
			return 0, false
		}
	}
	return 0, false
}

// payloadSpan is where the file's bytes are in a message: the payload item's start and end.
func payloadSpan(cbor []byte) (int, int, bool) {
	upload, ok := lookupAt(cbor, 0, "file_upload")
	if !ok {
		return 0, 0, false
	}
	start, ok := lookupAt(cbor, upload, "payload")
	if !ok {
		return 0, 0, false
	}
	if major, _, _, ok := headerAt(cbor, start); !ok || major != 2 {
		return 0, 0, false
	}
	stop, ok := skipAt(cbor, 1, start)
	return start, stop, ok
}

// TakePayload is a message with the file's bytes taken out, and the bytes.
func TakePayload(cbor []byte) (without, payload []byte, ok bool) {
	start, stop, ok := payloadSpan(cbor)
	if !ok {
		return nil, nil, false
	}
	_, _, data, _ := headerAt(cbor, start)
	without = append(append(bytes.Clone(cbor[:start]), 0x40), cbor[stop:]...)
	return without, bytes.Clone(cbor[data:stop]), true
}

// PutPayload is a message with payload put in place of the file's bytes.
func PutPayload(cbor, payload []byte) ([]byte, bool) {
	start, stop, ok := payloadSpan(cbor)
	if !ok {
		return nil, false
	}
	out := appendHeader(bytes.Clone(cbor[:start]), 2, uint64(len(payload)))
	return append(append(out, payload...), cbor[stop:]...), true
}

// ChunkCount is how many boxes of max bytes a message of n bytes takes in a substream.
func ChunkCount(n, max int) int { return (n + (max - 2)) / (max - 1) }

// MaxChunks is the most boxes of max bytes a substream is sent or fetched in: a message of
// MaxFile+max bytes, the most a sender cuts.
func MaxChunks(max int) int { return ChunkCount(MaxFile+max, max) }

// SubstreamBox is the ith box of blob's substream.
func SubstreamBox(blob []byte, max, i int) []byte {
	size := max - 1
	tag := byte('F')
	if i+1 < ChunkCount(len(blob), max) {
		tag = 'C'
	}
	lo, hi := min(i*size, len(blob)), min((i+1)*size, len(blob))
	return append([]byte{tag}, blob[lo:hi]...)
}

// Indirection is the 'I' box naming a substream of total boxes.
func Indirection(total int, readCap []byte) []byte {
	out := binary.BigEndian.AppendUint32([]byte{'I'}, uint32(total))
	return append(out, readCap...)
}

// Assemble is the message a substream's boxes hold, once its 'F' box is among them.
func Assemble(boxes [][]byte) ([]byte, bool) {
	if len(boxes) == 0 {
		return nil, false
	}
	last := boxes[len(boxes)-1]
	if len(last) == 0 || last[0] != 'F' {
		return nil, false
	}
	var out []byte
	for _, b := range boxes[:len(boxes)-1] {
		if len(b) == 0 || b[0] != 'C' {
			return nil, false
		}
		out = append(out, b[1:]...)
	}
	return append(out, last[1:]...), true
}

// TextOf is how a message's content reads.
func TextOf(content []byte) string {
	g := DecodeGcm(content)
	switch {
	case g == nil:
		return "[a message that cannot be read]"
	case g.MsgType == MsgText:
		if g.Text != nil {
			return *g.Text
		}
		return ""
	case g.MsgType == MsgFileUpload:
		return "[a file that cannot be read]"
	}
	return "[a message that cannot be shown]"
}
