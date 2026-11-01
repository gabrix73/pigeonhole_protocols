package wire

import (
	"math"
	"math/big"
	"unicode/utf8"
)

// A general CBOR item, as the reply to a new member uses: decoding accepts every well-formed item
// (indefinite lengths, tags, bignums, floats and simple values), and encoding writes definite
// lengths in shortest form.

type termKind int

const (
	termInt termKind = iota
	termBytes
	termText
	termList
	termMap
	termTag
	termNull
	termOther
)

type term struct {
	kind  termKind
	int   *big.Int
	bytes []byte
	text  string
	list  []term
	keys  []term
	tag   uint64
}

const maxTermDepth = 1000

func natTerm(n int) term { return term{kind: termInt, int: big.NewInt(int64(n))} }

func (t term) encode(out []byte) []byte {
	switch t.kind {
	case termInt:
		if t.int.Sign() < 0 {
			return appendHeader(out, 1, new(big.Int).Sub(new(big.Int).Neg(t.int), big.NewInt(1)).Uint64())
		}
		return appendUint(out, t.int.Uint64())
	case termBytes:
		return appendBytes(out, t.bytes)
	case termText:
		return appendText(out, t.text)
	case termList:
		out = appendHeader(out, 4, uint64(len(t.list)))
		for _, e := range t.list {
			out = e.encode(out)
		}
		return out
	case termMap:
		out = appendHeader(out, 5, uint64(len(t.keys)))
		for i, k := range t.keys {
			out = t.list[i].encode(k.encode(out))
		}
		return out
	}
	return append(out, 0xf6)
}

// decodeTerm reads one item; what follows it is ignored.
func decodeTerm(b []byte) (term, bool) {
	t, _, ok := readTerm(b, maxTermDepth)
	return t, ok
}

// rawHeader reads a header, allowing an indefinite length (indef is then true).
func rawHeader(l []byte) (major, ai byte, n uint64, rest []byte, indef, ok bool) {
	if len(l) == 0 {
		return
	}
	b := l[0]
	major, ai = b>>5, b&31
	if ai == 31 {
		if major == 0 || major == 1 || major == 6 {
			return
		}
		return major, ai, 0, l[1:], true, true
	}
	if ai >= 28 {
		return
	}
	major, n, rest, ok = readHeader(l)
	return major, ai, n, rest, false, ok
}

func readTerm(l []byte, depth int) (term, []byte, bool) {
	major, ai, n, rest, indef, ok := rawHeader(l)
	if !ok {
		return term{}, nil, false
	}
	if (major == 4 || major == 5 || major == 6) && depth == 0 {
		return term{}, nil, false
	}
	switch major {
	case 0:
		return term{kind: termInt, int: new(big.Int).SetUint64(n)}, rest, true
	case 1:
		v := new(big.Int).SetUint64(n)
		return term{kind: termInt, int: v.Neg(v).Sub(v, big.NewInt(1))}, rest, true
	case 2, 3:
		var data []byte
		if indef {
			for {
				if len(rest) == 0 {
					return term{}, nil, false
				}
				if rest[0] == 0xff {
					rest = rest[1:]
					break
				}
				var chunk []byte
				if chunk, rest, ok = readString(major, rest); !ok {
					return term{}, nil, false
				}
				if major == 3 && !utf8.Valid(chunk) {
					return term{}, nil, false
				}
				data = append(data, chunk...)
			}
		} else {
			if n > uint64(len(rest)) {
				return term{}, nil, false
			}
			data, rest = rest[:n], rest[n:]
			if major == 3 && !utf8.Valid(data) {
				return term{}, nil, false
			}
		}
		if major == 2 {
			return term{kind: termBytes, bytes: append([]byte{}, data...)}, rest, true
		}
		return term{kind: termText, text: string(data)}, rest, true
	case 4, 5:
		t := term{kind: termList}
		if major == 5 {
			t.kind = termMap
		}
		for i := uint64(0); indef || i < n; i++ {
			if indef {
				if len(rest) == 0 {
					return term{}, nil, false
				}
				if rest[0] == 0xff {
					return t, rest[1:], true
				}
			}
			var e term
			if major == 5 {
				if e, rest, ok = readTerm(rest, depth-1); !ok {
					return term{}, nil, false
				}
				t.keys = append(t.keys, e)
			}
			if e, rest, ok = readTerm(rest, depth-1); !ok {
				return term{}, nil, false
			}
			t.list = append(t.list, e)
		}
		return t, rest, true
	case 6:
		if (n == 2 || n == 3) && ai < 24 {
			if b, after, ok := readString(2, rest); ok {
				v := new(big.Int).SetBytes(b)
				if n == 3 {
					v.Neg(v).Sub(v, big.NewInt(1))
				}
				return term{kind: termInt, int: v}, after, true
			}
		}
		inner, after, ok := readTerm(rest, depth-1)
		if !ok {
			return term{}, nil, false
		}
		return term{kind: termTag, tag: n, list: []term{inner}}, after, true
	}
	if indef {
		return term{}, nil, false
	}
	if ai == 22 {
		return term{kind: termNull}, rest, true
	}
	return term{kind: termOther}, rest, true
}

// nat reads a natural number; one too large for an int saturates, which every bound it is
// checked against refuses.
func (t term) nat() (int, bool) {
	if t.kind != termInt || t.int.Sign() < 0 {
		return 0, false
	}
	if !t.int.IsInt64() || t.int.Int64() > math.MaxInt32 {
		return math.MaxInt32, true
	}
	return int(t.int.Int64()), true
}

func (t term) isNull() bool { return t.kind == termNull }

// field is the value of the last entry under key.
func (t term) field(key string) (term, bool) {
	for i := len(t.keys) - 1; i >= 0; i-- {
		if t.keys[i].kind == termText && t.keys[i].text == key {
			return t.list[i], true
		}
	}
	return term{}, false
}
