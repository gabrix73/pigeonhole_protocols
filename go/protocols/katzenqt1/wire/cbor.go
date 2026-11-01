package wire

import (
	"unicode/utf8"
)

// The CBOR a group chat message uses: definite-length unsigned integers, byte strings, text
// strings and maps, as Python's cbor2 writes them, each header in its shortest form. Reading also
// skips any other well-formed item, so that a field this client does not interpret can be passed
// over or kept as it came.

func appendHeader(out []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(out, m|byte(n))
	case n < 1<<8:
		return append(out, m|24, byte(n))
	case n < 1<<16:
		return append(out, m|25, byte(n>>8), byte(n))
	case n < 1<<32:
		return append(out, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
		byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func appendUint(out []byte, n uint64) []byte { return appendHeader(out, 0, n) }

func appendBytes(out, b []byte) []byte {
	return append(appendHeader(out, 2, uint64(len(b))), b...)
}

func appendText(out []byte, s string) []byte {
	return append(appendHeader(out, 3, uint64(len(s))), s...)
}

// readHeader returns an item's major type, its argument, and what follows the header. Indefinite
// lengths and the reserved additional information values are refused.
func readHeader(l []byte) (major byte, n uint64, rest []byte, ok bool) {
	if len(l) == 0 {
		return 0, 0, nil, false
	}
	b, rest := l[0], l[1:]
	ai := b & 31
	if ai < 24 {
		return b >> 5, uint64(ai), rest, true
	}
	if ai >= 28 {
		return 0, 0, nil, false
	}
	k := 1 << (ai - 24)
	if len(rest) < k {
		return 0, 0, nil, false
	}
	for _, c := range rest[:k] {
		n = n<<8 | uint64(c)
	}
	return b >> 5, n, rest[k:], true
}

func readUint(l []byte) (uint64, []byte, bool) {
	major, n, rest, ok := readHeader(l)
	if !ok || major != 0 {
		return 0, nil, false
	}
	return n, rest, true
}

func readString(major byte, l []byte) ([]byte, []byte, bool) {
	m, n, rest, ok := readHeader(l)
	if !ok || m != major || n > uint64(len(rest)) {
		return nil, nil, false
	}
	return rest[:n], rest[n:], true
}

func readBytes(l []byte) ([]byte, []byte, bool) {
	b, rest, ok := readString(2, l)
	if !ok {
		return nil, nil, false
	}
	return append([]byte{}, b...), rest, true
}

func readText(l []byte) (string, []byte, bool) {
	b, rest, ok := readString(3, l)
	if !ok || !utf8.Valid(b) {
		return "", nil, false
	}
	return string(b), rest, true
}

func isNull(l []byte) bool { return len(l) > 0 && l[0] == 0xf6 }

// skipItems passes over count well-formed items. fuel bounds the items visited; one per byte of
// input is always enough, since every item takes at least one byte.
func skipItems(fuel int, count uint64, l []byte) ([]byte, bool) {
	for ; count > 0; count-- {
		if fuel == 0 {
			return nil, false
		}
		fuel--
		major, n, rest, ok := readHeader(l)
		if !ok {
			return nil, false
		}
		switch major {
		case 0, 1, 7:
			l = rest
		case 2, 3:
			if n > uint64(len(rest)) {
				return nil, false
			}
			l = rest[n:]
		case 4, 5, 6:
			inner := n
			if major == 5 {
				if n > uint64(len(rest)) {
					return nil, false
				}
				inner = 2 * n
			} else if major == 6 {
				inner = 1
			}
			if l, ok = skipItems(fuel, inner, rest); !ok {
				return nil, false
			}
		}
	}
	return l, true
}

// readRaw returns the next item as it came, and what follows it.
func readRaw(l []byte) ([]byte, []byte, bool) {
	rest, ok := skipItems(len(l)+1, 1, l)
	if !ok {
		return nil, nil, false
	}
	return append([]byte{}, l[:len(l)-len(rest)]...), rest, true
}
