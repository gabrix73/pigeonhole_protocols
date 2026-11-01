package wire

import (
	"encoding/binary"
	"errors"
)

// The Acks field, following katzenqt's ack_codec.py: the count less one, the members named as a
// list or a bitmap, whichever is shorter, then each one's Idx64, little-endian. Reading is not
// strict: like katzenqt, it accepts a list where the bitmap would have been shorter.

const (
	// maxNaming is the longest naming: a bitmap reaching roster index 255.
	maxNaming = 32
	idxSize   = 8
)

var (
	ErrAcksShort  = errors.New("acks: field shorter than its count")
	ErrAcksNaming = errors.New("acks: malformed naming")
)

// width is the bytes a bitmap needs to reach roster index i.
func width(i int) int { return i/8 + 1 }

// EncodeAcks writes acks, in ascending order of roster index; empty when there is nothing to
// acknowledge.
func EncodeAcks(acks []Ack) []byte {
	if len(acks) == 0 {
		return nil
	}
	out := []byte{byte(len(acks) - 1)}
	last := acks[len(acks)-1].Member
	if len(acks) <= width(last) {
		for _, a := range acks {
			out = append(out, byte(a.Member))
		}
	} else {
		bitmap := make([]byte, width(last))
		for _, a := range acks {
			bitmap[a.Member/8] |= 1 << (7 - a.Member%8)
		}
		out = append(out, bitmap...)
	}
	for _, a := range acks {
		out = binary.LittleEndian.AppendUint64(out, a.Idx64)
	}
	return out
}

func readMembers(naming []byte, count int) ([]int, error) {
	if len(naming) == count {
		idx := make([]int, count)
		for i, b := range naming {
			if i > 0 && naming[i-1] >= b {
				return nil, ErrAcksNaming
			}
			idx[i] = int(b)
		}
		return idx, nil
	}
	if count < len(naming) || len(naming) > maxNaming || len(naming) == 0 || naming[len(naming)-1] == 0 {
		return nil, ErrAcksNaming
	}
	var idx []int
	for i := range len(naming) * 8 {
		if naming[i/8]&(1<<(7-i%8)) != 0 {
			idx = append(idx, i)
		}
	}
	if len(idx) != count {
		return nil, ErrAcksNaming
	}
	return idx, nil
}

// DecodeAcks returns the acknowledgements a field carries.
func DecodeAcks(field []byte) ([]Ack, error) {
	if len(field) == 0 {
		return nil, nil
	}
	count := int(field[0]) + 1
	rest := field[1:]
	if len(rest) < count*idxSize {
		return nil, ErrAcksShort
	}
	w := len(rest) - count*idxSize
	idx, err := readMembers(rest[:w], count)
	if err != nil {
		return nil, err
	}
	acks := make([]Ack, count)
	for i, m := range idx {
		acks[i] = Ack{Member: m, Idx64: binary.LittleEndian.Uint64(rest[w+i*idxSize:])}
	}
	return acks, nil
}
