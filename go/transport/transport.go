// Package transport is what a group protocol's client asks of Pigeonhole: boxes on streams, and
// the contact vouchers a new member joins through. Caps and indexes are BACAP's binary forms; a
// client steps from one index to the next itself, by BACAP.
package transport

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// BoxSizes are box plaintext sizes by name: mesh, a writer's default on Reticulum, a write in one
// Link packet; mixnet, Katzenpost's. A group can span meshes and mixnets joined by bridges, so a
// reader takes a box of any allowed size: these, the writer's own and any configured extra, each
// within MinBoxSize (a substream's I box) and MaxBoxSize. Only the payload differs: box IDs and
// signatures are the same size in each.
var BoxSizes = map[string]int{"mesh": 256, "mixnet": 1549}

const (
	MinBoxSize = 141
	MaxBoxSize = 16384
)

// BoxSize is a named size, or a number of bytes, within the bounds.
func BoxSize(s string) (int, error) {
	n, ok := BoxSizes[s]
	if !ok {
		var err error
		if n, err = strconv.Atoi(s); err != nil {
			return 0, fmt.Errorf("transport: box size: mesh, mixnet or a number of bytes, not %q", s)
		}
	}
	if n < MinBoxSize || n > MaxBoxSize {
		return 0, fmt.Errorf("transport: box size %d is not within %d..%d", n, MinBoxSize, MaxBoxSize)
	}
	return n, nil
}

// AllowedSizes are the named sizes and sizes, smallest first.
func AllowedSizes(sizes ...int) ([]int, error) {
	var out []int
	for _, n := range BoxSizes {
		out = append(out, n)
	}
	for _, n := range sizes {
		if n < MinBoxSize || n > MaxBoxSize {
			return nil, fmt.Errorf("transport: box size %d is not within %d..%d", n, MinBoxSize, MaxBoxSize)
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

var (
	// ErrBoxAlreadyExists is a write to a box that holds something else.
	ErrBoxAlreadyExists = errors.New("transport: box already exists with other contents")
	ErrClosed           = errors.New("transport: closed")
)

type ReadKind int

const (
	Data ReadKind = iota
	NotFound
	Tombstone
)

type Read struct {
	Kind      ReadKind
	Plaintext []byte
}

type Keypair struct {
	WriteCap []byte
	ReadCap  []byte
	// First is the index the stream starts at.
	First []byte
}

// Boxes is Pigeonhole's storage. Every call may fail; a caller that must succeed retries.
type Boxes interface {
	NewKeypair(ctx context.Context) (Keypair, error)
	// WriteBox writes plaintext to the box at index; an empty plaintext is a tombstone. Writing
	// again what a box holds succeeds; writing anything else is ErrBoxAlreadyExists.
	WriteBox(ctx context.Context, writeCap, index, plaintext []byte) error
	// ReadBox reads the box at index, reporting at once a box not written.
	ReadBox(ctx context.Context, readCap, index []byte) (Read, error)
	// ReplicaEpoch is the storage replicas' current epoch.
	ReplicaEpoch(ctx context.Context) (uint64, error)
	// MaxPlaintext is the most a box holds.
	MaxPlaintext(ctx context.Context) (int, error)
}

type Minted struct {
	Voucher, Payload, WriteCap, ReadCap, SecretKey []byte
	// Version is the payload's form: 2 the compact array, answered by a sealed box framed
	// over boxes 1 on; 1 the signed map, answered by an unframed reply in box 1 alone.
	Version int
}

type Inducted struct {
	Name           string
	MutatedReadCap []byte
	SealedReply    []byte
	// Version is the form the payload was in and the reply is in; see Minted.
	Version int
}

// VoucherVersion is the form of a voucher payload: 1 for the map form, else 2.
func VoucherVersion(payload []byte) int {
	if len(payload) > 0 && payload[0]>>5 == 5 {
		return 1
	}
	return 2
}

type Opened struct {
	WhoReply        []byte
	MutatedWriteCap []byte
}

// Vouchers are contact vouchers: a joiner mints one for its stream, an existing member inducts
// it with a sealed reply, and the joiner opens the reply.
type Vouchers interface {
	// VoucherMint mints a voucher whose payload is in form: 2 the compact array, 1 the signed
	// map.
	VoucherMint(ctx context.Context, writeCap []byte, name string, form int) (Minted, error)
	// VoucherDeriveStream is the voucher stream's write cap and read cap.
	VoucherDeriveStream(ctx context.Context, voucher []byte) (writeCap, readCap []byte, err error)
	VoucherInduct(ctx context.Context, voucher, payload, whoReply []byte) (Inducted, error)
	VoucherOpen(ctx context.Context, secretKey, sealedReply, writeCap []byte) (Opened, error)
}

type Backend interface {
	Boxes
	Vouchers
}
