// Package transport is what a group protocol's client asks of Pigeonhole: boxes on streams, and
// the contact vouchers a new member joins through. Caps and indexes are BACAP's binary forms; a
// client steps from one index to the next itself, by BACAP.
package transport

import (
	"context"
	"errors"
)

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
}

type Inducted struct {
	Name           string
	MutatedReadCap []byte
	SealedReply    []byte
}

type Opened struct {
	WhoReply        []byte
	MutatedWriteCap []byte
}

// Vouchers are contact vouchers: a joiner mints one for its stream, an existing member inducts
// it with a sealed reply, and the joiner opens the reply.
type Vouchers interface {
	VoucherMint(ctx context.Context, writeCap []byte, name string) (Minted, error)
	// VoucherDeriveStream is the voucher stream's write cap and read cap.
	VoucherDeriveStream(ctx context.Context, voucher []byte) (writeCap, readCap []byte, err error)
	VoucherInduct(ctx context.Context, voucher, payload, whoReply []byte) (Inducted, error)
	VoucherOpen(ctx context.Context, secretKey, sealedReply, writeCap []byte) (Opened, error)
}

type Backend interface {
	Boxes
	Vouchers
}
