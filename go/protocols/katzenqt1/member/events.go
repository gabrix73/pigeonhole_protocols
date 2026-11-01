// Package member is one member of one katzenqt1 group chat: a state machine over Group, driven
// either by events (Handle, returning effects) or by a client that reads and writes itself
// (Observe, Compose, Written). A member never derives a BACAP index, encrypts, or touches the
// network itself.
package member

import (
	"encoding/binary"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

// Key is a member's identity: the public key its read cap begins with, as bytes.
type Key string

// Index is a box: its 104-byte MessageBoxIndex, as bytes.
type Index string

func keyOf(readCap []byte) Key { return Key(wire.KeyOf(readCap)) }

func startOf(readCap []byte) Index { return Index(wire.StartOf(readCap)) }

// counter is the BACAP Idx64 of an index: its first 8 bytes, little-endian.
func counter(i Index) uint64 {
	var b [8]byte
	copy(b[:], i)
	return binary.LittleEndian.Uint64(b[:])
}

func prefixOf(k Key) []byte { return []byte(k[:min(wire.PrefixSize, len(k))]) }

// At names an Introduction: its introducer and its box.
type At struct {
	Introducer Key
	Index      Index
}

type ReadKind int

const (
	// ReadData is a box that holds a message, or nothing a member can decode.
	ReadData ReadKind = iota
	ReadTombstone
	ReadNotFound
)

// ReadResult is what reading a box found.
type ReadResult struct {
	Kind    ReadKind
	Message *wire.Message
}

// Payload is what a box of the member's own stream holds, as its Sent box keeps it: a message the
// member composed, which its client encodes, or the bytes a client that writes for itself handed
// over, which the member never looks into. Exactly one is set.
type Payload struct {
	Message *wire.Message
	Bytes   []byte
}

type Event interface{ event() }

type (
	Send struct{ Content []byte }
	Read struct{ Stream Key }
	Scan struct{ Stream Key }
	// BoxRead is the result of a ReadBox effect, with the index after it.
	BoxRead struct {
		Stream Key
		Index  Index
		Result ReadResult
		Next   *Index
	}
	IndexesDerived struct {
		Stream  Key
		Indexes []Index
	}
	// Walked is the result of a Walk effect: the box at the furthest target Idx64 within reach,
	// the indexes before it (the last Keep of them), and how many steps ahead it is.
	Walked struct {
		Stream  Key
		Target  *Index
		Skipped []Index
		Steps   int
	}
	Invite struct {
		Name    string
		ReadCap []byte
	}
	Introduce struct {
		Name    string
		ReadCap []byte
	}
	Remove       struct{ Member Key }
	EpochChanged struct{ Epoch int }
)

func (Send) event()           {}
func (Read) event()           {}
func (Scan) event()           {}
func (BoxRead) event()        {}
func (IndexesDerived) event() {}
func (Walked) event()         {}
func (Invite) event()         {}
func (Introduce) event()      {}
func (Remove) event()         {}
func (EpochChanged) event()   {}

type Effect interface{ effect() }

type (
	WriteBox struct {
		Index   Index
		Payload Payload
	}
	WriteTombstone struct{ Index Index }
	ReadBox        struct {
		Stream  Key
		ReadCap []byte
		Index   Index
		Recheck bool
	}
	DeriveIndexes struct {
		Stream Key
		Start  Index
		Count  int
	}
	Walk struct {
		Stream  Key
		Start   Index
		Targets []uint64
		Keep    int
	}
	Deliver struct {
		Sender  Key
		Index   Index
		Content []byte
	}
	Expire struct {
		Sender Key
		Index  Index
	}
	SendJoinReply struct {
		To    []byte
		Reply *wire.JoinReply
	}
)

func (WriteBox) effect()       {}
func (WriteTombstone) effect() {}
func (ReadBox) effect()        {}
func (DeriveIndexes) effect()  {}
func (Walk) effect()           {}
func (Deliver) effect()        {}
func (Expire) effect()         {}
func (SendJoinReply) effect()  {}
