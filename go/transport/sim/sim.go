// Package sim is an in-memory Pigeonhole with the katzenpost replica's rules, for tests: a box
// is kept for the epoch it was stored in and the next, a matching rewrite succeeds without
// storing it again, a different one is refused, and a tombstone is always stored.
package sim

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/pigeonhole_protocols/go/transport"
)

type box struct {
	epoch     uint64
	plaintext []byte
}

// World is the replica every Backend made from it shares.
type World struct {
	mu    sync.Mutex
	boxes map[string]box
	epoch uint64
	// Rand is where keypairs come from.
	Rand         io.Reader
	maxPlaintext int
	failWrites   int
	failOpens    int
	// Refused is each write refused for its box holding other contents: the stream's key and
	// the box's Idx64.
	Refused []Box
	Writes  int
	// Hook, if set, sees every write and read before it happens, and fails it if it returns an
	// error.
	Hook func(op string, index []byte) error
}

func NewWorld() *World {
	return &World{boxes: map[string]box{}, epoch: 1, Rand: rand.Reader, maxPlaintext: 1530}
}

func (w *World) SetEpoch(e uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.epoch = e
}

func (w *World) Epoch() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.epoch
}

// FailWrites makes the next n writes fail.
func (w *World) FailWrites(n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.failWrites = n
}

// FailOpens makes the next n replies to a voucher fail to open.
func (w *World) FailOpens(n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.failOpens = n
}

// Plaintexts is what every box holds, for tests that look at what was written.
func (w *World) Plaintexts() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([][]byte, 0, len(w.boxes))
	for _, b := range w.boxes {
		out = append(out, b.plaintext)
	}
	return out
}

func (w *World) SetMaxPlaintext(n int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.maxPlaintext = n
}

// Box names a box: its stream's key and its Idx64.
type Box struct {
	Stream string
	Idx64  uint64
}

var errFailed = errors.New("sim: write failed")

func boxKey(cap, index []byte) string {
	return string(cap[:32]) + string(index)
}

func (w *World) kept(b box) bool { return b.epoch+1 >= w.epoch }

func (w *World) write(readKey, index, plaintext []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.Hook != nil {
		if err := w.Hook("write", index); err != nil {
			return err
		}
	}
	if w.failWrites > 0 {
		w.failWrites--
		return errFailed
	}
	// As a mesh transport, a box too long for the writer's size goes at a larger one.
	if len(plaintext) > max(w.maxPlaintext, transport.BoxSizes["mixnet"]) {
		return errors.New("sim: box too large")
	}
	w.Writes++
	k := boxKey(readKey, index)
	if old, ok := w.boxes[k]; ok && w.kept(old) && len(plaintext) > 0 {
		if bytes.Equal(old.plaintext, plaintext) {
			return nil
		}
		w.Refused = append(w.Refused, Box{string(readKey[:32]), binary.LittleEndian.Uint64(index)})
		return transport.ErrBoxAlreadyExists
	}
	w.boxes[k] = box{w.epoch, bytes.Clone(plaintext)}
	return nil
}

func (w *World) read(readCap, index []byte) (transport.Read, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.Hook != nil {
		if err := w.Hook("read", index); err != nil {
			return transport.Read{}, err
		}
	}
	b, ok := w.boxes[boxKey(readCap, index)]
	switch {
	case !ok || !w.kept(b):
		return transport.Read{Kind: transport.NotFound}, nil
	case len(b.plaintext) == 0:
		return transport.Read{Kind: transport.Tombstone}, nil
	}
	return transport.Read{Kind: transport.Data, Plaintext: bytes.Clone(b.plaintext)}, nil
}

// Backend is one client's view of the world; Size, when set, is the box size it writes at.
type Backend struct {
	World *World
	Size  int
}

var _ transport.Backend = Backend{}

func (b Backend) NewKeypair(ctx context.Context) (transport.Keypair, error) {
	b.World.mu.Lock()
	wc, err := bacap.NewWriteCap(b.World.Rand)
	b.World.mu.Unlock()
	if err != nil {
		return transport.Keypair{}, err
	}
	return keypairOf(wc)
}

func keypairOf(wc *bacap.WriteCap) (transport.Keypair, error) {
	w, err := wc.MarshalBinary()
	if err != nil {
		return transport.Keypair{}, err
	}
	r, err := wc.ReadCap().MarshalBinary()
	if err != nil {
		return transport.Keypair{}, err
	}
	return transport.Keypair{WriteCap: w, ReadCap: r, First: bytes.Clone(r[32:])}, nil
}

// readCapOf is the read cap of a write cap: its public key, from its last 136 bytes.
func readCapOf(writeCap []byte) ([]byte, error) {
	wc, err := bacap.NewWriteCapFromBytes(writeCap)
	if err != nil {
		return nil, err
	}
	return wc.ReadCap().MarshalBinary()
}

func (b Backend) WriteBox(ctx context.Context, writeCap, index, plaintext []byte) error {
	rc, err := readCapOf(writeCap)
	if err != nil {
		return err
	}
	return b.World.write(rc, index, plaintext)
}

func (b Backend) ReadBox(ctx context.Context, readCap, index []byte) (transport.Read, error) {
	return b.World.read(readCap, index)
}

func (b Backend) ReplicaEpoch(ctx context.Context) (uint64, error) { return b.World.Epoch(), nil }

func (b Backend) MaxPlaintext(ctx context.Context) (int, error) {
	b.World.mu.Lock()
	defer b.World.mu.Unlock()
	if b.Size > 0 {
		return b.Size, nil
	}
	return b.World.maxPlaintext, nil
}

// Vouchers without cryptography: the voucher names its stream, the payload is the name, a zero
// byte and the joiner's read cap, the sealed reply is the reply itself, and caps are not mutated.
// A form 1 payload begins with mapHeader, which no name can begin with.

// mapHeader is the CBOR header of an empty map.
const mapHeader = 0xa0

func (b Backend) voucherStream(voucher []byte) (*bacap.WriteCap, error) {
	seed := make([]byte, 0, 96)
	for len(seed) < 96 {
		seed = append(seed, voucher...)
	}
	return bacap.NewWriteCap(bytes.NewReader(seed))
}

func (b Backend) VoucherMint(ctx context.Context, writeCap []byte, name string, form int) (transport.Minted, error) {
	v := make([]byte, 32)
	b.World.mu.Lock()
	_, err := io.ReadFull(b.World.Rand, v)
	b.World.mu.Unlock()
	if err != nil {
		return transport.Minted{}, err
	}
	rc, err := readCapOf(writeCap)
	if err != nil {
		return transport.Minted{}, err
	}
	wc, err := b.voucherStream(v)
	if err != nil {
		return transport.Minted{}, err
	}
	kp, err := keypairOf(wc)
	if err != nil {
		return transport.Minted{}, err
	}
	var payload []byte
	if form == 1 {
		payload = []byte{mapHeader}
	}
	payload = append(append(append(payload, name...), 0), rc...)
	return transport.Minted{Voucher: v, Payload: payload, WriteCap: kp.WriteCap, ReadCap: kp.ReadCap, SecretKey: v, Version: transport.VoucherVersion(payload)}, nil
}

func (b Backend) VoucherDeriveStream(ctx context.Context, voucher []byte) ([]byte, []byte, error) {
	wc, err := b.voucherStream(voucher)
	if err != nil {
		return nil, nil, err
	}
	kp, err := keypairOf(wc)
	return kp.WriteCap, kp.ReadCap, err
}

func (b Backend) VoucherInduct(ctx context.Context, voucher, payload, whoReply []byte) (transport.Inducted, error) {
	version := transport.VoucherVersion(payload)
	payload = bytes.TrimPrefix(payload, []byte{mapHeader})
	i := bytes.IndexByte(payload, 0)
	if i < 0 {
		return transport.Inducted{}, errors.New("sim: not a voucher payload")
	}
	return transport.Inducted{Name: string(payload[:i]), MutatedReadCap: bytes.Clone(payload[i+1:]), SealedReply: bytes.Clone(whoReply), Version: version}, nil
}

func (b Backend) VoucherOpen(ctx context.Context, secretKey, sealedReply, writeCap []byte) (transport.Opened, error) {
	b.World.mu.Lock()
	defer b.World.mu.Unlock()
	if b.World.failOpens > 0 {
		b.World.failOpens--
		// Read as Rust's transport errors read, so the scenarios show the same notice.
		return transport.Opened{}, errors.New("transport: sim: open failed")
	}
	return transport.Opened{WhoReply: bytes.Clone(sealedReply), MutatedWriteCap: bytes.Clone(writeCap)}, nil
}
