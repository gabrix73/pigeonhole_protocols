// Package thinclient is a transport over the katzenpost client daemon, through its thin client.
package thinclient

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/pigeonhole_protocols/go/transport"
)

type Backend struct {
	Client *thin.ThinClient
}

var _ transport.Backend = Backend{}

func readCap(b []byte) (*bacap.ReadCap, error) {
	rc := bacap.NewEmptyReadCap()
	return rc, rc.UnmarshalBinary(b)
}

func marshal(m interface{ MarshalBinary() ([]byte, error) }) []byte {
	b, _ := m.MarshalBinary()
	return b
}

// await runs f, cancelling the daemon's resending of envelope when ctx is done first.
func (b Backend) await(ctx context.Context, envelope *[32]byte, f func() (*thin.StartResendingResult, error)) (*thin.StartResendingResult, error) {
	type result struct {
		r   *thin.StartResendingResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := f()
		done <- result{r, err}
	}()
	select {
	case r := <-done:
		return r.r, r.err
	case <-ctx.Done():
		_ = b.Client.CancelResendingEncryptedMessage(envelope)
		<-done
		return nil, ctx.Err()
	}
}

func (b Backend) NewKeypair(ctx context.Context) (transport.Keypair, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return transport.Keypair{}, err
	}
	wc, rc, first, err := b.Client.NewKeypair(seed)
	if err != nil {
		return transport.Keypair{}, err
	}
	return transport.Keypair{WriteCap: marshal(wc), ReadCap: marshal(rc), First: marshal(first)}, nil
}

// WriteBox writes a box. The same bytes again are the same box, as BACAP seals them, and replicas
// take a box they hold again as written; only other bytes are ErrBoxAlreadyExists.
func (b Backend) WriteBox(ctx context.Context, writeCap, index, plaintext []byte) error {
	wc, err := bacap.NewWriteCapFromBytes(writeCap)
	if err != nil {
		return err
	}
	idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(index)
	if err != nil {
		return err
	}
	ct, desc, hash, _, err := b.Client.EncryptWrite(plaintext, wc, idx)
	if err != nil {
		return err
	}
	_, err = b.await(ctx, hash, func() (*thin.StartResendingResult, error) {
		return b.Client.StartResendingEncryptedMessageReturnBoxExists(nil, wc, nil, nil, desc, ct, hash)
	})
	if errors.Is(err, thin.ErrBoxAlreadyExists) {
		return transport.ErrBoxAlreadyExists
	}
	return err
}

func (b Backend) ReadBox(ctx context.Context, rcBytes, index []byte) (transport.Read, error) {
	rc, err := readCap(rcBytes)
	if err != nil {
		return transport.Read{}, err
	}
	idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(index)
	if err != nil {
		return transport.Read{}, err
	}
	ct, desc, hash, _, err := b.Client.EncryptRead(rc, idx)
	if err != nil {
		return transport.Read{}, err
	}
	r, err := b.await(ctx, hash, func() (*thin.StartResendingResult, error) {
		return b.Client.StartResendingEncryptedMessageNoRetry(rc, nil, index, nil, desc, ct, hash)
	})
	switch {
	case errors.Is(err, thin.ErrBoxIDNotFound):
		return transport.Read{Kind: transport.NotFound}, nil
	case errors.Is(err, thin.ErrTombstone):
		return transport.Read{Kind: transport.Tombstone}, nil
	case err != nil:
		return transport.Read{}, err
	case len(r.Plaintext) == 0:
		return transport.Read{Kind: transport.Tombstone}, nil
	}
	return transport.Read{Kind: transport.Data, Plaintext: r.Plaintext}, nil
}

// ReplicaEpoch is the epoch most storage replicas are in: each publishes envelope keys up to the
// epoch after its own.
func (b Backend) ReplicaEpoch(ctx context.Context) (uint64, error) {
	doc := b.Client.PKIDocument()
	if doc == nil {
		return 0, errors.New("thinclient: no PKI document")
	}
	var epochs []uint64
	for _, r := range doc.StorageReplicas {
		var top uint64
		for e := range r.EnvelopeKeys {
			top = max(top, e)
		}
		if top > 0 {
			epochs = append(epochs, top-1)
		}
	}
	return mostCommon(epochs)
}

func mostCommon(epochs []uint64) (uint64, error) {
	if len(epochs) == 0 {
		return 0, errors.New("thinclient: no storage replica epochs")
	}
	slices.Sort(epochs)
	best, bestN, n := epochs[0], 0, 0
	for i, e := range epochs {
		if i > 0 && e == epochs[i-1] {
			n++
		} else {
			n = 1
		}
		if n > bestN {
			best, bestN = e, n
		}
	}
	return best, nil
}

func (b Backend) MaxPlaintext(ctx context.Context) (int, error) {
	g := b.Client.GetPigeonholeGeometry()
	if g == nil {
		return 0, errors.New("thinclient: no pigeonhole geometry")
	}
	return g.MaxPlaintextPayloadLength, nil
}

func (b Backend) VoucherMint(ctx context.Context, writeCap []byte, name string) (transport.Minted, error) {
	r, err := b.Client.VoucherMint(writeCap, name)
	if err != nil {
		return transport.Minted{}, err
	}
	return transport.Minted{Voucher: r.Voucher, Payload: r.VoucherPayload, WriteCap: r.VoucherWriteCap,
		ReadCap: r.VoucherReadCap, SecretKey: r.VoucherSecretKey}, nil
}

func (b Backend) VoucherDeriveStream(ctx context.Context, voucher []byte) ([]byte, []byte, error) {
	r, err := b.Client.VoucherDeriveStream(voucher)
	if err != nil {
		return nil, nil, err
	}
	return r.VoucherWriteCap, r.VoucherReadCap, nil
}

func (b Backend) VoucherInduct(ctx context.Context, voucher, payload, whoReply []byte) (transport.Inducted, error) {
	r, err := b.Client.VoucherInduct(voucher, payload, whoReply)
	if err != nil {
		return transport.Inducted{}, err
	}
	return transport.Inducted{Name: r.DisplayName, MutatedReadCap: r.MutatedMessageReadCap, SealedReply: r.SealedReply}, nil
}

func (b Backend) VoucherOpen(ctx context.Context, secretKey, sealedReply, writeCap []byte) (transport.Opened, error) {
	r, err := b.Client.VoucherOpen(secretKey, sealedReply, writeCap)
	if err != nil {
		return transport.Opened{}, err
	}
	return transport.Opened{WhoReply: r.WhoReply, MutatedWriteCap: r.MutatedMessageWriteCap}, nil
}
