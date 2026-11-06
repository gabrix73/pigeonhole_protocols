package sim

import (
	"context"
	"errors"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/transport"
)

func TestReplicaRules(t *testing.T) {
	ctx := context.Background()
	w := NewWorld()
	b := Backend{World: w}
	kp, err := b.NewKeypair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(kp.WriteCap) != 168 || len(kp.ReadCap) != 136 || len(kp.First) != 104 {
		t.Fatalf("cap sizes %d %d %d", len(kp.WriteCap), len(kp.ReadCap), len(kp.First))
	}
	read := func(i []byte) transport.Read {
		r, err := b.ReadBox(ctx, kp.ReadCap, i)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := read(kp.First); r.Kind != transport.NotFound {
		t.Fatalf("unwritten box: %v", r.Kind)
	}
	if err := b.WriteBox(ctx, kp.WriteCap, kp.First, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := b.WriteBox(ctx, kp.WriteCap, kp.First, []byte("a")); err != nil {
		t.Fatalf("matching rewrite: %v", err)
	}
	if err := b.WriteBox(ctx, kp.WriteCap, kp.First, []byte("b")); !errors.Is(err, transport.ErrBoxAlreadyExists) || len(w.Refused) != 1 {
		t.Fatalf("different rewrite: %v", err)
	}
	if r := read(kp.First); r.Kind != transport.Data || string(r.Plaintext) != "a" {
		t.Fatalf("read %v %q", r.Kind, r.Plaintext)
	}
	// A matching rewrite does not store the box again, so it goes when its epoch does.
	w.SetEpoch(2)
	b.WriteBox(ctx, kp.WriteCap, kp.First, []byte("a"))
	w.SetEpoch(3)
	if r := read(kp.First); r.Kind != transport.NotFound {
		t.Fatalf("box kept past its epoch: %v", r.Kind)
	}
	next, _ := member.NextIndex(member.Index(kp.First))
	b.WriteBox(ctx, kp.WriteCap, []byte(next), []byte("c"))
	if err := b.WriteBox(ctx, kp.WriteCap, []byte(next), nil); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	if r := read([]byte(next)); r.Kind != transport.Tombstone {
		t.Fatalf("tombstone read as %v", r.Kind)
	}
	w.FailWrites(1)
	if err := b.WriteBox(ctx, kp.WriteCap, kp.First, []byte("x")); err == nil {
		t.Fatal("failed write succeeded")
	}
	other, _ := b.NewKeypair(ctx)
	if r, _ := b.ReadBox(ctx, other.ReadCap, []byte(next)); r.Kind != transport.NotFound {
		t.Fatal("streams share boxes")
	}
}

func TestVouchers(t *testing.T) {
	ctx := context.Background()
	b := Backend{World: NewWorld()}
	joiner, _ := b.NewKeypair(ctx)
	m, err := b.VoucherMint(ctx, joiner.WriteCap, "carol", 2)
	if err != nil {
		t.Fatal(err)
	}
	wc, rc, err := b.VoucherDeriveStream(ctx, m.Voucher)
	if err != nil || string(wc) != string(m.WriteCap) || string(rc) != string(m.ReadCap) {
		t.Fatal("derived stream differs from the minted one")
	}
	in, err := b.VoucherInduct(ctx, m.Voucher, m.Payload, []byte("reply"))
	if err != nil || in.Name != "carol" || string(in.MutatedReadCap) != string(joiner.ReadCap) {
		t.Fatalf("induct %+v %v", in, err)
	}
	o, err := b.VoucherOpen(ctx, m.SecretKey, in.SealedReply, joiner.WriteCap)
	if err != nil || string(o.WhoReply) != "reply" {
		t.Fatalf("open %+v %v", o, err)
	}
}
