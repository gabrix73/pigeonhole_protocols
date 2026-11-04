package remote

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/transport"
	"github.com/katzenpost/pigeonhole_protocols/go/transport/sim"
)

func TestRemote(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go Serve(l, sim.Backend{World: sim.NewWorld()})
	c, err := Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	kp, err := c.NewKeypair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.WriteBox(ctx, kp.WriteCap, kp.First, []byte("a")); err != nil {
		t.Fatal(err)
	}
	if err := c.WriteBox(ctx, kp.WriteCap, kp.First, []byte("b")); !errors.Is(err, transport.ErrBoxAlreadyExists) {
		t.Fatalf("other bytes: %v", err)
	}
	r, err := c.ReadBox(ctx, kp.ReadCap, kp.First)
	if err != nil || r.Kind != transport.Data || string(r.Plaintext) != "a" {
		t.Fatalf("read %+v %v", r, err)
	}
	m, err := c.VoucherMint(ctx, kp.WriteCap, "x", 2)
	if err != nil || len(m.Voucher) == 0 {
		t.Fatalf("mint %v", err)
	}
	if n, err := c.MaxPlaintext(ctx); err != nil || n != 1530 {
		t.Fatalf("max %d %v", n, err)
	}
}
