package thinclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/katzenpost/pigeonhole_protocols/go/transport"
)

// TestLiveRewrite writes a box over the client daemon at $DAEMON, then again: the same bytes
// again succeed, as a write tried again after a crash must, and other bytes are refused.
func TestLiveRewrite(t *testing.T) {
	daemon := os.Getenv("DAEMON")
	if daemon == "" {
		t.Skip("DAEMON not set")
	}
	b, err := Dial(daemon, "")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	kp, err := b.NewKeypair(ctx)
	if err != nil {
		t.Fatal(err)
	}
	box := []byte("the same bytes, twice")
	for i, want := range []error{nil, nil} {
		start := time.Now()
		if err := b.WriteBox(ctx, kp.WriteCap, kp.First, box); !errors.Is(err, want) {
			t.Fatalf("write %d: %v", i+1, err)
		}
		t.Logf("write %d: %v", i+1, time.Since(start))
	}
	if err := b.WriteBox(ctx, kp.WriteCap, kp.First, []byte("other bytes")); !errors.Is(err, transport.ErrBoxAlreadyExists) {
		t.Fatalf("other bytes: %v", err)
	}
	r, err := b.ReadBox(ctx, kp.ReadCap, kp.First)
	if err != nil || r.Kind != transport.Data || !bytes.Equal(r.Plaintext, box) {
		t.Fatalf("read back: %v %v %q", err, r.Kind, r.Plaintext)
	}
}
