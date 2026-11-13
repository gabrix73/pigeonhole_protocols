package store

import (
	"reflect"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
)

// A job keeps the lines packed into it, and one saved before packing has none.
func TestJobKeepsPackedLines(t *testing.T) {
	token, line := 1, 2
	c := &engine.Chat{ID: "g", Name: "g", Jobs: []*engine.Job{{ID: 1, Token: &token, Box: []byte("F"), Line: &line, Packed: []int{3, 5}}}}
	b, err := encodeChat(c)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeChat(b)
	if err != nil || !reflect.DeepEqual(back.Jobs[0].Packed, []int{3, 5}) {
		t.Fatalf("packed %v, %v", back.Jobs[0].Packed, err)
	}
	c.Jobs[0].Packed = nil
	if b, err = encodeChat(c); err != nil {
		t.Fatal(err)
	}
	if back, err = decodeChat(b); err != nil || back.Jobs[0].Packed != nil {
		t.Fatalf("packed %v, %v", back.Jobs[0].Packed, err)
	}
}

// A chat joining keeps the vouchers it minted before, and one saved before there were any has
// none.
func TestJoiningKeepsEarlierVouchers(t *testing.T) {
	c := &engine.Chat{ID: "g", Name: "g", Joining: &engine.Joining{Code: "b", SecretKey: []byte{2}, Box1: "2", Version: 2,
		Earlier: []engine.Joining{{Code: "a", SecretKey: []byte{1}, VoucherReadCap: []byte{1}, Box1: "1", Version: 2}}}}
	b, err := encodeChat(c)
	if err != nil {
		t.Fatal(err)
	}
	back, err := decodeChat(b)
	if err != nil || !reflect.DeepEqual(back.Joining, c.Joining) {
		t.Fatalf("joining %+v, %v", back.Joining, err)
	}
	c.Joining.Earlier = nil
	if b, err = encodeChat(c); err != nil {
		t.Fatal(err)
	}
	if back, err = decodeChat(b); err != nil || back.Joining.Earlier != nil {
		t.Fatalf("earlier %v, %v", back.Joining.Earlier, err)
	}
}
