package client

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
	"github.com/katzenpost/pigeonhole_protocols/go/transport"
	"github.com/katzenpost/pigeonhole_protocols/go/transport/sim"
)

func open(t *testing.T, w *sim.World, dir, name string) *Client {
	t.Helper()
	c, err := Open(context.Background(), Config{StateDir: dir, Name: name, Backend: sim.Backend{World: w}, EpochPoll: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// waitFor polls until ok holds, for up to a minute.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(time.Minute); !ok(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("waited a minute for %s", what)
		}
	}
}

func has(t *testing.T, c *Client, id engine.ChatID, text string) bool {
	ls, err := c.Lines(id, -1)
	if err != nil {
		t.Fatal(err)
	}
	return slices.ContainsFunc(ls, func(l LineView) bool { return l.Notice == nil && l.Text == text })
}

// TestLeaveStopsReading leaves a group while reading for a voucher never published: the client
// reads for it no more.
func TestLeaveStopsReading(t *testing.T) {
	w := sim.NewWorld()
	var reads atomic.Int64
	w.Hook = func(op string, _ []byte) error {
		if op == "read" {
			reads.Add(1)
		}
		return nil
	}
	alice := open(t, w, t.TempDir(), "alice")
	defer alice.Close()
	g, err := alice.Create("g")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alice's group", func() bool { v, _ := alice.Chat(g); return v.Joined })
	if err := alice.Invite(g, engine.VoucherCode(make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	before := reads.Load()
	waitFor(t, "the voucher to be read for again", func() bool { return reads.Load() > before+1 })
	if err := alice.Leave(g); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	left := reads.Load()
	time.Sleep(2 * RetryMs * time.Millisecond)
	if n := reads.Load(); n != left {
		t.Fatalf("%d reads after leaving", n-left)
	}
}

func TestClient(t *testing.T) {
	w := sim.NewWorld()
	aliceDir, bobDir := t.TempDir(), t.TempDir()
	alice, bob := open(t, w, aliceDir, "alice"), open(t, w, bobDir, "bob")
	events := alice.Subscribe()
	g, err := alice.Create("g")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Create("g"); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("a name taken: %v", err)
	}
	if err := alice.Send("nope", "x"); !errors.Is(err, ErrNoSuchChat) {
		t.Fatalf("no such group: %v", err)
	}
	bg, err := bob.Join("g")
	if err != nil {
		t.Fatal(err)
	}
	var code string
	waitFor(t, "a voucher code", func() bool {
		v, _ := bob.Chat(bg)
		code = v.Code
		return code != ""
	})
	waitFor(t, "alice's group", func() bool { v, _ := alice.Chat(g); return v.Joined })
	if err := alice.Invite(g, "abc!"); !errors.Is(err, ErrNotAVoucher) {
		t.Fatalf("junk taken for a voucher: %v", err)
	}
	if err := alice.Invite(g, code); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob to join", func() bool { v, _ := bob.Chat(bg); return v.Joined })
	if err := bob.Send(bg, "hi alice"); err != nil {
		t.Fatal(err)
	}
	if err := alice.Send(g, "hi bob"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "each to read the other", func() bool { return has(t, alice, g, "hi alice") && has(t, bob, bg, "hi bob") })
	select {
	case e := <-events:
		if e.Chat != g {
			t.Fatalf("event for %s", e.Chat)
		}
	default:
		t.Fatal("no events")
	}
	bobKey, err := alice.MemberNamed(g, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if bobKey == "" {
		t.Fatal("bob not found by name")
	}
	v, _ := alice.Chat(g)
	if err := alice.Remove(g, v.Me); !errors.Is(err, ErrRemoveSelf) {
		t.Fatalf("remove ourselves: %v", err)
	}
	if err := alice.Remove(g, "nobody"); !errors.Is(err, ErrNoSuchMember) {
		t.Fatalf("remove nobody: %v", err)
	}
	// Alice closes, and opens again where she was.
	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}
	for range events {
	}
	if err := alice.Send(g, "closed"); !errors.Is(err, ErrClosed) {
		t.Fatalf("send after close: %v", err)
	}
	alice = open(t, w, aliceDir, "alice")
	defer alice.Close()
	defer bob.Close()
	if !has(t, alice, g, "hi alice") {
		t.Fatal("alice forgets what she read")
	}
	if err := alice.Send(g, "back again"); err != nil {
		t.Fatal(err)
	}
	if err := bob.Send(bg, "read you"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the conversation to carry on", func() bool { return has(t, bob, bg, "back again") && has(t, alice, g, "read you") })
	waitFor(t, "bob to acknowledge", func() bool {
		ls, _ := alice.Lines(g, -1)
		return slices.ContainsFunc(ls, func(l LineView) bool { return l.Text == "hi bob" && l.Mine && l.Acked })
	})
	if len(w.Refused) > 0 {
		t.Fatalf("refused: %v", w.Refused)
	}
}

// flaky is a Pigeonhole whose next failing reads fail, as reads over the mixnet sometimes do.
type flaky struct {
	sim.Backend
	failing *atomic.Int64
}

func (f flaky) ReadBox(ctx context.Context, readCap, index []byte) (transport.Read, error) {
	if f.failing.Add(-1) >= 0 {
		return transport.Read{}, errors.New("read timed out")
	}
	return f.Backend.ReadBox(ctx, readCap, index)
}

// TestVoucherReadsThatFailAreRetried: a joiner whose reads of the voucher's reply fail for a
// while still joins once they succeed; so does an introducer whose reads of the voucher fail.
func TestVoucherReadsThatFailAreRetried(t *testing.T) {
	w := sim.NewWorld()
	var aliceFailing, bobFailing atomic.Int64
	openFlaky := func(name string, failing *atomic.Int64) *Client {
		c, err := Open(context.Background(), Config{StateDir: t.TempDir(), Name: name,
			Backend: flaky{sim.Backend{World: w}, failing}, EpochPoll: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	alice, bob := openFlaky("alice", &aliceFailing), openFlaky("bob", &bobFailing)
	defer alice.Close()
	defer bob.Close()
	g, err := alice.Create("g")
	if err != nil {
		t.Fatal(err)
	}
	bg, err := bob.Join("g")
	if err != nil {
		t.Fatal(err)
	}
	var code string
	waitFor(t, "a voucher code and alice's group", func() bool {
		v, _ := bob.Chat(bg)
		a, _ := alice.Chat(g)
		code = v.Code
		return code != "" && a.Joined
	})
	aliceFailing.Store(3)
	bobFailing.Store(3)
	if err := alice.Invite(g, code); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob to join", func() bool { v, _ := bob.Chat(bg); return v.Joined })
}

// TestReplySpansBoxes: a sealed reply larger than a box is written framed over boxes 1 on and
// read back by the joiner. The sim's seal adds nothing, so the reply only outgrows a box once
// it names two members: carol's, from alice, after bob is in.
func TestReplySpansBoxes(t *testing.T) {
	w := sim.NewWorld()
	w.SetMaxPlaintext(200)
	alice := open(t, w, t.TempDir(), "alice")
	defer alice.Close()
	g, err := alice.Create("g")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alice's group", func() bool { v, _ := alice.Chat(g); return v.Joined })
	for _, name := range []string{"bob", "carol"} {
		c := open(t, w, t.TempDir(), name)
		defer c.Close()
		cg, err := c.Join("g")
		if err != nil {
			t.Fatal(err)
		}
		var code string
		waitFor(t, name+"'s voucher code", func() bool { v, _ := c.Chat(cg); code = v.Code; return code != "" })
		if err := alice.Invite(g, code); err != nil {
			t.Fatal(err)
		}
		waitFor(t, name+" to join", func() bool { v, _ := c.Chat(cg); return v.Joined })
	}
	pieces := 0
	for _, p := range w.Plaintexts() {
		if len(p) > 0 && p[0] == 'C' {
			pieces++
		}
	}
	if pieces == 0 {
		t.Fatal("no reply was split into C pieces")
	}
}

// joinAndChat has alice on wire version va found a group that bob on vb joins, and each read the
// other; it returns every box written.
func joinAndChat(t *testing.T, va, vb uint64) [][]byte {
	w := sim.NewWorld()
	openV := func(name string, v uint64) *Client {
		c, err := Open(context.Background(), Config{StateDir: t.TempDir(), Name: name, Backend: sim.Backend{World: w}, EpochPoll: time.Second, WireVersion: v})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	alice, bob := openV("alice", va), openV("bob", vb)
	defer alice.Close()
	defer bob.Close()
	g, err := alice.Create("g")
	if err != nil {
		t.Fatal(err)
	}
	bg, err := bob.Join("g")
	if err != nil {
		t.Fatal(err)
	}
	var code string
	waitFor(t, "a voucher code and alice's group", func() bool {
		v, _ := bob.Chat(bg)
		a, _ := alice.Chat(g)
		code = v.Code
		return code != "" && a.Joined
	})
	if err := alice.Invite(g, code); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob to join", func() bool { v, _ := bob.Chat(bg); return v.Joined })
	if err := alice.Send(g, "hi bob"); err != nil {
		t.Fatal(err)
	}
	if err := bob.Send(bg, "hi alice"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "each to read the other", func() bool { return has(t, alice, g, "hi alice") && has(t, bob, bg, "hi bob") })
	return w.Plaintexts()
}

// groupBoxes is the CBOR of every box holding a group message.
func groupBoxes(boxes [][]byte) [][]byte {
	var out [][]byte
	for _, p := range boxes {
		if len(p) > 1 && p[0] == 'F' && wire.ToMessage(p[1:]) != nil {
			out = append(out, p[1:])
		}
	}
	return out
}

// TestWireVersion: version 3 writes maps, as the version 3 vectors encode them, mints the map
// form and gets the reply unframed; version 4 writes arrays, mints the array form and gets the
// reply framed.
func TestWireVersion(t *testing.T) {
	for _, v := range []uint64{3, 4} {
		boxes := joinAndChat(t, v, v)
		major := byte(4)
		if v == wire.MapVersion {
			major = 5
		}
		mapPayload, arrayPayload, unframed, framed := false, false, false, false
		for _, p := range boxes {
			mapPayload = mapPayload || bytes.HasPrefix(p, []byte("\xa0bob\x00"))
			arrayPayload = arrayPayload || bytes.HasPrefix(p, []byte("bob\x00"))
			unframed = unframed || wire.DecodeReplyWho(p) != nil
			framed = framed || len(p) > 1 && p[0] == 'F' && wire.ToMessage(p[1:]) == nil && wire.DecodeReplyWho(p[1:]) != nil
		}
		if mapPayload != (v == 3) || arrayPayload != (v == 4) {
			t.Errorf("version %d: payload map %v array %v", v, mapPayload, arrayPayload)
		}
		if unframed != (v == 3) || framed != (v == 4) {
			t.Errorf("version %d: reply unframed %v framed %v", v, unframed, framed)
		}
		gb := groupBoxes(boxes)
		if len(gb) < 4 {
			t.Fatalf("version %d: %d group boxes", v, len(gb))
		}
		for _, cbor := range gb {
			if cbor[0]>>5 != major {
				t.Errorf("version %d: a box in the other form: %x", v, cbor)
			}
			if b := wire.Box(wire.ToMessage(cbor), v); !bytes.Equal(b[1:], cbor) {
				t.Errorf("version %d: written otherwise: %x, not %x", v, cbor, b[1:])
			}
		}
	}
}

// TestMixedWireVersions: a member on version 3 and one on 4 join each other's groups and read
// each other.
func TestMixedWireVersions(t *testing.T) {
	for _, vs := range [][2]uint64{{3, 4}, {4, 3}} {
		majors := map[byte]bool{}
		for _, cbor := range groupBoxes(joinAndChat(t, vs[0], vs[1])) {
			majors[cbor[0]>>5] = true
		}
		if !majors[4] || !majors[5] || len(majors) != 2 {
			t.Errorf("%d with %d: forms %v", vs[0], vs[1], majors)
		}
	}
}
