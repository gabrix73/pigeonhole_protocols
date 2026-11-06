package client

import (
	"slices"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

// writeRaw has member i write cbor as its next box, past its engine's own sending.
func writeRaw(w *scWorld, i int, chat string, cbor []byte) {
	c := w.chatOf(i, chat)
	for _, o := range c.Group.Compose(cbor) {
		tok := o.Token
		c.Jobs = append(c.Jobs, &engine.Job{ID: c.NextID, Token: &tok, Box: wire.Frame(cbor)})
		c.NextID++
	}
}

func onlyLine(t *testing.T, w *scWorld, i int, text string) {
	t.Helper()
	if slices.ContainsFunc(w.chatOf(i, "g").Log, func(l *engine.Line) bool { return l.Notice == nil && l.Text != text }) {
		t.Fatalf("%s shows more than %q: %v", w.members[i].name, text, w.show(i, "g"))
	}
}

// TestUnknownTypeIsNoticed: a message of a type this client does not know is shown as a notice
// naming its type and version, and what follows it in the stream is read.
func TestUnknownTypeIsNoticed(t *testing.T) {
	w := newWorld("alice", "bob")
	foundAndJoin(t, w)
	g := w.chatOf(0, "g").Group
	writeRaw(w, 0, "g", (&wire.Gcm{Version: wire.CurrentVersion, MembershipHash: g.Membership(nil), MsgType: 12}).Encode())
	send(w, 0, "g", "after")
	if !w.runUntil(func() bool { return w.says(1, "g", "after") }, limit) {
		t.Fatal("bob does not read past the unknown message")
	}
	if !w.noticed(1, "g", "~alice sent a message this app cannot show (type 12, version 4): update the app") {
		t.Fatalf("no notice: %v", w.show(1, "g"))
	}
	onlyLine(t, w, 1, "after")
}

// TestPing: a ping is a notice to its readers, and no line.
func TestPing(t *testing.T) {
	w := newWorld("alice", "bob")
	foundAndJoin(t, w)
	w.feed(0, engine.Ping{Chat: "g"})
	send(w, 0, "g", "after")
	if !w.runUntil(func() bool { return w.says(1, "g", "after") }, limit) {
		t.Fatal("bob does not read alice")
	}
	if !w.noticed(1, "g", "~alice pinged") {
		t.Fatalf("no ping: %v", w.show(1, "g"))
	}
	onlyLine(t, w, 1, "after")
}
