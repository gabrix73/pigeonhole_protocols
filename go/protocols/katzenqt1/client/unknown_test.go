package client

import (
	"reflect"
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
	writeRaw(w, 0, "g", (&wire.Gcm{Version: wire.CurrentVersion, MembershipHash: g.Membership(nil), MsgType: 13}).Encode())
	send(w, 0, "g", "after")
	if !w.runUntil(func() bool { return w.says(1, "g", "after") }, limit) {
		t.Fatal("bob does not read past the unknown message")
	}
	if !w.noticed(1, "g", "~alice sent a message this app cannot show (type 13, version 5): update the app") {
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

// TestTally: a tally message is a line carrying the tally, for the sender and its readers alike.
func TestTally(t *testing.T) {
	w := newWorld("alice", "bob")
	foundAndJoin(t, w)
	tl := wire.Tally{Kind: wire.MsgTallyVote, SurveyID: []byte("survey-0000000000"), Version: 2, Choice: []wire.Choice{{Slot: "s1", Availability: "yes"}}}
	w.feed(0, engine.SendTally{Chat: "g", Tally: tl})
	if !w.runUntil(func() bool { return w.says(1, "g", "[a vote]") }, limit) {
		t.Fatalf("bob does not read the vote: %v", w.show(1, "g"))
	}
	for i := range 2 {
		l := w.chatOf(i, "g").Log[slices.IndexFunc(w.chatOf(i, "g").Log, func(l *engine.Line) bool { return l.Tally != nil })]
		if !reflect.DeepEqual(*l.Tally, tl) || l.Sender != w.chatOf(0, "g").Group.Me() {
			t.Fatalf("%s: %+v from %x", w.members[i].name, l.Tally, l.Sender)
		}
	}
}
