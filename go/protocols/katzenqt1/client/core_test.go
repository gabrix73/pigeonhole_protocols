package client

import (
	"slices"
	"strings"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/transport/sim"
)

// Members chatting over the in-memory Pigeonhole, as group_chat_client's core tests do.

func newWorld(names ...string) *scWorld {
	w := &scWorld{sim: sim.NewWorld(), held: map[int]bool{}, epoch: 1}
	for _, n := range names {
		w.who(n)
	}
	return w
}

// tick runs one action, or moves the clock on to the next thing due; false when there is
// nothing left at all.
func (w *scWorld) tick() bool {
	if w.act() {
		return true
	}
	due := -1
	for _, l := range w.later {
		if !w.held[l.who] && (due < 0 || l.at < due) {
			due = l.at
		}
	}
	if due < 0 {
		return false
	}
	w.runTo(due)
	return true
}

// runUntil runs until done holds or the clock passes limit milliseconds from now.
func (w *scWorld) runUntil(done func() bool, limit int) bool {
	start := w.clock
	for !done() {
		if w.clock > start+limit || !w.tick() {
			return done()
		}
	}
	return true
}

func (w *scWorld) says(i int, chat, text string) bool {
	c := w.chatOf(i, chat)
	return c != nil && slices.ContainsFunc(c.Log, func(l *engine.Line) bool { return l.Notice == nil && l.Text == text })
}

func (w *scWorld) noticed(i int, chat, text string) bool {
	c := w.chatOf(i, chat)
	return c != nil && slices.ContainsFunc(c.Log, func(l *engine.Line) bool {
		return l.Notice != nil && strings.HasPrefix(engine.Plain(l.Notice), text)
	})
}

func (w *scWorld) joined(i int, chat string) bool {
	c := w.chatOf(i, chat)
	return c != nil && c.Group != nil
}

func (w *scWorld) idle() bool {
	for _, m := range w.members {
		for _, c := range m.eng.State.Chats {
			if len(c.Jobs) > 0 {
				return false
			}
		}
	}
	return true
}

const limit = 600000

func create(w *scWorld, i int, chat string) {
	w.feed(i, engine.Create{Chat: engine.ChatID(chat), Name: chat})
}

func send(w *scWorld, i int, chat, text string) {
	w.feed(i, engine.Send{Chat: engine.ChatID(chat), Text: text})
}

// induct has member i add member j, who mints a voucher to join chat.
func induct(t *testing.T, w *scWorld, i, j int, chat string) {
	t.Helper()
	w.feed(j, engine.Join{Chat: engine.ChatID(chat), Name: chat})
	if !w.runUntil(func() bool { return w.code(j, chat) != "" }, limit) {
		t.Fatal("no voucher code")
	}
	w.feed(i, engine.Induct{Chat: engine.ChatID(chat), Code: w.code(j, chat)})
	added := "added ~" + w.members[j].name
	if !w.runUntil(func() bool { return w.joined(j, chat) && w.noticed(i, chat, added) }, limit) {
		t.Fatalf("%s does not join", w.members[j].name)
	}
}

// foundAndJoin has Alice found g and add Bob.
func foundAndJoin(t *testing.T, w *scWorld) {
	t.Helper()
	create(w, 0, "g")
	induct(t, w, 0, 1, "g")
}

func TestTwoMembers(t *testing.T) {
	w := newWorld("alice", "bob")
	foundAndJoin(t, w)
	send(w, 1, "g", "hi from bob")
	send(w, 0, "g", "hi from alice")
	if !w.runUntil(func() bool { return w.says(0, "g", "hi from bob") && w.says(1, "g", "hi from alice") }, limit) {
		t.Fatal("alice and bob do not read each other")
	}
	// Bob acknowledges what he read in his next message.
	send(w, 1, "g", "read you")
	acked := func() bool {
		c := w.chatOf(0, "g")
		return slices.ContainsFunc(c.Log, func(l *engine.Line) bool { return l.Text == "hi from alice" && c.Acknowledged(l) })
	}
	if !w.runUntil(acked, limit) {
		t.Fatal("bob's message does not acknowledge alice's")
	}
	if !w.idle() {
		t.Fatal("something is left to write")
	}
	if !slices.Contains(w.chatOf(0, "g").Names.Values(), "bob") {
		t.Fatal("alice does not know bob by name")
	}
}

// TestJoinsThroughAReplyWithoutRosters: katzenqt replies to a voucher with the members' read caps
// alone when its conversation keeps no rosters, as one does that had members before rosters or
// joined through such a reply. The newcomer joins anyway, as katzenqt's own joiner does, and
// reads and is read by every member.
func TestJoinsThroughAReplyWithoutRosters(t *testing.T) {
	w := newWorld("alice", "bob", "carol")
	foundAndJoin(t, w)
	w.rosterless = map[int]bool{0: true}
	induct(t, w, 0, 2, "g")
	send(w, 2, "g", "carol here")
	send(w, 0, "g", "hi carol")
	send(w, 1, "g", "bob too")
	if !w.runUntil(func() bool {
		return w.says(0, "g", "carol here") && w.says(1, "g", "carol here") &&
			w.says(2, "g", "hi carol") && w.says(2, "g", "bob too")
	}, limit) {
		t.Fatal("carol does not read or is not read by every member")
	}
}

func TestThreeMembers(t *testing.T) {
	w := newWorld("alice", "bob", "carol")
	foundAndJoin(t, w)
	// Carol joins through Bob; Alice learns of her from Bob's Introduction.
	induct(t, w, 1, 2, "g")
	if !w.runUntil(func() bool { return w.noticed(0, "g", "~bob added ~carol") }, limit) {
		t.Fatal("alice does not hear of carol")
	}
	send(w, 2, "g", "carol here")
	send(w, 0, "g", "welcome carol")
	if !w.runUntil(func() bool {
		return w.says(0, "g", "carol here") && w.says(1, "g", "carol here") && w.says(2, "g", "welcome carol")
	}, limit) {
		t.Fatal("the three do not all read each other")
	}
}

func TestRemoveAndLeave(t *testing.T) {
	w := newWorld("alice", "bob", "carol")
	foundAndJoin(t, w)
	induct(t, w, 0, 2, "g")
	if !w.runUntil(func() bool { return w.noticed(1, "g", "~alice added ~carol") }, limit) {
		t.Fatal("bob does not hear of carol")
	}
	send(w, 2, "g", "carol before")
	w.runUntil(func() bool { return w.says(0, "g", "carol before") && w.says(1, "g", "carol before") }, limit)
	carol := w.chatOf(2, "g").Group.Me()
	// Alice stops reading Carol; Bob does not.
	w.feed(0, engine.RemoveMember{Chat: "g", Who: carol})
	c := w.chatOf(0, "g")
	if c.Group.Readers.Len() != 1 || w.says(0, "g", "carol before") {
		t.Fatal("remove does not stop reading a member and delete what they sent")
	}
	send(w, 2, "g", "carol after")
	send(w, 1, "g", "bob after")
	if !w.runUntil(func() bool { return w.says(1, "g", "carol after") && w.says(0, "g", "bob after") }, limit) ||
		w.says(0, "g", "carol after") {
		t.Fatal("the others do not still read the removed member, or alice does")
	}
	w.feed(0, engine.RemoveMember{Chat: "g", Who: carol})
	if !w.noticed(0, "g", "that member is no longer in this group") {
		t.Fatal("removing a member no longer there does not say so")
	}
	// Bob leaves; what was under way for the group comes to nothing.
	w.feed(1, engine.Leave{Chat: "g"})
	w.runUntil(func() bool { return false }, 60000)
	if w.chatOf(1, "g") != nil {
		t.Fatal("leave does not delete the group")
	}
}

func TestRename(t *testing.T) {
	w := newWorld("alice", "bob")
	foundAndJoin(t, w)
	send(w, 0, "g", "before")
	// Renamed while that message and the reads of Bob's stream are under way.
	w.feed(0, engine.Rename{Chat: "g", To: "friends"})
	if c := w.chatOf(0, "g"); c.Name != "friends" || !w.noticed(0, "g", "renamed from g") {
		t.Fatal("rename does not give a group another name")
	}
	send(w, 1, "g", "from bob")
	if !w.runUntil(func() bool { return w.says(1, "g", "before") && w.says(0, "g", "from bob") }, limit) {
		t.Fatal("what was under way does not reach the renamed group")
	}
	w.feed(0, engine.Create{Chat: "other", Name: "friends"})
	if w.chatOf(0, "other") != nil || !w.noticed(0, "g", "you already have a group called friends") {
		t.Fatal("a second group takes a name in use")
	}
	w.feed(0, engine.Rename{Chat: "g", To: "g"})
	if w.chatOf(0, "g").Name != "g" {
		t.Fatal("a group cannot take its old name back")
	}
}

func TestFailingWrites(t *testing.T) {
	w := newWorld("alice", "bob")
	foundAndJoin(t, w)
	w.sim.FailWrites(3)
	send(w, 0, "g", "eventually")
	if !w.runUntil(func() bool { return w.says(1, "g", "eventually") }, limit) {
		t.Fatal("a write that fails is not tried again")
	}
}

func TestBackfill(t *testing.T) {
	w := newWorld("alice", "bob")
	foundAndJoin(t, w)
	send(w, 0, "g", "one")
	w.runUntil(func() bool { return w.says(1, "g", "one") }, limit)
	before := w.sim.Writes
	// A new replica epoch: each member rewrites its boxes, with the bytes first written.
	for _, e := range []int{2, 3} {
		w.sim.SetEpoch(uint64(e))
		w.feed(0, engine.Epoch{N: e})
		w.feed(1, engine.Epoch{N: e})
		w.runUntil(w.idle, limit)
	}
	if w.sim.Writes <= before {
		t.Fatal("a new epoch rewrites nothing")
	}
	if !w.idle() || len(w.sim.Refused) > 0 {
		t.Fatalf("a rewrite is refused: %v", w.sim.Refused)
	}
}

func TestNameTaken(t *testing.T) {
	w := newWorld("alice")
	create(w, 0, "fu")
	w.runUntil(func() bool { return w.joined(0, "fu") }, limit)
	w.feed(0, engine.Join{Chat: "fu2", Name: "fu"})
	w.feed(0, engine.Create{Chat: "fu3", Name: "fu"})
	if len(w.members[0].eng.State.Chats) != 1 || !w.noticed(0, "fu", "you already have a group called fu: to join") ||
		w.chatOf(0, "fu").Joining != nil {
		t.Fatal("a name already used is not refused with a reason")
	}
}

func TestVoucherCode(t *testing.T) {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	if engine.VoucherCode([]byte("hello world")) != "aGVsbG8gd29ybGQ=" || engine.VoucherCode(nil) != "" {
		t.Fatal("voucher code is not padded base64")
	}
	w := newWorld("alice")
	create(w, 0, "g")
	w.runUntil(func() bool { return w.joined(0, "g") }, limit)
	w.feed(0, engine.Induct{Chat: "g", Code: "abc!"})
	if !w.noticed(0, "g", "that is not a voucher code") {
		t.Fatal("junk taken for a voucher")
	}
}

// TestGroupMadeLateInAHighEpochKeepsItsRecords: the replicas are at epoch 491 when the group is
// made, as on a real network, and the engines heard so before. The first message must still be
// found by the acknowledgement that names it after the next epoch report.
func TestGroupMadeLateInAHighEpochKeepsItsRecords(t *testing.T) {
	w := newWorld("alice", "bob")
	w.sim.SetEpoch(491)
	w.feed(0, engine.Epoch{N: 491})
	w.feed(1, engine.Epoch{N: 491})
	foundAndJoin(t, w)
	send(w, 0, "g", "first")
	if !w.runUntil(func() bool { return w.says(1, "g", "first") }, limit) {
		t.Fatal("bob does not read alice")
	}
	w.feed(0, engine.Epoch{N: 491})
	w.feed(1, engine.Epoch{N: 491})
	send(w, 1, "g", "read it")
	acked := func() bool {
		c := w.chatOf(0, "g")
		return slices.ContainsFunc(c.Log, func(l *engine.Line) bool { return l.Text == "first" && c.Acknowledged(l) })
	}
	if !w.runUntil(acked, limit) {
		t.Fatal("the acknowledgement of a message written before the epoch report is lost")
	}
}
