package client

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

func bytesOf(n, seed int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + seed) % 251)
	}
	return b
}

func (w *scWorld) attachmentOf(i int, chat, name string) *engine.Attachment {
	c := w.chatOf(i, chat)
	if c == nil {
		return nil
	}
	for _, l := range c.Log {
		if l.Attachment != nil && l.Attachment.Name == name {
			return l.Attachment
		}
	}
	return nil
}

// received says whether member i has the file a line called name carries.
func (w *scWorld) received(i int, chat, name string) bool {
	a := w.attachmentOf(i, chat, name)
	return a != nil && w.members[i].files[a.File] != nil
}

func sendFile(w *scWorld, i int, chat, name string, b []byte) {
	w.feed(i, engine.SendFile{Chat: engine.ChatID(chat), Name: name, Bytes: b})
}

func TestLongMessage(t *testing.T) {
	w := newWorld("alice", "bob")
	foundAndJoin(t, w)
	text := strings.Repeat("a long message ", 400)
	send(w, 0, "g", text)
	send(w, 0, "g", "after it")
	if !w.runUntil(func() bool { return w.says(1, "g", text) && w.says(1, "g", "after it") }, limit) {
		t.Fatal("a message too long for a box does not go by a substream")
	}
	log := w.chatOf(1, "g").Log
	if log[len(log)-2].Text != text || log[len(log)-1].Text != "after it" {
		t.Fatal("what was sent after it does not come after it")
	}
}

func TestImage(t *testing.T) {
	w := newWorld("alice", "bob")
	foundAndJoin(t, w)
	pic := bytesOf(20000, 7)
	sendFile(w, 0, "g", "cat.png", pic)
	if !slices.ContainsFunc(w.chatOf(0, "g").Log, func(l *engine.Line) bool { return l.Attachment != nil && l.Status == engine.Pending }) {
		t.Fatal("a file sent does not show at once")
	}
	if !w.runUntil(func() bool { return w.received(1, "g", "cat.png") }, limit) {
		t.Fatal("bob does not receive alice's picture")
	}
	w.runUntil(func() bool { return len(w.chatOf(0, "g").Jobs) == 0 }, limit)
	if a := w.attachmentOf(1, "g", "cat.png"); a.Filetype != "image/png" || a.Size != 20000 || !bytes.Equal(w.members[1].files[a.File], pic) {
		t.Fatal("the picture comes without its type, size or bytes")
	}
	if a := w.attachmentOf(0, "g", "cat.png"); !bytes.Equal(w.members[0].files[a.File], pic) {
		t.Fatal("alice does not keep what she sent")
	}
	if !slices.ContainsFunc(w.chatOf(0, "g").Log, func(l *engine.Line) bool { return l.Attachment != nil && l.Status == engine.Sent }) {
		t.Fatal("alice does not see it written")
	}
	for f := range w.members[0].files {
		if strings.HasPrefix(f, "spool/") {
			t.Fatal("what was spooled to send it is still there")
		}
	}
}

func TestConcurrentChunks(t *testing.T) {
	w := newWorld("alice", "bob")
	foundAndJoin(t, w)
	doc := bytesOf(30000, 5)
	sendFile(w, 0, "g", "big.bin", doc)
	out := func() int {
		n := 0
		for _, q := range w.queue {
			if _, ok := q.a.(engine.DoWriteChunk); ok {
				n++
			}
		}
		return n
	}
	if !w.runUntil(func() bool { return out() >= engine.Window }, limit) {
		t.Fatal("an upload does not write several boxes at once")
	}
	// The replicas answer the writes in the opposite order.
	slices.Reverse(w.queue)
	if !w.runUntil(func() bool { return w.received(1, "g", "big.bin") }, limit) {
		t.Fatal("bob does not receive the file")
	}
	if a := w.attachmentOf(1, "g", "big.bin"); !bytes.Equal(w.members[1].files[a.File], doc) {
		t.Fatal("boxes written out of order make another file")
	}
}

func TestFileLimits(t *testing.T) {
	w := newWorld("alice")
	create(w, 0, "g")
	w.runUntil(func() bool { return w.joined(0, "g") }, limit)
	sendFile(w, 0, "g", "huge.bin", make([]byte, wire.MaxFile+1))
	if len(w.chatOf(0, "g").Jobs) != 0 || !w.noticed(0, "g", "that file is too large to send") {
		t.Fatal("a file too large is not refused")
	}
}

func TestRemoveDeletesFiles(t *testing.T) {
	w := newWorld("alice", "bob")
	foundAndJoin(t, w)
	sendFile(w, 0, "g", "a.png", bytesOf(500, 7))
	if !w.runUntil(func() bool { return w.received(1, "g", "a.png") }, limit) {
		t.Fatal("bob does not receive the file")
	}
	a := w.attachmentOf(1, "g", "a.png")
	alice := w.chatOf(1, "g").Group.Readers.Keys()[0]
	w.feed(1, engine.RemoveMember{Chat: "g", Who: alice})
	w.runUntil(func() bool { return false }, limit)
	if w.members[1].files[a.File] != nil {
		t.Fatal("removing a member does not delete the files they sent")
	}
	w.feed(0, engine.Leave{Chat: "g"})
	w.runUntil(func() bool { return false }, limit)
	if len(w.members[0].files) != 0 {
		t.Fatalf("leaving a group leaves its files: %v", len(w.members[0].files))
	}
	if wire.SafeName("../../etc/passwd") != "_.._etc_passwd" {
		t.Fatal("a name is not made safe")
	}
}
