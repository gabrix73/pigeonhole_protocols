package client

import (
	"bytes"
	"os"
	"slices"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/store"
)

// onDisk keeps every member's state on disk.
func onDisk(t *testing.T, w *scWorld) {
	for _, m := range w.members {
		st, err := store.Open(t.TempDir(), store.Options{NoSync: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		m.st = st
	}
}

// restart stops member i, as a crash would: what it had under way is lost, and it starts again
// from what is on disk.
func (w *scWorld) restart(t *testing.T, i int) {
	t.Helper()
	w.restartMember(i)
}

func (w *scWorld) restartMember(i int) {
	if w.restarts == nil {
		w.restarts = map[int]int{}
	}
	w.restarts[i]++
	m := w.members[i]
	w.queue = slices.DeleteFunc(w.queue, func(q queued) bool { return q.who == i })
	w.later = slices.DeleteFunc(w.later, func(l later) bool { return l.who == i })
	s, err := m.st.Load(m.name)
	if err != nil {
		panic(err)
	}
	m.eng = w.engine(s)
	w.release(i, m.eng.Resume(0))
}

func (w *scWorld) file(i int, name string) []byte {
	b, _ := store.Files{S: w.members[i].st}.Read(name)
	return b
}

func TestRestart(t *testing.T) {
	w := newWorld("alice", "bob")
	onDisk(t, w)
	foundAndJoin(t, w)
	send(w, 0, "g", "before")
	if !w.runUntil(func() bool { return w.says(1, "g", "before") }, limit) {
		t.Fatal("no conversation before restarting")
	}
	w.restart(t, 0)
	send(w, 0, "g", "after")
	send(w, 1, "g", "bob after")
	if !w.runUntil(func() bool { return w.says(1, "g", "after") && w.says(0, "g", "bob after") }, limit) {
		t.Fatal("alice does not carry on after restarting")
	}
	if len(w.sim.Refused) > 0 {
		t.Fatalf("writes refused: %v", w.sim.Refused)
	}
}

func TestRestartMidUpload(t *testing.T) {
	w := newWorld("alice", "bob")
	onDisk(t, w)
	foundAndJoin(t, w)
	doc := bytesOf(40000, 3)
	sendFile(w, 0, "g", "notes.txt", doc)
	underWay := func() bool {
		return slices.ContainsFunc(w.chatOf(0, "g").Jobs, func(j *engine.Job) bool { return j.Upload != nil && j.Upload.Sent >= 5 })
	}
	if !w.runUntil(underWay, limit) {
		t.Fatal("no upload under way")
	}
	w.restart(t, 0)
	if !w.runUntil(func() bool {
		a := w.attachmentOf(1, "g", "notes.txt")
		return a != nil && w.file(1, a.File) != nil
	}, limit) {
		t.Fatal("after a restart the upload does not carry on")
	}
	a := w.attachmentOf(1, "g", "notes.txt")
	if a.Filetype != "arbitrary" || !bytes.Equal(w.file(1, a.File), doc) {
		t.Fatal("bob does not receive the file whole")
	}
}

// TestRestartMidInduction restarts the inducting member after each of its actions in an
// induction, with what came of the action either lost or kept: the induction is finished, not
// given up, and the new member is introduced to the others.
func TestRestartMidInduction(t *testing.T) {
	for _, lost := range []bool{false, true} {
		for crashAt := 1; ; crashAt++ {
			w := newWorld("alice", "bob", "carol")
			onDisk(t, w)
			foundAndJoin(t, w)
			w.feed(2, engine.Join{Chat: "g", Name: "g"})
			w.runUntil(func() bool { return w.code(2, "g") != "" }, limit)
			w.feed(0, engine.Induct{Chat: "g", Code: w.code(2, "g")})
			n, crashed := 0, false
			w.crash = func(who int, a engine.Action) (bool, bool) {
				if who != 0 || crashed {
					return false, false
				}
				n++
				crashed = n == crashAt
				return crashed, lost
			}
			if !w.runUntil(func() bool { return w.joined(2, "g") }, limit) {
				t.Fatalf("crash after %d of alice's actions (lost %v): carol does not join\n%v\n%v", crashAt, lost, w.show(0, "g"), w.show(2, "g"))
			}
			send(w, 2, "g", "carol here")
			if !w.runUntil(func() bool { return w.says(0, "g", "carol here") && w.says(1, "g", "carol here") }, limit) {
				t.Fatalf("crash after %d (lost %v): carol is not read by all\n%v\n%v", crashAt, lost, w.show(0, "g"), w.show(1, "g"))
			}
			if len(w.sim.Refused) > 0 {
				t.Fatalf("crash after %d (lost %v): writes refused: %v", crashAt, lost, w.sim.Refused)
			}
			if !crashed {
				t.Logf("lost %v: restarted after each of %d actions", lost, crashAt-1)
				break
			}
		}
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("TMPDIR") == "" {
		os.Setenv("TMPDIR", os.ExpandEnv("$HOME/scratch/tmp"))
		os.MkdirAll(os.Getenv("TMPDIR"), 0o700)
	}
	os.Exit(m.Run())
}
