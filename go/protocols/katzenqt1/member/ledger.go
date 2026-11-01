package member

import "github.com/katzenpost/pigeonhole_protocols/go/internal/ordmap"

// The ledger is what this member has acknowledged, and what others have acknowledged of each
// stream. An induction holds publishing back.

type Induction int

const (
	InductionIdle Induction = iota
	CatchingUp
	Inducting
)

type Invitee struct {
	Name    string
	ReadCap []byte
}

type Ledger struct {
	// Published is the last index acknowledged of each stream.
	Published ordmap.Map[Key, Index]
	// AckedBy is the Idx64 of the last box of our stream each member has acknowledged, after the
	// Sent-box check.
	AckedBy ordmap.Map[Key, uint64]
	// Heard is, for each stream, the Idx64 of the last box each other member acknowledged of it.
	Heard     ordmap.Map[Key, *ordmap.Map[Key, uint64]]
	Induction Induction
	// Invitee is the member being inducted.
	Invitee *Invitee
	// Commit says to commit the induction as soon as catching up is done.
	Commit bool
	// Starts is where each stream had been read when the invitation began.
	Starts ordmap.Map[Key, Index]
}

func (l *Ledger) holding() bool { return l.Induction == Inducting }

// owed is the index to acknowledge of stream, the end of the unbroken run read, if anything new.
func (l *Ledger) owed(stream Key, run *Index) *Index {
	if run == nil || l.holding() {
		return nil
	}
	if p, ok := l.Published.Get(stream); ok && p == *run {
		return nil
	}
	return run
}

func (l *Ledger) hear(stream Key, idx64 uint64, by Key) {
	h, ok := l.Heard.Get(stream)
	if !ok {
		h = &ordmap.Map[Key, uint64]{}
		l.Heard.Set(stream, h)
	}
	h.Set(by, idx64)
}

func (l *Ledger) acked(member Key, idx64 uint64) {
	if s, ok := l.AckedBy.Get(member); ok {
		idx64 = max(s, idx64)
	}
	l.AckedBy.Set(member, idx64)
}

func (l *Ledger) forget(member Key) {
	l.AckedBy.Delete(member)
	l.Heard.Delete(member)
	for _, h := range l.Heard.All {
		h.Delete(member)
	}
}
