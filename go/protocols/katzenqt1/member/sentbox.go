package member

import (
	"cmp"
	"slices"

	"github.com/katzenpost/pigeonhole_protocols/go/internal/ordmap"
)

// The Sent box holds the boxes a member wrote to its own stream: what it may still rewrite, and
// what retention lets it forget.

type Retention struct {
	// Window is the epochs a Sent-box record is kept and backfilled; nil keeps it for good.
	Window *int
	// DiscardAcked drops plaintext every member still read has acknowledged.
	DiscardAcked bool
	// KeepSent is the epochs the policy keeps sent content.
	KeepSent *int
	// KeepReceived is the epochs the policy keeps received content.
	KeepReceived *int
}

func DefaultRetention() Retention {
	w := 3
	return Retention{Window: &w, DiscardAcked: true}
}

type Record struct {
	// Index is the box's whole MessageBoxIndex.
	Index Index
	// Plaintext is nil once it is gone, or if it was never handed over.
	Plaintext *Payload
	Control   bool
	Written   int
	// Settled is set once it is written as a tombstone because every member acknowledged it.
	Settled bool
}

type SentBox struct {
	// Records are by the box's Idx64, which orders the boxes of the member's stream as it wrote
	// them.
	Records ordmap.Map[uint64, Record]
	// Backfilled is the epoch last backfilled.
	Backfilled *int
}

func (s *SentBox) record(index Index, plaintext *Payload, control bool, epoch int) {
	s.Records.Set(counter(index), Record{Index: index, Plaintext: plaintext, Control: control, Written: epoch})
}

// checkAt is the Sent-box check for an acknowledgement, which names the box by its Idx64.
func (s *SentBox) checkAt(idx64 uint64) bool { return s.Records.Has(idx64) }

func (s *SentBox) retain(epoch int, policy Retention, everyoneAcked func(uint64) bool) {
	if policy.Window != nil {
		s.Records.Filter(func(_ uint64, r Record) bool { return epoch <= r.Written+*policy.Window })
	}
	for k, r := range s.Records.All {
		expired := policy.KeepSent != nil && !r.Control && r.Written+*policy.KeepSent <= epoch
		if expired || policy.DiscardAcked && everyoneAcked(k) {
			s.Records.Modify(k, func(r Record) Record { r.Plaintext = nil; return r })
		}
	}
}

// backfill rewrites every record a member has yet to acknowledge, at most once per epoch, and
// writes a record every member has acknowledged as a tombstone once its plaintext is gone.
func (s *SentBox) backfill(epoch int, everyoneAcked func(uint64) bool) []Effect {
	if s.Backfilled != nil && *s.Backfilled == epoch {
		return nil
	}
	keys := s.Records.Keys()
	slices.SortStableFunc(keys, cmp.Compare[uint64])
	var es []Effect
	for _, k := range keys {
		r, _ := s.Records.Get(k)
		switch {
		case !everyoneAcked(k) && r.Plaintext != nil:
			es = append(es, WriteBox{Index: r.Index, Payload: *r.Plaintext})
		case !everyoneAcked(k):
			es = append(es, WriteTombstone{Index: r.Index})
		case r.Plaintext == nil && !r.Settled:
			es = append(es, WriteTombstone{Index: r.Index})
		}
	}
	for k, r := range s.Records.All {
		if everyoneAcked(k) && r.Plaintext == nil {
			s.Records.Modify(k, func(r Record) Record { r.Settled = true; return r })
		}
	}
	e := epoch
	s.Backfilled = &e
	return es
}
