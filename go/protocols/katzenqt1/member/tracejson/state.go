package tracejson

import (
	"github.com/katzenpost/pigeonhole_protocols/go/internal/ordmap"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

// Reading a member's state back from what Group writes, so that the state can be saved in this
// form.

func eachPair(j any, f func(k, v any)) {
	for _, p := range items(j) {
		kv := tuple(p, 2)
		f(kv[0], kv[1])
	}
}

func optKey(j any) *member.Key {
	if j == nil {
		return nil
	}
	k := key(j)
	return &k
}

func optBytes(j any) []byte {
	if j == nil {
		return nil
	}
	return bytesOf(j)
}

func readAt(j any) member.At {
	p := tuple(j, 2)
	return member.At{Introducer: key(p[0]), Index: index(p[1])}
}

func boolean(j any) bool {
	b, ok := j.(bool)
	if !ok {
		fail("not a bool: %v", j)
	}
	return b
}

func readReader(j any) *member.Reader {
	r := &member.Reader{
		Stream: key(field(j, "stream")), ReadCap: bytesOf(field(j, "read_cap")),
		Next: index(field(j, "next")), Last: optIndex(field(j, "last")), Passed: natural(field(j, "passed")),
	}
	for _, k := range items(field(j, "kept")) {
		p := tuple(k, 3)
		r.Kept = append(r.Kept, member.Kept{Index: index(p[0]), Passed: natural(p[1]), Before: optIndex(p[2])})
	}
	if l := field(j, "lost"); l != nil {
		p := tuple(l, 2)
		r.Lost = &member.Lost{Passed: natural(p[0]), Before: optIndex(p[1])}
	}
	for m, s := range modes {
		if s == field(j, "mode") {
			r.Mode = m
		}
	}
	for _, t := range items(field(j, "tried")) {
		r.Tried = append(r.Tried, num(t))
	}
	return r
}

func readRosters(j any) member.Rosters {
	var r member.Rosters
	eachPair(field(j, "entries"), func(k, v any) {
		ro := &member.Roster{}
		eachPair(v, func(i, e any) {
			ro.Set(natural(i), member.Entry{Key: optKey(field(e, "key")), Prefix: optBytes(field(e, "prefix"))})
		})
		r.Entries.Set(key(k), ro)
	})
	eachPair(field(j, "started"), func(k, v any) {
		p := tuple(v, 2)
		r.Started.Set(key(k), member.Started{Introducer: key(p[0]), Top: natural(p[1])})
	})
	eachPair(field(j, "introductions"), func(k, v any) { r.Introductions.Set(readAt(k), key(v)) })
	for _, k := range items(field(j, "keys")) {
		r.Keys = append(r.Keys, key(k))
	}
	return r
}

func readSentBox(j any) member.SentBox {
	var s member.SentBox
	eachPair(field(j, "records"), func(k, v any) {
		rec := member.Record{Index: index(field(v, "index")), Control: boolean(field(v, "control")),
			Written: natural(field(v, "written")), Settled: boolean(field(v, "settled"))}
		if p := field(v, "plaintext"); p != nil {
			pl := readPayload(p)
			rec.Plaintext = &pl
		}
		s.Records.Set(num(k), rec)
	})
	if b := field(j, "backfilled"); b != Nat(-1) {
		n := natural(b)
		s.Backfilled = &n
	}
	return s
}

func indexPairs(j any) ordmap.Map[member.Key, member.Index] {
	var m ordmap.Map[member.Key, member.Index]
	eachPair(j, func(k, v any) { m.Set(key(k), index(v)) })
	return m
}

func natPairs(j any) *ordmap.Map[member.Key, uint64] {
	m := &ordmap.Map[member.Key, uint64]{}
	eachPair(j, func(k, v any) { m.Set(key(k), num(v)) })
	return m
}

func readLedger(j any) member.Ledger {
	l := member.Ledger{Published: indexPairs(field(j, "published")), AckedBy: *natPairs(field(j, "acked_by")),
		Commit: boolean(field(j, "commit")), Starts: indexPairs(field(j, "starts"))}
	eachPair(field(j, "heard"), func(k, v any) { l.Heard.Set(key(k), natPairs(v)) })
	for i, s := range inductions {
		if s == field(j, "induction") {
			l.Induction = i
		}
	}
	if inv := field(j, "invitee"); inv != nil {
		p := tuple(inv, 2)
		l.Invitee = &member.Invitee{Name: str(p[0]), ReadCap: bytesOf(p[1])}
	}
	return l
}

func readPending(j any) *member.Pending {
	p := &member.Pending{Introduced: optKey(field(j, "introduced")), Control: boolean(field(j, "control"))}
	for _, n := range items(field(j, "numbers")) {
		e := tuple(n, 2)
		na := member.NumberAt{Index: natural(e[0])}
		if e[1] != nil {
			a := readAt(e[1])
			na.At = &a
		}
		p.Numbers = append(p.Numbers, na)
	}
	eachPair(field(j, "acks"), func(k, v any) {
		e := tuple(v, 2)
		p.Acks.Set(key(k), member.AckedRun{Before: optIndex(e[0]), Now: index(e[1])})
	})
	return p
}

func readGroup(j any) *member.Group {
	g := &member.Group{
		ReadCap: bytesOf(field(j, "read_cap")), Policy: readRetention(field(j, "policy")),
		Recheck: natural(field(j, "recheck")), Rosters: readRosters(field(j, "rosters")),
		Sent: readSentBox(field(j, "sent")), Ledger: readLedger(field(j, "ledger")),
		Epoch: natural(field(j, "epoch")), Tip: index(field(j, "tip")), Deriving: boolean(field(j, "deriving")),
		Tokens: natural(field(j, "tokens")), JoinedThrough: optKey(field(j, "joined_through")),
		AwaitingStart: indexPairs(field(j, "awaiting_start")),
		Allocates:     j.(map[string]any)["allocates"] == nil || boolean(field(j, "allocates")),
	}
	eachPair(field(j, "readers"), func(k, v any) { g.Readers.Set(key(k), readReader(v)) })
	for _, i := range items(field(j, "pool")) {
		g.Pool = append(g.Pool, index(i))
	}
	for _, b := range items(field(j, "outbox")) {
		g.Outbox = append(g.Outbox, bytesOf(b))
	}
	eachPair(field(j, "pending"), func(k, v any) { g.Pending.Set(natural(k), readPending(v)) })
	for _, a := range items(field(j, "unnumbered")) {
		g.Unnumbered = append(g.Unnumbered, readAt(a))
	}
	if ia := field(j, "introduced_at"); ia != nil {
		g.IntroducedAt = &wire.IntroRef{Introducer: natural(field(ia, "introducer")), Index: bytesOf(field(ia, "index"))}
	}
	eachPair(field(j, "received"), func(k, v any) {
		p := tuple(k, 2)
		g.Received.Set(member.ReceivedAt{Sender: key(p[0]), Index: index(p[1])}, natural(v))
	})
	return g
}

// ReadGroup reads back a member's state as Group writes it.
func ReadGroup(j any) (*member.Group, error) {
	return get(func() *member.Group { return readGroup(j) })
}
