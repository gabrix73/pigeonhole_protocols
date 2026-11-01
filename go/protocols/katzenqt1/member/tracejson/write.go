// Package tracejson reads call arguments and writes results and member state in katzenqt's
// group chat trace format, as values of encoding/json's generic form (with json.Number). Bytes are
// hex; a map is a list of pairs in order.
package tracejson

import (
	"encoding/hex"
	"encoding/json"
	"strconv"

	"github.com/katzenpost/pigeonhole_protocols/go/internal/ordmap"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

type obj = map[string]any
type arr = []any

func Hex[T ~string | ~[]byte](b T) any { return hex.EncodeToString([]byte(b)) }

func optHex[T ~string](p *T) any {
	if p == nil {
		return nil
	}
	return Hex(*p)
}

func hexOrNil(b []byte) any {
	if b == nil {
		return nil
	}
	return Hex(b)
}

func Nat[T ~int | ~uint64](n T) any {
	if n < 0 {
		return json.Number(strconv.FormatInt(int64(n), 10))
	}
	return json.Number(strconv.FormatUint(uint64(n), 10))
}

func optNat(p *int) any {
	if p == nil {
		return nil
	}
	return Nat(*p)
}

func pairs[K comparable, V any](m *ordmap.Map[K, V], fk func(K) any, fv func(V) any) any {
	out := arr{}
	for k, v := range m.All {
		out = append(out, arr{fk(k), fv(v)})
	}
	return out
}

func list[T any](l []T, f func(T) any) any {
	out := make(arr, 0, len(l))
	for _, e := range l {
		out = append(out, f(e))
	}
	return out
}

func introRef(r *wire.IntroRef) any {
	if r == nil {
		return nil
	}
	return arr{Nat(r.Introducer), Hex(r.Index)}
}

func Message(m *wire.Message) any {
	if m == nil {
		return nil
	}
	var intro any
	if m.Introduction != nil {
		intro = obj{"name": m.Introduction.Name, "read_cap": Hex(m.Introduction.ReadCap)}
	}
	var content any
	if m.Content != nil {
		content = Hex(m.Content)
	}
	return obj{
		"content":      content,
		"introduction": intro,
		"numbers": list(m.Numbers, func(n wire.Number) any {
			var p any
			if n.Prefix != nil {
				p = Hex(n.Prefix)
			}
			return arr{Nat(n.Index), p}
		}),
		"introduced_at":   introRef(m.IntroducedAt),
		"acks":            list(m.Acks, func(a wire.Ack) any { return arr{Nat(a.Member), Nat(a.Idx64)} }),
		"membership_hash": hexOrNil(m.MembershipHash),
	}
}

// Payload is a message decoded, or bytes the member never looks into, as {"bytes": hex}.
func Payload(p member.Payload) any {
	if p.Message != nil {
		return Message(p.Message)
	}
	return obj{"bytes": Hex(p.Bytes)}
}

func JoinReply(r *wire.JoinReply) any {
	return obj{
		"type": "JoinReply",
		"members": list(r.Members, func(m *wire.Member) any {
			if m == nil {
				return nil
			}
			return arr{Hex(m.ReadCap), Hex(m.Start)}
		}),
		"rosters": list(r.Rosters, func(ro *wire.Roster) any {
			if ro == nil {
				return nil
			}
			return list(ro.Entries, func(e wire.RosterEntry) any { return arr{Nat(e.Index), optNat(e.Place)} })
		}),
		"introductions": list(r.Introductions, func(i wire.IntroAt) any {
			return arr{Nat(i.By), Hex(i.Index), Nat(i.Member)}
		}),
		"introducer": Nat(r.Introducer),
		"newcomer":   Nat(r.Newcomer),
	}
}

func Effect(e member.Effect) any {
	switch e := e.(type) {
	case member.WriteBox:
		return obj{"type": "WriteBox", "index": Hex(e.Index), "payload": Payload(e.Payload)}
	case member.WriteTombstone:
		return obj{"type": "WriteTombstone", "index": Hex(e.Index)}
	case member.ReadBox:
		return obj{"type": "ReadBox", "stream": Hex(e.Stream), "read_cap": Hex(e.ReadCap),
			"index": Hex(e.Index), "recheck": e.Recheck}
	case member.DeriveIndexes:
		return obj{"type": "DeriveIndexes", "stream": Hex(e.Stream), "start": Hex(e.Start), "count": Nat(e.Count)}
	case member.Walk:
		return obj{"type": "Walk", "stream": Hex(e.Stream), "start": Hex(e.Start),
			"targets": list(e.Targets, func(t uint64) any { return Nat(t) }), "keep": Nat(e.Keep)}
	case member.Deliver:
		return obj{"type": "Deliver", "sender": Hex(e.Sender), "index": Hex(e.Index), "content": Hex(e.Content)}
	case member.Expire:
		return obj{"type": "Expire", "sender": Hex(e.Sender), "index": Hex(e.Index)}
	case member.SendJoinReply:
		return obj{"type": "SendJoinReply", "to": Hex(e.To), "reply": JoinReply(e.Reply)}
	}
	panic("unknown effect")
}

func Effects(es []member.Effect) any { return list(es, Effect) }

func Outgoing(o member.Outgoing) any {
	return obj{"type": "Outgoing", "token": Nat(o.Token), "message": Message(o.Message)}
}

func Outgoings(os []member.Outgoing) any { return list(os, Outgoing) }

var modes = map[member.Mode]string{member.Idle: "idle", member.Reading: "reading", member.Scanning: "scanning"}

var inductions = map[member.Induction]string{
	member.InductionIdle: "idle", member.CatchingUp: "catching up", member.Inducting: "inducting"}

func at(a member.At) any { return arr{Hex(a.Introducer), Hex(a.Index)} }

func reader(r *member.Reader) any {
	var lost any
	if r.Lost != nil {
		lost = arr{Nat(r.Lost.Passed), optHex(r.Lost.Before)}
	}
	return obj{
		"stream": Hex(r.Stream), "read_cap": Hex(r.ReadCap), "next": Hex(r.Next),
		"last": optHex(r.Last), "passed": Nat(r.Passed),
		"kept": list(r.Kept, func(k member.Kept) any { return arr{Hex(k.Index), Nat(k.Passed), optHex(k.Before)} }),
		"lost": lost, "mode": modes[r.Mode],
		"tried": list(r.Tried, func(t uint64) any { return Nat(t) }),
	}
}

func rosters(r *member.Rosters) any {
	return obj{
		"entries": pairs(&r.Entries, func(k member.Key) any { return Hex(k) }, func(ro *member.Roster) any {
			return pairs(ro, func(i int) any { return Nat(i) }, func(e member.Entry) any {
				var p any
				if e.Prefix != nil {
					p = Hex(e.Prefix)
				}
				return obj{"key": optHex(e.Key), "prefix": p}
			})
		}),
		"started": pairs(&r.Started, func(k member.Key) any { return Hex(k) }, func(s member.Started) any {
			return arr{Hex(s.Introducer), Nat(s.Top)}
		}),
		"introductions": pairs(&r.Introductions, at, func(k member.Key) any { return Hex(k) }),
		"keys":          list(r.Keys, func(k member.Key) any { return Hex(k) }),
	}
}

func Retention(p member.Retention) any {
	return obj{"window": optNat(p.Window), "discard_acked": p.DiscardAcked,
		"keep_sent": optNat(p.KeepSent), "keep_received": optNat(p.KeepReceived)}
}

func sentBox(s *member.SentBox) any {
	backfilled := Nat(-1)
	if s.Backfilled != nil {
		backfilled = Nat(*s.Backfilled)
	}
	return obj{
		"records": pairs(&s.Records, func(k uint64) any { return Nat(k) }, func(r member.Record) any {
			var p any
			if r.Plaintext != nil {
				p = Payload(*r.Plaintext)
			}
			return obj{"index": Hex(r.Index), "plaintext": p, "control": r.Control,
				"written": Nat(r.Written), "settled": r.Settled}
		}),
		"backfilled": backfilled,
	}
}

func hexKey(k member.Key) any { return Hex(k) }

func ledger(l *member.Ledger) any {
	var inv any
	if l.Invitee != nil {
		inv = arr{l.Invitee.Name, Hex(l.Invitee.ReadCap)}
	}
	return obj{
		"published": pairs(&l.Published, hexKey, func(i member.Index) any { return Hex(i) }),
		"acked_by":  pairs(&l.AckedBy, hexKey, func(n uint64) any { return Nat(n) }),
		"heard": pairs(&l.Heard, hexKey, func(h *ordmap.Map[member.Key, uint64]) any {
			return pairs(h, hexKey, func(n uint64) any { return Nat(n) })
		}),
		"induction": inductions[l.Induction], "invitee": inv, "commit": l.Commit,
		"starts": pairs(&l.Starts, hexKey, func(i member.Index) any { return Hex(i) }),
	}
}

func pending(p *member.Pending) any {
	return obj{
		"numbers": list(p.Numbers, func(n member.NumberAt) any {
			var a any
			if n.At != nil {
				a = at(*n.At)
			}
			return arr{Nat(n.Index), a}
		}),
		"introduced": optHex(p.Introduced),
		"acks": pairs(&p.Acks, hexKey, func(a member.AckedRun) any {
			return arr{optHex(a.Before), Hex(a.Now)}
		}),
		"control": p.Control,
	}
}

func Group(g *member.Group) any {
	var ia any
	if g.IntroducedAt != nil {
		ia = obj{"introducer": Nat(g.IntroducedAt.Introducer), "index": Hex(g.IntroducedAt.Index)}
	}
	return obj{
		"read_cap": Hex(g.ReadCap), "policy": Retention(g.Policy), "recheck": Nat(g.Recheck),
		"rosters": rosters(&g.Rosters), "readers": pairs(&g.Readers, hexKey, reader),
		"sent": sentBox(&g.Sent), "ledger": ledger(&g.Ledger), "epoch": Nat(g.Epoch),
		"pool": list(g.Pool, func(i member.Index) any { return Hex(i) }), "tip": Hex(g.Tip),
		"deriving": g.Deriving, "outbox": list(g.Outbox, func(b []byte) any { return Hex(b) }),
		"pending": pairs(&g.Pending, func(n int) any { return Nat(n) }, pending),
		"tokens":  Nat(g.Tokens), "unnumbered": list(g.Unnumbered, at),
		"introduced_at": ia, "joined_through": optHex(g.JoinedThrough),
		"awaiting_start": pairs(&g.AwaitingStart, hexKey, func(i member.Index) any { return Hex(i) }),
		"allocates":      g.Allocates,
		"received": pairs(&g.Received, func(r member.ReceivedAt) any { return arr{Hex(r.Sender), Hex(r.Index)} },
			func(n int) any { return Nat(n) }),
	}
}

func resultJSON(r member.ReadResult) any {
	switch r.Kind {
	case member.ReadNotFound:
		return "not found"
	case member.ReadTombstone:
		return "tombstone"
	}
	return obj{"data": Message(r.Message)}
}

func indexes(is []member.Index) any { return list(is, func(i member.Index) any { return Hex(i) }) }

func Event(e member.Event) any {
	switch e := e.(type) {
	case member.Send:
		return obj{"type": "Send", "content": Hex(e.Content)}
	case member.Read:
		return obj{"type": "Read", "stream": Hex(e.Stream)}
	case member.Scan:
		return obj{"type": "Scan", "stream": Hex(e.Stream)}
	case member.BoxRead:
		return obj{"type": "BoxRead", "stream": Hex(e.Stream), "index": Hex(e.Index),
			"result": resultJSON(e.Result), "next_index": optHex(e.Next)}
	case member.IndexesDerived:
		return obj{"type": "IndexesDerived", "stream": Hex(e.Stream), "indexes": indexes(e.Indexes)}
	case member.Walked:
		return obj{"type": "Walked", "stream": Hex(e.Stream), "target": optHex(e.Target),
			"skipped": indexes(e.Skipped), "steps": Nat(e.Steps)}
	case member.Invite:
		return obj{"type": "Invite", "name": e.Name, "read_cap": Hex(e.ReadCap)}
	case member.Introduce:
		return obj{"type": "Introduce", "name": e.Name, "read_cap": Hex(e.ReadCap)}
	case member.Remove:
		return obj{"type": "Remove", "member": Hex(e.Member)}
	case member.EpochChanged:
		return obj{"type": "EpochChanged", "epoch": Nat(e.Epoch)}
	}
	panic("unknown event")
}

// Args are a call's arguments: the policy and recheck in force, and what the call takes.
func Args(g *member.Group, policy member.Retention, recheck int, more map[string]any) map[string]any {
	p := Retention(policy).(obj)
	p["type"] = "Retention"
	args := obj{"policy": p, "recheck": Nat(recheck)}
	for k, v := range more {
		args[k] = v
	}
	return args
}

// Line is one trace line.
func Line(call string, me member.Key, name string, args map[string]any, result any, g *member.Group) map[string]any {
	return obj{"call": call, "me": Hex(me), "member": name, "args": args, "result": result, "state": Group(g)}
}
