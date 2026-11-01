package tracejson

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

// Parse decodes a trace line into the generic form these functions read.
func Parse(line []byte) (map[string]any, error) {
	var v map[string]any
	d := json.NewDecoder(bytesReader(line))
	d.UseNumber()
	err := d.Decode(&v)
	return v, err
}

type perr struct{ msg string }

// get runs f, turning a parse failure inside it into an error.
func get[T any](f func() T) (v T, err error) {
	defer func() {
		if r := recover(); r != nil {
			if p, ok := r.(perr); ok {
				err = fmt.Errorf("%s", p.msg)
				return
			}
			panic(r)
		}
	}()
	return f(), nil
}

func fail(format string, a ...any) { panic(perr{fmt.Sprintf(format, a...)}) }

func field(j any, k string) any {
	o, ok := j.(map[string]any)
	if !ok {
		fail("not an object: %v", j)
	}
	v, ok := o[k]
	if !ok {
		fail("no field %s", k)
	}
	return v
}

func str(j any) string {
	s, ok := j.(string)
	if !ok {
		fail("not a string: %v", j)
	}
	return s
}

func bytesOf(j any) []byte {
	b, err := hex.DecodeString(str(j))
	if err != nil {
		fail("not hex: %v", j)
	}
	return b
}

func index(j any) member.Index { return member.Index(bytesOf(j)) }

func key(j any) member.Key { return member.Key(bytesOf(j)) }

func optIndex(j any) *member.Index {
	if j == nil {
		return nil
	}
	i := index(j)
	return &i
}

func num(j any) uint64 {
	n, ok := j.(json.Number)
	if !ok {
		fail("not a number: %v", j)
	}
	u, err := strconv.ParseUint(string(n), 10, 64)
	if err != nil {
		fail("not a natural number: %v", j)
	}
	return u
}

func natural(j any) int { return int(num(j)) }

func optNatural(j any) *int {
	if j == nil {
		return nil
	}
	n := natural(j)
	return &n
}

func items(j any) []any {
	a, ok := j.([]any)
	if !ok {
		fail("not a list: %v", j)
	}
	return a
}

func tuple(j any, n int) []any {
	a := items(j)
	if len(a) != n {
		fail("not %d items: %v", n, j)
	}
	return a
}

func readMessage(j any) *wire.Message {
	m := &wire.Message{}
	if c := field(j, "content"); c != nil {
		m.Content = bytesOf(c)
	}
	if i := field(j, "introduction"); i != nil {
		m.Introduction = &wire.Introduction{Name: str(field(i, "name")), ReadCap: bytesOf(field(i, "read_cap"))}
	}
	for _, n := range items(field(j, "numbers")) {
		p := tuple(n, 2)
		num := wire.Number{Index: natural(p[0])}
		if p[1] != nil {
			num.Prefix = bytesOf(p[1])
		}
		m.Numbers = append(m.Numbers, num)
	}
	if a := field(j, "introduced_at"); a != nil {
		p := tuple(a, 2)
		m.IntroducedAt = &wire.IntroRef{Introducer: natural(p[0]), Index: bytesOf(p[1])}
	}
	for _, a := range items(field(j, "acks")) {
		p := tuple(a, 2)
		m.Acks = append(m.Acks, wire.Ack{Member: natural(p[0]), Idx64: num(p[1])})
	}
	m.MembershipHash = optBytes(field(j, "membership_hash"))
	return m
}

func optMessage(j any) *wire.Message {
	if j == nil {
		return nil
	}
	return readMessage(j)
}

func readPayload(j any) member.Payload {
	if o, ok := j.(map[string]any); ok {
		if b, ok := o["bytes"]; ok {
			return member.Payload{Bytes: bytesOf(b)}
		}
	}
	return member.Payload{Message: readMessage(j)}
}

func readJoinReply(j any) *wire.JoinReply {
	r := &wire.JoinReply{Introducer: natural(field(j, "introducer")), Newcomer: natural(field(j, "newcomer"))}
	for _, m := range items(field(j, "members")) {
		if m == nil {
			r.Members = append(r.Members, nil)
			continue
		}
		p := tuple(m, 2)
		r.Members = append(r.Members, &wire.Member{ReadCap: bytesOf(p[0]), Start: bytesOf(p[1])})
	}
	for _, ro := range items(field(j, "rosters")) {
		if ro == nil {
			r.Rosters = append(r.Rosters, nil)
			continue
		}
		roster := &wire.Roster{Entries: []wire.RosterEntry{}}
		for _, e := range items(ro) {
			p := tuple(e, 2)
			roster.Entries = append(roster.Entries, wire.RosterEntry{Index: natural(p[0]), Place: optNatural(p[1])})
		}
		r.Rosters = append(r.Rosters, roster)
	}
	for _, i := range items(field(j, "introductions")) {
		p := tuple(i, 3)
		r.Introductions = append(r.Introductions, wire.IntroAt{By: natural(p[0]), Index: bytesOf(p[1]), Member: natural(p[2])})
	}
	return r
}

func readRetention(j any) member.Retention {
	b, ok := field(j, "discard_acked").(bool)
	if !ok {
		fail("discard_acked is not a bool")
	}
	return member.Retention{Window: optNatural(field(j, "window")), DiscardAcked: b,
		KeepSent: optNatural(field(j, "keep_sent")), KeepReceived: optNatural(field(j, "keep_received"))}
}

func readResult(j any) member.ReadResult {
	switch j {
	case "not found":
		return member.ReadResult{Kind: member.ReadNotFound}
	case "tombstone":
		return member.ReadResult{Kind: member.ReadTombstone}
	}
	return member.ReadResult{Kind: member.ReadData, Message: optMessage(field(j, "data"))}
}

func readEvent(j any) member.Event {
	by := func(k string) []byte { return bytesOf(field(j, k)) }
	switch t := str(field(j, "type")); t {
	case "Send":
		return member.Send{Content: by("content")}
	case "Read":
		return member.Read{Stream: key(field(j, "stream"))}
	case "Scan":
		return member.Scan{Stream: key(field(j, "stream"))}
	case "BoxRead":
		return member.BoxRead{Stream: key(field(j, "stream")), Index: index(field(j, "index")),
			Result: readResult(field(j, "result")), Next: optIndex(field(j, "next_index"))}
	case "IndexesDerived":
		var is []member.Index
		for _, i := range items(field(j, "indexes")) {
			is = append(is, index(i))
		}
		return member.IndexesDerived{Stream: key(field(j, "stream")), Indexes: is}
	case "Walked":
		var skipped []member.Index
		for _, i := range items(field(j, "skipped")) {
			skipped = append(skipped, index(i))
		}
		return member.Walked{Stream: key(field(j, "stream")), Target: optIndex(field(j, "target")),
			Skipped: skipped, Steps: natural(field(j, "steps"))}
	case "Invite":
		return member.Invite{Name: str(field(j, "name")), ReadCap: by("read_cap")}
	case "Introduce":
		return member.Introduce{Name: str(field(j, "name")), ReadCap: by("read_cap")}
	case "Remove":
		return member.Remove{Member: key(field(j, "member"))}
	case "EpochChanged":
		return member.EpochChanged{Epoch: natural(field(j, "epoch"))}
	default:
		fail("unknown event %s", t)
	}
	return nil
}

func ReadMessage(j any) (*wire.Message, error) {
	return get(func() *wire.Message { return optMessage(j) })
}
func ReadPayload(j any) (member.Payload, error) {
	return get(func() member.Payload { return readPayload(j) })
}
func ReadJoinReply(j any) (*wire.JoinReply, error) {
	return get(func() *wire.JoinReply { return readJoinReply(j) })
}
func ReadRetention(j any) (member.Retention, error) {
	return get(func() member.Retention { return readRetention(j) })
}
func ReadEvent(j any) (member.Event, error) { return get(func() member.Event { return readEvent(j) }) }
