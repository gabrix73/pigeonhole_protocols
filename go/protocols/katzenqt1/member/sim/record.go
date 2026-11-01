package sim

import (
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member/tracejson"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

// Every call on a member goes through these, so a recorder sees each one.

func (w *world) rec(call string, m *simMember, more map[string]any, result any, g *member.Group) {
	if w.record == nil {
		return
	}
	w.record(call, m.key(), m.name, tracejson.Args(g, g.Policy, g.Recheck, more), result, g)
}

func (w *world) found(m *simMember, caps [][]byte) {
	m.group = member.Found(m.readCap, caps, w.policy(), w.recheck())
	var fs []any
	for _, c := range caps {
		fs = append(fs, tracejson.Hex(c))
	}
	w.rec("found", m, map[string]any{"read_cap": tracejson.Hex(m.readCap), "founders": fs}, nil, m.group)
}

func (w *world) joined(m *simMember, reply *wire.JoinReply) *member.Group {
	m.group = member.Joined(m.readCap, reply, w.policy(), w.recheck())
	w.rec("joined", m, map[string]any{"read_cap": tracejson.Hex(m.readCap), "reply": tracejson.JoinReply(reply)}, nil, m.group)
	return m.group
}

func (w *world) handle(m *simMember, g *member.Group, e member.Event) []member.Effect {
	var ev any
	if w.record != nil {
		ev = tracejson.Event(e)
	}
	es := g.Handle(e)
	w.rec("handle", m, map[string]any{"event": ev}, tracejson.Effects(es), g)
	return es
}

func (w *world) observe(m *simMember, stream member.Key, index member.Index, msg *wire.Message, next member.Index) []member.Effect {
	g := m.group
	es := g.Observe(stream, index, msg, next)
	w.rec("observe", m, map[string]any{"stream": tracejson.Hex(stream), "index": tracejson.Hex(index),
		"message": tracejson.Message(msg), "next": tracejson.Hex(next)}, tracejson.Effects(es), g)
	return es
}

func (w *world) compose(m *simMember, content []byte) []member.Outgoing {
	g := m.group
	out := g.Compose(content)
	var c any
	if content != nil {
		c = tracejson.Hex(content)
	}
	w.rec("compose", m, map[string]any{"content": c}, tracejson.Outgoings(out), g)
	return out
}

func (w *world) written(m *simMember, token int, index member.Index, p *member.Payload) {
	g := m.group
	g.Written(token, index, p)
	var pj any
	if p != nil {
		pj = tracejson.Payload(*p)
	}
	w.rec("written", m, map[string]any{"token": tracejson.Nat(token), "index": tracejson.Hex(index), "payload": pj}, nil, g)
}

func (w *world) abandoned(m *simMember, token int) {
	g := m.group
	g.Abandoned(token)
	w.rec("abandoned", m, map[string]any{"token": tracejson.Nat(token)}, nil, g)
}

func (w *world) beginInduction(m *simMember) []member.Outgoing {
	g := m.group
	out := g.BeginInduction()
	w.rec("begin_induction", m, nil, tracejson.Outgoings(out), g)
	return out
}

func (w *world) introduceNow(m *simMember, name string, readCap []byte) member.Outgoing {
	g := m.group
	o := g.IntroduceNow(name, readCap)
	w.rec("introduce_now", m, map[string]any{"name": name, "read_cap": tracejson.Hex(readCap)}, tracejson.Outgoing(o), g)
	return o
}

func (w *world) reply(m *simMember, ownStart member.Index) *wire.JoinReply {
	g := m.group
	if g == nil {
		fail("%s has not joined", m.name)
	}
	r := g.Reply(ownStart)
	w.rec("reply", m, map[string]any{"own_start": tracejson.Hex(ownStart)}, tracejson.JoinReply(r), g)
	return r
}
