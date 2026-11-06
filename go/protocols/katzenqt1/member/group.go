package member

import (
	"slices"

	"github.com/katzenpost/pigeonhole_protocols/go/internal/ordmap"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

// PoolSize is how many of its own indexes a member derives at a time.
const PoolSize = 4

// placeholder is what stands in a roster for a member known only by its place.
func placeholder(place int) Key { return Key("retired" + string([]byte{byte(place)})) }

// NumberAt is a roster index a composed message assigns, and to whose Introduction; nil for the
// one it carries.
type NumberAt struct {
	Index int
	At    *At
}

// AckedRun is what a composed message acknowledges of a stream: what had been published before,
// and now.
type AckedRun struct {
	Before *Index
	Now    Index
}

// Pending is what a composed message does once it has a box.
type Pending struct {
	Numbers    []NumberAt
	Introduced *Key
	Acks       ordmap.Map[Key, AckedRun]
	Control    bool
}

type Outgoing struct {
	Token   int
	Message *wire.Message
}

type Group struct {
	// ReadCap is our own read cap: our key and our stream's first index.
	ReadCap []byte
	Policy  Retention
	// Recheck is how many boxes behind it a reader keeps one a scan stepped past.
	Recheck int
	Rosters Rosters
	Readers ordmap.Map[Key, *Reader]
	Sent    SentBox
	Ledger  Ledger
	Epoch   int
	Pool    []Index
	// Tip is the furthest of our own indexes derived so far.
	Tip      Index
	Deriving bool
	// Outbox is content waiting for an index.
	Outbox [][]byte
	// Pending is the messages composed that have no box yet, by token.
	Pending ordmap.Map[int, *Pending]
	Tokens  int
	// Unnumbered is the Introductions read whose member we have not numbered yet.
	Unnumbered []At
	// IntroducedAt is owed in our next message, once we have read our Introduction.
	IntroducedAt *wire.IntroRef
	// JoinedThrough is our introducer, until we have read our Introduction.
	JoinedThrough *Key
	// AwaitingStart is each IntroducedAt read before the Introduction it names.
	AwaitingStart ordmap.Map[Key, Index]
	// Allocates is whether this member picks the boxes it writes, as it does driven by events. A
	// client that writes for itself takes that over with its first call to write, and from then
	// on the member writes nothing by itself: its pool would name boxes the client hands out too.
	Allocates bool
	// Received is the content delivered, by sender and box, and the epoch it came, while the
	// policy keeps received content only for a time.
	Received ordmap.Map[ReceivedAt, int]
}

// ReceivedAt is a box content was delivered from.
type ReceivedAt struct {
	Sender Key
	Index  Index
}

func newGroup(readCap []byte, policy Retention, recheck int) *Group {
	return &Group{ReadCap: readCap, Policy: policy, Recheck: recheck,
		Tip: startOf(readCap), Pool: []Index{startOf(readCap)}, Allocates: true}
}

// Me is our own key.
func (g *Group) Me() Key { return keyOf(g.ReadCap) }

func (g *Group) follow(readCap []byte, start Index) {
	g.Readers.Set(keyOf(readCap), &Reader{Stream: keyOf(readCap), ReadCap: readCap, Next: start})
}

// followIfNew reads the stream of readCap from its start, unless we read it already.
func (g *Group) followIfNew(readCap []byte) {
	if !g.Readers.Has(keyOf(readCap)) {
		g.follow(readCap, startOf(readCap))
	}
}

// Found starts a group with founders' read caps, ours among them.
func Found(readCap []byte, founders [][]byte, policy Retention, recheck int) *Group {
	g := newGroup(readCap, policy, recheck)
	keys := make([]Key, len(founders))
	for i, c := range founders {
		keys[i] = keyOf(c)
	}
	g.Rosters.found(keys)
	for _, c := range founders {
		if keyOf(c) != g.Me() {
			g.follow(c, startOf(c))
		}
	}
	return g
}

// Joined joins a group from what our introducer handed us.
func Joined(readCap []byte, reply *wire.JoinReply, policy Retention, recheck int) *Group {
	g := newGroup(readCap, policy, recheck)
	order := make([]Key, 0, len(reply.Members)+1)
	for place, m := range reply.Members {
		if m != nil {
			order = append(order, keyOf(m.ReadCap))
		} else {
			order = append(order, placeholder(place))
		}
	}
	order = append(order, g.Me())
	at := func(i int) (Key, bool) {
		if i < 0 || i >= len(order) {
			return "", false
		}
		return order[i], true
	}
	var entries ordmap.Map[Key, *Roster]
	for place, ro := range reply.Rosters {
		owner, ok := at(place)
		if ro == nil || !ok {
			continue
		}
		var r Roster
		for _, e := range ro.Entries {
			var entry Entry
			if e.Place != nil {
				if k, ok := at(*e.Place); ok {
					entry.Key = &k
				}
			}
			r.Set(e.Index, entry)
		}
		entries.Set(owner, &r)
	}
	for _, i := range reply.Introductions {
		by, ok1 := at(i.By)
		m, ok2 := at(i.Member)
		if ok1 && ok2 {
			g.Rosters.Introductions.Set(At{by, Index(i.Index)}, m)
		}
	}
	for _, m := range reply.Members {
		if m != nil {
			g.Rosters.learn(keyOf(m.ReadCap))
		}
	}
	g.Rosters.learn(g.Me())
	introducer, _ := at(reply.Introducer)
	var own Roster
	if ro, ok := entries.Get(introducer); ok {
		own = ro.Clone()
	}
	me := g.Me()
	own.Set(reply.Newcomer, Entry{Key: &me})
	entries.Set(me, &own)
	g.Rosters.Entries = entries
	for _, m := range reply.Members {
		if m != nil {
			g.follow(m.ReadCap, Index(m.Start))
		}
	}
	g.JoinedThrough = &introducer
	return g
}

// Reading

func (g *Group) heard(stream Key) []uint64 {
	if h, ok := g.Ledger.Heard.Get(stream); ok {
		return h.Values()
	}
	return nil
}

func (g *Group) scanStream(stream Key) []Effect {
	r, ok := g.Readers.Get(stream)
	if !ok {
		return nil
	}
	return r.scan(g.heard(stream), g.Recheck)
}

// numbered says whether member is in our roster, or will be once what we have composed is
// written.
func (g *Group) numbered(member Key) bool {
	if _, ok := g.Rosters.indexOf(g.Me(), member); ok {
		return true
	}
	for _, p := range g.Pending.Values() {
		if p.Introduced != nil && *p.Introduced == member {
			return true
		}
		for _, n := range p.Numbers {
			if n.At != nil {
				if k, ok := g.Rosters.Introductions.Get(*n.At); ok && k == member {
					return true
				}
			}
		}
	}
	return false
}

// beginRoster records that member's roster began as introducer's, through the index introducer
// gave it.
func (g *Group) beginRoster(member, introducer Key) {
	if place, ok := g.Rosters.indexOf(introducer, member); ok {
		g.Rosters.Started.Set(member, Started{introducer, place})
	}
}

// started takes member's word that it joined through the Introduction at index.
func (g *Group) started(member Key, index Index) {
	for a, n := range g.Rosters.Introductions.All {
		if n == member && a.Index == index {
			g.beginRoster(member, a.Introducer)
			return
		}
	}
	g.AwaitingStart.Set(member, index)
}

// noteOwn notes our own Introduction by the introducer we joined through, to say where in
// IntroducedAt.
func (g *Group) noteOwn(introducer Key, index Index, new Key) {
	if new == g.Me() && g.JoinedThrough != nil && *g.JoinedThrough == introducer {
		if place, ok := g.Rosters.indexOf(g.Me(), introducer); ok {
			g.IntroducedAt = &wire.IntroRef{Introducer: place, Index: []byte(index)}
			g.JoinedThrough = nil
		}
	}
}

// noteAwaited follows an IntroducedAt read earlier that named this Introduction.
func (g *Group) noteAwaited(introducer Key, index Index, new Key) {
	if i, ok := g.AwaitingStart.Get(new); ok && i == index {
		g.AwaitingStart.Delete(new)
		g.beginRoster(new, introducer)
	}
}

// noteNew reads the new member's stream, and owes it a number.
func (g *Group) noteNew(introducer Key, index Index, intro *wire.Introduction) {
	new := keyOf(intro.ReadCap)
	if new == g.Me() || g.numbered(new) {
		return
	}
	g.followIfNew(intro.ReadCap)
	a := At{introducer, index}
	if !slices.Contains(g.Unnumbered, a) {
		g.Unnumbered = append(g.Unnumbered, a)
	}
}

func (g *Group) introduced(introducer Key, index Index, intro *wire.Introduction) {
	new := keyOf(intro.ReadCap)
	g.Rosters.Introductions.Set(At{introducer, index}, new)
	g.Rosters.learn(new)
	g.noteOwn(introducer, index, new)
	g.noteAwaited(introducer, index, new)
	g.noteNew(introducer, index, intro)
}

// takeAck takes one acknowledgement sender sent: of our own stream, it counts only for a box the
// Sent-box check finds; of another's, it is heard.
func (g *Group) takeAck(sender Key, a wire.Ack) {
	acked, ok := g.Rosters.resolve(sender, a.Member)
	switch {
	case !ok:
	case acked == g.Me():
		if g.Sent.checkAt(a.Idx64) {
			g.Ledger.acked(sender, a.Idx64)
		}
	default:
		g.Ledger.hear(acked, a.Idx64, sender)
	}
}

func (g *Group) deliver(sender Key, index Index, m *wire.Message) []Effect {
	if m.Content == nil {
		return nil
	}
	if g.Policy.KeepReceived != nil {
		g.Received.Set(ReceivedAt{sender, index}, g.Epoch)
	}
	return []Effect{Deliver{Sender: sender, Index: index, Content: m.Content}}
}

func (g *Group) ingest(sender Key, index Index, m *wire.Message) []Effect {
	for _, n := range m.Numbers {
		var e Entry
		switch {
		case n.Prefix != nil:
			e.Prefix = n.Prefix
		case m.Introduction != nil:
			k := keyOf(m.Introduction.ReadCap)
			e.Key = &k
		}
		g.Rosters.number(sender, n.Index, e)
	}
	if m.Introduction != nil {
		g.introduced(sender, index, m.Introduction)
	}
	if m.IntroducedAt != nil {
		g.started(sender, Index(m.IntroducedAt.Index))
	}
	for _, a := range m.Acks {
		g.takeAck(sender, a)
	}
	return g.deliver(sender, index, m)
}

func (g *Group) boxRead(stream Key, index Index, res ReadResult, next *Index) []Effect {
	r, ok := g.Readers.Get(stream)
	if !ok {
		return nil
	}
	m, es := r.found(index, res, next, g.Recheck)
	if m == nil {
		return es
	}
	return append(g.ingest(stream, index, m), es...)
}

// Writing

// size is the next index of our roster, counting what is composed.
func (g *Group) size() int {
	s := g.Rosters.size(g.Me())
	for _, p := range g.Pending.Values() {
		for _, n := range p.Numbers {
			s = max(s, n.Index+1)
		}
	}
	return s
}

// Room is whether our roster has an index left for one more member. Without one an Introduction
// numbers nobody, and its member cannot join.
func (g *Group) Room() bool { return g.size() < wire.RosterMax }

// Membership is our view of the group, as a message we make ourselves says it: ourselves and
// every member we read, but for leaving.
func (g *Group) Membership(leaving *Key) []byte {
	var caps [][]byte
	for _, c := range append([][]byte{g.ReadCap}, g.readCaps()...) {
		if leaving == nil || keyOf(c) != *leaving {
			caps = append(caps, c)
		}
	}
	return wire.MembershipHash(caps)
}

func (g *Group) readCaps() [][]byte {
	var caps [][]byte
	for _, r := range g.Readers.Values() {
		caps = append(caps, r.ReadCap)
	}
	return caps
}

func (g *Group) owesControl() bool {
	return !g.Ledger.holding() && (g.IntroducedAt != nil || len(g.numberable()) > 0)
}

type numberable struct {
	at  At
	new Key
}

// numberable is whom a control message would number now: each member whose Introduction we have
// read, while our roster has room, once per key prefix, so that the Numbers field can name each.
// One whose prefix is taken waits for the next control message.
func (g *Group) numberable() []numberable {
	var out []numberable
	prefixes := map[string]bool{}
	size := g.size()
	for _, a := range g.Unnumbered {
		new, ok := g.Rosters.Introductions.Get(a)
		if !ok || size+len(out) >= wire.RosterMax {
			continue
		}
		p := prefixOf(new)
		if len(p) == wire.PrefixSize && !prefixes[string(p)] {
			prefixes[string(p)] = true
			out = append(out, numberable{a, new})
		}
	}
	return out
}

// control numbers whom numberable names, and says where we were introduced.
func (g *Group) control() (*wire.Message, *Pending) {
	next := g.size()
	m := &wire.Message{IntroducedAt: g.IntroducedAt, MembershipHash: g.Membership(nil)}
	p := &Pending{Control: true}
	left := slices.Clone(g.Unnumbered)
	for _, n := range g.numberable() {
		a, new := n.at, n.new
		m.Numbers = append(m.Numbers, wire.Number{Index: next, Prefix: prefixOf(new)})
		p.Numbers = append(p.Numbers, NumberAt{Index: next, At: &a})
		if i := slices.Index(left, a); i >= 0 {
			left = slices.Delete(left, i, i+1)
		}
		next++
	}
	g.Unnumbered, g.IntroducedAt = left, nil
	return m, p
}

func (g *Group) release() {
	g.Ledger.Induction, g.Ledger.Invitee, g.Ledger.Commit = InductionIdle, nil, false
	g.Ledger.Starts = ordmap.Map[Key, Index]{}
}

func (g *Group) hold() {
	g.Ledger.Induction = Inducting
	var starts ordmap.Map[Key, Index]
	for k, r := range g.Readers.All {
		starts.Set(k, r.Next)
	}
	g.Ledger.Starts = starts
}

// introductionOf is the Introduction of the member read by readCap, numbering it next unless it
// is numbered already, and what it does once written.
func (g *Group) introductionOf(name string, readCap []byte) (*wire.Message, *Pending) {
	new := keyOf(readCap)
	m := &wire.Message{Introduction: &wire.Introduction{Name: name, ReadCap: readCap},
		MembershipHash: g.Membership(&new)}
	p := &Pending{Introduced: &new, Control: true}
	if !g.numbered(new) && g.Room() {
		n := g.size()
		m.Numbers = []wire.Number{{Index: n}}
		p.Numbers = []NumberAt{{Index: n}}
	}
	return m, p
}

func (g *Group) introduction(name string, readCap []byte) (*wire.Message, *Pending) {
	m, p := g.introductionOf(name, readCap)
	g.followIfNew(readCap)
	g.release()
	return m, p
}

// withAcks acknowledges every stream we read whose run has moved on since we last did, keyed by
// our roster index and naming each box by its Idx64.
func (g *Group) withAcks(m *wire.Message, p *Pending) {
	for _, e := range g.Rosters.known(g.Me()) {
		if e.Key == nil {
			continue
		}
		r, ok := g.Readers.Get(*e.Key)
		if !ok {
			continue
		}
		owed := g.Ledger.owed(r.Stream, r.run())
		if owed == nil {
			continue
		}
		m.Acks = append(m.Acks, wire.Ack{Member: e.Index, Idx64: counter(*owed)})
		var before *Index
		if b, ok := g.Ledger.Published.Get(r.Stream); ok {
			before = &b
		}
		p.Acks.Set(r.Stream, AckedRun{Before: before, Now: *owed})
		g.Ledger.Published.Set(r.Stream, *owed)
	}
}

func (g *Group) stage(m *wire.Message, p *Pending) Outgoing {
	g.Tokens++
	g.Pending.Set(g.Tokens, p)
	return Outgoing{Token: g.Tokens, Message: m}
}

// Written says the message token landed in the box index of our stream.
func (g *Group) Written(token int, index Index, plaintext *Payload) {
	g.Allocates = false
	g.landed(token, index, plaintext)
}

// landed records the message token in the box index of our stream, which we picked or our client
// did.
func (g *Group) landed(token int, index Index, plaintext *Payload) {
	p, ok := g.Pending.Get(token)
	if !ok {
		return
	}
	me := g.Me()
	for _, n := range p.Numbers {
		var key *Key
		if n.At != nil {
			if k, ok := g.Rosters.Introductions.Get(*n.At); ok {
				key = &k
			}
		} else {
			key = p.Introduced
		}
		g.Rosters.number(me, n.Index, Entry{Key: key})
	}
	if p.Introduced != nil {
		g.Rosters.learn(*p.Introduced)
		g.Rosters.Introductions.Set(At{me, index}, *p.Introduced)
	}
	g.Pending.Delete(token)
	g.Sent.record(index, plaintext, p.Control, g.Epoch)
}

func (g *Group) write(o Outgoing) []Effect {
	if len(g.Pool) == 0 {
		return nil
	}
	index := g.Pool[0]
	g.Pool = g.Pool[1:]
	g.landed(o.Token, index, &Payload{Message: o.Message})
	return []Effect{WriteBox{Index: index, Payload: Payload{Message: o.Message}}}
}

// next is the message to send next: control if owed, else the oldest content.
func (g *Group) next() (*wire.Message, *Pending) {
	if g.owesControl() {
		return g.control()
	}
	m := &wire.Message{}
	if len(g.Outbox) > 0 {
		m.Content = g.Outbox[0]
		g.Outbox = g.Outbox[1:]
	}
	return m, &Pending{}
}

// flush writes what is owed.
func (g *Group) flush() []Effect {
	var es []Effect
	for n := len(g.Pool); n > 0; n-- {
		if !g.Allocates || len(g.Pool) == 0 || !(g.owesControl() || len(g.Outbox) > 0) {
			break
		}
		m, p := g.next()
		g.withAcks(m, p)
		es = append(es, g.write(g.stage(m, p))...)
	}
	if g.Allocates && len(g.Pool) < 2 && !g.Deriving {
		g.Deriving = true
		es = append(es, DeriveIndexes{Stream: g.Me(), Start: g.Tip, Count: PoolSize})
	}
	return es
}

func (g *Group) settled() bool {
	if len(g.Unnumbered) > 0 || len(g.Outbox) > 0 {
		return false
	}
	for _, r := range g.Readers.Values() {
		if r.Mode != Idle {
			return false
		}
	}
	return true
}

// Reply is what to hand a new member, which will start our stream at ownStart.
func (g *Group) Reply(ownStart Index) *wire.JoinReply {
	order := g.Rosters.known(g.Me())
	size := 0
	if len(order) > 0 {
		size = order[len(order)-1].Index + 1
	}
	var place ordmap.Map[Key, int]
	for _, e := range order {
		if e.Key != nil {
			place.Set(*e.Key, e.Index)
		}
	}
	keyAt := func(index int) (Key, bool) {
		for _, e := range order {
			if e.Index == index {
				if e.Key == nil {
					return "", false
				}
				return *e.Key, true
			}
		}
		return "", false
	}
	r := &wire.JoinReply{Introducer: place.GetOr(g.Me(), 0), Newcomer: size}
	for index := range size {
		var m *wire.Member
		if k, ok := keyAt(index); ok {
			if k == g.Me() {
				m = &wire.Member{ReadCap: g.ReadCap, Start: []byte(ownStart)}
			} else if rd, ok := g.Readers.Get(k); ok {
				m = &wire.Member{ReadCap: rd.ReadCap, Start: []byte(g.Ledger.Starts.GetOr(k, rd.Next))}
			}
		}
		r.Members = append(r.Members, m)
	}
	for index := range size {
		var known []KnownEntry
		if k, ok := keyAt(index); ok {
			known = g.Rosters.known(k)
		}
		if len(known) == 0 {
			r.Rosters = append(r.Rosters, nil)
			continue
		}
		ro := &wire.Roster{Entries: []wire.RosterEntry{}}
		for _, e := range known {
			entry := wire.RosterEntry{Index: e.Index}
			if e.Key != nil {
				if p, ok := place.Get(*e.Key); ok {
					entry.Place = &p
				}
			}
			ro.Entries = append(ro.Entries, entry)
		}
		r.Rosters = append(r.Rosters, ro)
	}
	for a, k := range g.Rosters.Introductions.All {
		pa, ok1 := place.Get(a.Introducer)
		pb, ok2 := place.Get(k)
		if ok1 && ok2 {
			r.Introductions = append(r.Introductions, wire.IntroAt{By: pa, Index: []byte(a.Index), Member: pb})
		}
	}
	return r
}

// IntroduceNow stages the Introduction of the member read by readCap.
func (g *Group) IntroduceNow(name string, readCap []byte) Outgoing {
	g.Allocates = false
	return g.stage(g.introduction(name, readCap))
}

func (g *Group) commitInduction() []Effect {
	inv := g.Ledger.Invitee
	if inv == nil {
		return nil
	}
	var head Index
	if len(g.Pool) > 0 {
		head = g.Pool[0]
	}
	reply := g.Reply(head)
	es := g.write(g.stage(g.introduction(inv.Name, inv.ReadCap)))
	es = append(es, SendJoinReply{To: inv.ReadCap, Reply: reply})
	return append(es, g.flush()...)
}

// progress does whatever has become possible: write what is owed, finish catching up, commit an
// induction.
func (g *Group) progress() []Effect {
	es := g.flush()
	if g.Ledger.Induction == CatchingUp && g.settled() {
		g.hold()
	}
	if g.Ledger.Induction == Inducting && g.Ledger.Commit && g.Allocates && len(g.Pool) > 0 {
		es = append(es, g.commitInduction()...)
	}
	return es
}

func (g *Group) derived(indexes []Index) []Effect {
	g.Deriving = false
	g.Pool = append(g.Pool, indexes...)
	if len(indexes) > 0 {
		g.Tip = indexes[len(indexes)-1]
	}
	return g.progress()
}

func (g *Group) invite(name string, readCap []byte, commit bool) []Effect {
	g.Ledger.Induction = CatchingUp
	g.Ledger.Invitee = &Invitee{Name: name, ReadCap: readCap}
	g.Ledger.Commit = commit
	var es []Effect
	for _, r := range g.Readers.Values() {
		es = append(es, r.read()...)
	}
	return append(es, g.progress()...)
}

// Membership and time

// Remove stops reading member and forgets its key, keeping its places.
func (g *Group) Remove(member Key) {
	var token Key
	if place, ok := g.Rosters.indexOf(g.Me(), member); ok {
		token = placeholder(place)
	} else {
		token = Key("retired:") + member[:min(8, len(member))]
	}
	g.Rosters.retire(member, token)
	g.Readers.Delete(member)
	g.Ledger.forget(member)
	left := g.Unnumbered[:0:0]
	for _, a := range g.Unnumbered {
		if k, ok := g.Rosters.Introductions.Get(a); !ok || k != token {
			left = append(left, a)
		}
	}
	g.Unnumbered = left
}

func (g *Group) everyoneAcked(idx64 uint64) bool {
	for _, k := range g.Readers.Keys() {
		s, ok := g.Ledger.AckedBy.Get(k)
		if !ok || idx64 > s {
			return false
		}
	}
	return true
}

func (g *Group) onEpoch(epoch int) []Effect {
	g.Epoch = epoch
	g.Sent.retain(epoch, g.Policy, g.everyoneAcked)
	var es []Effect
	if g.Policy.KeepReceived == nil {
		g.Received = ordmap.Map[ReceivedAt, int]{}
	}
	if keep := g.Policy.KeepReceived; keep != nil {
		expired := map[ReceivedAt]bool{}
		for k, at := range g.Received.All {
			if at+*keep <= epoch {
				expired[k] = true
				es = append(es, Expire{Sender: k.Sender, Index: k.Index})
			}
		}
		g.Received.Filter(func(k ReceivedAt, _ int) bool { return !expired[k] })
	}
	return append(es, g.Sent.backfill(epoch, g.everyoneAcked)...)
}

// Driven by events

func (g *Group) Handle(e Event) []Effect {
	switch e := e.(type) {
	case Send:
		g.Outbox = append(g.Outbox, e.Content)
		return g.progress()
	case Read:
		if r, ok := g.Readers.Get(e.Stream); ok {
			return r.read()
		}
	case Scan:
		return g.scanStream(e.Stream)
	case BoxRead:
		return append(g.boxRead(e.Stream, e.Index, e.Result, e.Next), g.progress()...)
	case IndexesDerived:
		return g.derived(e.Indexes)
	case Walked:
		if r, ok := g.Readers.Get(e.Stream); ok {
			return r.walked(e.Target, e.Skipped, e.Steps, g.Recheck)
		}
	case Invite:
		return g.invite(e.Name, e.ReadCap, false)
	case Introduce:
		if g.Ledger.Induction == InductionIdle {
			return g.invite(e.Name, e.ReadCap, true)
		}
		g.Ledger.Commit = true
		return g.progress()
	case Remove:
		g.Remove(e.Member)
	case EpochChanged:
		return g.onEpoch(e.Epoch)
	}
	return nil
}

// Driven by a client that reads and writes for itself

// Observe takes a box read on stream, in order: its message, or nil for one that holds nothing
// we can use.
func (g *Group) Observe(stream Key, index Index, m *wire.Message, next Index) []Effect {
	r, ok := g.Readers.Get(stream)
	if !ok {
		return nil
	}
	r.Next, r.Mode = index, Reading
	es := g.boxRead(stream, index, ReadResult{Kind: ReadData, Message: m}, &next)
	if r, ok := g.Readers.Get(stream); ok {
		r.Mode = Idle
	}
	var out []Effect
	for _, e := range es {
		switch e.(type) {
		case Deliver, Expire:
			out = append(out, e)
		}
	}
	return out
}

// Compose returns the messages to send now, in order: a control message if one is owed, then
// content. Each takes effect when Written.
func (g *Group) Compose(content []byte) []Outgoing {
	g.Allocates = false
	type staged struct {
		m *wire.Message
		p *Pending
	}
	var owed []staged
	if g.owesControl() {
		m, p := g.control()
		owed = append(owed, staged{m, p})
	}
	if content != nil {
		owed = append(owed, staged{&wire.Message{Content: content}, &Pending{}})
	}
	var out []Outgoing
	for _, s := range owed {
		g.withAcks(s.m, s.p)
		out = append(out, g.stage(s.m, s.p))
	}
	return out
}

// OwesControl says whether a control message is owed, to go ahead of the next content.
func (g *Group) OwesControl() bool { return g.owesControl() }

// Acknowledge returns a control message carrying whatever is owed, acknowledgements among it,
// or nothing when nothing is.
func (g *Group) Acknowledge() []Outgoing {
	if !g.owesControl() && !g.owesAcks() {
		return nil
	}
	g.Allocates = false
	m, p := g.control()
	g.withAcks(m, p)
	return []Outgoing{g.stage(m, p)}
}

// owesAcks says whether a stream we read has moved on since we last acknowledged it.
func (g *Group) owesAcks() bool {
	for _, e := range g.Rosters.known(g.Me()) {
		if e.Key == nil {
			continue
		}
		if r, ok := g.Readers.Get(*e.Key); ok && g.Ledger.owed(r.Stream, r.run()) != nil {
			return true
		}
	}
	return false
}

// Abandoned says the message token will never be written: whatever it acknowledged is owed
// again, and whoever it numbered still needs numbering.
func (g *Group) Abandoned(token int) {
	p, ok := g.Pending.Get(token)
	if !ok {
		return
	}
	for stream, a := range p.Acks.All {
		if cur, ok := g.Ledger.Published.Get(stream); ok && cur == a.Now {
			if a.Before != nil {
				g.Ledger.Published.Set(stream, *a.Before)
			} else {
				g.Ledger.Published.Delete(stream)
			}
		}
	}
	g.Pending.Delete(token)
	if p.Introduced == nil {
		for _, n := range p.Numbers {
			if n.At != nil {
				g.Unnumbered = append(g.Unnumbered, *n.At)
			}
		}
	}
}

// BeginInduction begins inducting a member, starting each stream where we have read it now.
// Anything owed goes out first.
func (g *Group) BeginInduction() []Outgoing {
	out := g.Compose(nil)
	g.hold()
	return out
}

func (g *Group) CancelInduction() { g.release() }

// Known is every index owner is known to have assigned, in ascending order, and to whom.
func (g *Group) Known(owner Key) []KnownEntry { return g.Rosters.known(owner) }

// Resolve is who owner numbered index, if this member can tell.
func (g *Group) Resolve(owner Key, index int) (Key, bool) { return g.Rosters.resolve(owner, index) }
