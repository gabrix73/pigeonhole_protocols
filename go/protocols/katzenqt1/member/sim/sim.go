// Package sim runs katzenqt's group chat scenarios (its groupchat/sim.py) through the member, with
// the same replica rules, the same seeded keys and the same way of printing what each member
// read, wrote, acknowledged and resolved.
package sim

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/pigeonhole_protocols/go/internal/ordmap"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

// draw is shake_256("{name}/{n}"), the nth draw of katzenqt's seeded randomness.
func draw(name string, n, size int) []byte {
	out := make([]byte, size)
	sha3.ShakeSum256(out, []byte(fmt.Sprintf("%s/%d", name, n)))
	return out
}

// capOf is the write cap katzenqt's WriteCap.generate(seeded(name)) makes: a signing seed, then
// an HKDF state and a starting index.
func capOf(name string) (*bacap.WriteCap, error) {
	return bacap.NewWriteCap(io.MultiReader(bytes.NewReader(draw(name, 1, 32)),
		bytes.NewReader(draw(name, 2, 32)), bytes.NewReader(draw(name, 3, 16))))
}

func step(i member.Index) member.Index {
	n, err := member.NextIndex(i)
	if err != nil {
		return ""
	}
	return n
}

// stored is what a box holds: a message, or a tombstone (nil).
type stored = *wire.Message

type slot struct {
	index member.Index
	box   stored
}

type bucket struct {
	epoch int
	boxes []slot
}

type replica struct {
	epoch   int
	buckets []bucket
}

func (r *replica) kept() []int {
	if r.epoch == 0 {
		return []int{0}
	}
	return []int{r.epoch, r.epoch - 1}
}

func (r *replica) bucket(e int) []slot {
	for _, b := range r.buckets {
		if b.epoch == e {
			return b.boxes
		}
	}
	return nil
}

func (r *replica) find(e int, index member.Index) (stored, bool) {
	for _, s := range r.bucket(e) {
		if s.index == index {
			return s.box, true
		}
	}
	return nil, false
}

func (r *replica) read(index member.Index) (stored, bool) {
	for _, e := range r.kept() {
		if b, ok := r.find(e, index); ok {
			return b, true
		}
	}
	return nil, false
}

// write stores a box: a write to a box still kept succeeds only with what it holds already, and a
// tombstone is always stored.
func (r *replica) write(index member.Index, box stored) string {
	if box != nil {
		if old, ok := r.read(index); ok {
			if old.Equal(box) {
				return "same"
			}
			return "refused"
		}
	}
	var b []slot
	for _, s := range r.bucket(r.epoch) {
		if s.index != index {
			b = append(b, s)
		}
	}
	b = append(b, slot{index, box})
	var bs []bucket
	for _, x := range r.buckets {
		if x.epoch != r.epoch {
			bs = append(bs, x)
		}
	}
	r.buckets = append(bs, bucket{r.epoch, b})
	return "stored"
}

func (r *replica) advance() {
	r.epoch++
	kept := r.kept()
	var bs []bucket
	for _, b := range r.buckets {
		if slices.Contains(kept, b.epoch) {
			bs = append(bs, b)
		}
	}
	r.buckets = bs
}

type delivered struct {
	sender member.Key
	index  member.Index
	text   string
}

type seenBox struct {
	stream member.Key
	index  member.Index
	msg    *wire.Message
}

type simMember struct {
	name    string
	first   member.Index
	readCap []byte
	// chain is our stream's indexes from its first, WalkLimit of them.
	chain     []member.Index
	group     *member.Group
	inbox     []delivered
	seen      []seenBox
	reported  int64
	passive   bool
	unwritten []member.Outgoing
	nextOwn   member.Index
	cursors   ordmap.Map[member.Key, member.Index]
}

func (m *simMember) key() member.Key { return member.Key(wire.KeyOf(m.readCap)) }

func (m *simMember) ordinalOf(index member.Index) (int, bool) {
	i := slices.Index(m.chain, index)
	return i, i >= 0
}

// ordinalAt is which box of our stream an Idx64 names.
func (m *simMember) ordinalAt(idx64 uint64) (int, bool) {
	first := wire.Counter([]byte(m.chain[0]))
	if first <= idx64 && idx64-first < member.WalkLimit {
		return int(idx64 - first), true
	}
	return 0, false
}

type optValue struct {
	kind int // 0 flag, 1 nothing, 2 number
	flag bool
	num  int
}

type option struct {
	name  string
	value optValue
}

// Recorder is told of every call made on a member, in katzenqt's trace format.
type Recorder func(call string, me member.Key, name string, args map[string]any, result any, g *member.Group)

type world struct {
	replica replica
	members []*simMember
	options []option
	record  Recorder
}

type simError struct{ msg string }

func fail(format string, a ...any) { panic(simError{fmt.Sprintf(format, a...)}) }

func (w *world) option(name string) (optValue, bool) {
	for _, o := range w.options {
		if o.name == name {
			return o.value, true
		}
	}
	return optValue{}, false
}

func (w *world) flag(name string) bool {
	v, ok := w.option(name)
	return ok && v.kind == 0 && v.flag
}

func (w *world) policy() member.Retention {
	num := func(n string, d *int) *int {
		v, ok := w.option(n)
		switch {
		case ok && v.kind == 2:
			k := v.num
			return &k
		case ok && v.kind == 1:
			return nil
		}
		return d
	}
	three := 3
	discard := true
	if v, ok := w.option("discard_acked"); ok && v.kind == 0 {
		discard = v.flag
	}
	return member.Retention{Window: num("window", &three), KeepSent: num("keep_sent", nil),
		KeepReceived: num("keep_received", nil), DiscardAcked: discard}
}

func (w *world) recheck() int {
	if v, ok := w.option("recheck"); ok && v.kind == 2 {
		return v.num
	}
	return 256
}

func (w *world) newMember(name string) int {
	wc, err := capOf(name)
	if err != nil {
		fail("%v", err)
	}
	rc, err := wc.ReadCap().MarshalBinary()
	if err != nil {
		fail("%v", err)
	}
	first := member.Index(rc[wire.KeySize:])
	chain := []member.Index{first}
	for len(chain) < member.WalkLimit {
		chain = append(chain, step(chain[len(chain)-1]))
	}
	m := &simMember{name: name, first: first, readCap: rc, chain: chain, reported: -1}
	for i, o := range w.members {
		if o.name == name {
			w.members[i] = m
			return i
		}
	}
	w.members = append(w.members, m)
	return len(w.members) - 1
}

func (w *world) member(name string) int {
	for i, m := range w.members {
		if m.name == name {
			return i
		}
	}
	return w.newMember(name)
}

func (w *world) existing(name string) int {
	for i, m := range w.members {
		if m.name == name {
			return i
		}
	}
	fail("no member %s", name)
	return 0
}

func (w *world) groupOf(i int) *member.Group {
	if w.members[i].group == nil {
		fail("%s has not joined", w.members[i].name)
	}
	return w.members[i].group
}

func (w *world) byKey(k member.Key) (int, bool) {
	for i, m := range w.members {
		if m.key() == k {
			return i, true
		}
	}
	return 0, false
}

func (w *world) nameOf(k *member.Key) string {
	if k == nil {
		return "?"
	}
	if strings.HasPrefix(string(*k), "retired") {
		return "removed"
	}
	if i, ok := w.byKey(*k); ok {
		return w.members[i].name
	}
	return "?"
}

// atIndex is name@n: the nth box of its stream.
func (w *world) atIndex(k member.Key, index member.Index) string {
	i, ok := w.byKey(k)
	if !ok {
		fail("no member with that key")
	}
	m := w.members[i]
	if n, ok := m.ordinalOf(index); ok {
		return fmt.Sprintf("%s@%d", m.name, n)
	}
	return m.name + "@None"
}

func (w *world) atIdx64(k member.Key, idx64 uint64) string {
	i, ok := w.byKey(k)
	if !ok {
		fail("no member with that key")
	}
	m := w.members[i]
	if n, ok := m.ordinalAt(idx64); ok {
		return fmt.Sprintf("%s@%d", m.name, n)
	}
	return m.name + "@None"
}

// whereIdx64 is which stream's box an Idx64 names.
func (w *world) whereIdx64(idx64 uint64) string {
	for _, m := range w.members {
		if n, ok := m.ordinalAt(idx64); ok {
			return fmt.Sprintf("%s@%d", m.name, n)
		}
	}
	return "?"
}

// prefixed is who has a key starting with prefix: the truth.
func (w *world) prefixed(p []byte) string {
	var found []*simMember
	for _, m := range w.members {
		if bytes.HasPrefix([]byte(m.key()), p) {
			found = append(found, m)
		}
	}
	if len(found) == 1 {
		return found[0].name
	}
	return "?"
}

// introduced is who the Introduction in the box index introduced: the truth, from its
// introducer's records.
func (w *world) introduced(index []byte) string {
	for _, m := range w.members {
		if m.group == nil {
			continue
		}
		r, ok := m.group.Sent.Records.Get(wire.Counter(index))
		if !ok || r.Index != member.Index(index) {
			continue
		}
		if r.Plaintext != nil && r.Plaintext.Message != nil && r.Plaintext.Message.Introduction != nil {
			return r.Plaintext.Message.Introduction.Name
		}
	}
	return "?"
}

func sortedAcks(acks []wire.Ack) []wire.Ack {
	s := slices.Clone(acks)
	slices.SortStableFunc(s, func(a, b wire.Ack) int { return cmp.Compare(a.Member, b.Member) })
	return s
}

func (w *world) showMsg(m *wire.Message) string {
	var parts []string
	if m.Content != nil {
		parts = append(parts, `"`+string(m.Content)+`"`)
	}
	if m.Introduction != nil {
		parts = append(parts, "introduces "+m.Introduction.Name)
	}
	if m.IntroducedAt != nil {
		parts = append(parts, "introduced-at "+w.introduced(m.IntroducedAt.Index))
	}
	if len(m.Numbers) > 0 {
		var ns []string
		for _, n := range m.Numbers {
			who := "?"
			switch {
			case n.Prefix != nil:
				if len(n.Prefix) != 0 {
					who = w.prefixed(n.Prefix)
				}
			case m.Introduction != nil:
				who = m.Introduction.Name
			}
			ns = append(ns, fmt.Sprintf("%d:%s", n.Index, who))
		}
		parts = append(parts, "numbers "+strings.Join(ns, " "))
	}
	if len(m.Acks) > 0 {
		var as []string
		for _, a := range sortedAcks(m.Acks) {
			as = append(as, fmt.Sprintf("%d:%s", a.Member, w.whereIdx64(a.Idx64)))
		}
		parts = append(parts, "acks "+strings.Join(as, " "))
	}
	if len(parts) == 0 {
		return "(empty)"
	}
	return strings.Join(parts, " ")
}

type fetched struct {
	kind member.ReadKind
	msg  *wire.Message
}

func (f fetched) value() string {
	if f.kind == member.ReadTombstone {
		return "tombstone"
	}
	return "not found"
}

func (w *world) fetch(index member.Index) (fetched, *member.Index) {
	box, ok := w.replica.read(index)
	if !ok {
		return fetched{kind: member.ReadNotFound}, nil
	}
	next := step(index)
	if box == nil {
		return fetched{kind: member.ReadTombstone}, &next
	}
	return fetched{kind: member.ReadData, msg: box}, &next
}

func (w *world) storeOk(index member.Index, box stored) {
	if r := w.replica.write(index, box); r != "stored" && r != "same" {
		fail("a write was %s", r)
	}
}

func (w *world) showRead(i int, stream member.Key, index member.Index, f fetched, recheck bool) []string {
	where := w.atIndex(stream, index)
	if f.kind == member.ReadData {
		m := w.members[i]
		seen := m.seen[:0:0]
		for _, s := range m.seen {
			if s.stream != stream || s.index != index {
				seen = append(seen, s)
			}
		}
		m.seen = append(seen, seenBox{stream, index, f.msg})
		return []string{where + " " + w.showMsg(f.msg)}
	}
	if recheck {
		return []string{where + " recheck: " + f.value()}
	}
	lines := []string{where + " " + f.value()}
	o, ok := w.byKey(stream)
	if !ok {
		return lines
	}
	here, ok := w.members[o].ordinalOf(index)
	if f.kind != member.ReadNotFound || !ok {
		return lines
	}
	if h, ok := w.groupOf(i).Ledger.Heard.Get(stream); ok {
		for by, heard := range h.All {
			if there, ok := w.members[o].ordinalAt(heard); ok && there >= here {
				lines = append(lines, fmt.Sprintf("  stuck: %s acked %s", w.nameOf(&by), w.atIdx64(stream, heard)))
			}
		}
	}
	return lines
}

func resultOf(f fetched) member.ReadResult {
	return member.ReadResult{Kind: f.kind, Message: f.msg}
}

func (w *world) makePassive(i int) {
	if w.flag("passive") {
		w.members[i].passive = true
		w.members[i].nextOwn = w.members[i].first
	}
}

func (w *world) join(i int, reply *wire.JoinReply) []string {
	m := w.members[i]
	if m.group != nil {
		return []string{m.name + " already joined"}
	}
	g := w.joined(m, reply)
	w.handle(m, g, member.EpochChanged{Epoch: w.replica.epoch})
	w.makePassive(i)
	return nil
}

// drive hands event to member i and carries out its effects, depth first, until there are none
// left.
func (w *world) drive(i int, event member.Event) []string {
	var out []string
	m := w.members[i]
	pending := w.handle(m, w.groupOf(i), event)
	for len(pending) > 0 {
		e := pending[0]
		pending = pending[1:]
		var follow member.Event
		switch e := e.(type) {
		case member.WriteBox:
			if e.Payload.Message == nil {
				fail("a member asked to write bytes it was never given")
			}
			w.storeOk(e.Index, e.Payload.Message)
		case member.WriteTombstone:
			w.storeOk(e.Index, nil)
		case member.ReadBox:
			f, next := w.fetch(e.Index)
			out = append(out, w.showRead(i, e.Stream, e.Index, f, e.Recheck)...)
			follow = member.BoxRead{Stream: e.Stream, Index: e.Index, Result: resultOf(f), Next: next}
		case member.DeriveIndexes:
			var is []member.Index
			at := e.Start
			for range max(e.Count, 1) {
				at = step(at)
				is = append(is, at)
			}
			follow = member.IndexesDerived{Stream: e.Stream, Indexes: is}
		case member.Walk:
			target, skipped, steps, _ := member.WalkWith(func(i member.Index) (member.Index, error) { return step(i), nil },
				e.Start, e.Targets, e.Keep)
			follow = member.Walked{Stream: e.Stream, Target: target, Skipped: skipped, Steps: steps}
		case member.Deliver:
			m.inbox = append(m.inbox, delivered{e.Sender, e.Index, string(e.Content)})
		case member.Expire:
			kept := m.inbox[:0:0]
			for _, d := range m.inbox {
				if d.sender != e.Sender || d.index != e.Index {
					kept = append(kept, d)
				}
			}
			m.inbox = kept
		case member.SendJoinReply:
			n, ok := w.byKey(member.Key(wire.KeyOf(e.To)))
			if !ok {
				fail("a join reply to no member")
			}
			out = append(out, w.join(n, e.Reply)...)
		}
		if follow != nil {
			pending = append(w.handle(m, w.groupOf(i), follow), pending...)
		}
	}
	return out
}

// land writes what member i has composed, in order, as a client's own write queue would.
func (w *world) land(i int) {
	m := w.members[i]
	for _, o := range m.unwritten {
		at := m.nextOwn
		w.storeOk(at, o.Message)
		w.written(m, o.Token, at, &member.Payload{Message: o.Message})
		m.nextOwn = step(at)
	}
	m.unwritten = nil
}

func (w *world) queue(i int, out []member.Outgoing) {
	w.members[i].unwritten = append(w.members[i].unwritten, out...)
	if !w.flag("delay_writes") {
		w.land(i)
	}
}

// writtenSince is what member i has written since a command last printed it.
func (w *world) writtenSince(i int) []string {
	m := w.members[i]
	g := w.groupOf(i)
	keys := g.Sent.Records.Keys()
	slices.Sort(keys)
	var lines []string
	for _, idx64 := range keys {
		r, _ := g.Sent.Records.Get(idx64)
		if int64(idx64) > m.reported && r.Plaintext != nil && r.Plaintext.Message != nil {
			lines = append(lines, w.atIndex(m.key(), r.Index)+" "+w.showMsg(r.Plaintext.Message))
			m.reported = int64(idx64)
		}
	}
	return lines
}

func (w *world) readPassively(i, owner int) []string {
	m, o := w.members[i], w.members[owner]
	r, ok := w.groupOf(i).Readers.Get(o.key())
	if !ok {
		return nil
	}
	cursor := m.cursors.GetOr(o.key(), r.Next)
	var out []string
	for {
		f, next := w.fetch(cursor)
		out = append(out, w.showRead(i, o.key(), cursor, f, false)...)
		if next == nil {
			break
		}
		for _, e := range w.observe(m, o.key(), cursor, f.msg, *next) {
			if d, ok := e.(member.Deliver); ok {
				m.inbox = append(m.inbox, delivered{d.Sender, d.Index, string(d.Content)})
			}
		}
		cursor = *next
	}
	m.cursors.Set(o.key(), cursor)
	return out
}

func (w *world) invite(who, new string) []string {
	i := w.existing(who)
	if w.members[i].passive {
		w.land(i)
		w.queue(i, w.beginInduction(w.members[i]))
		w.land(i)
		return w.writtenSince(i)
	}
	n := w.member(new)
	out := w.drive(i, member.Invite{Name: new, ReadCap: w.members[n].readCap})
	return append(out, w.writtenSince(i)...)
}

func (w *world) introduce(who, new string) []string {
	i := w.existing(who)
	if w.members[i].passive {
		if w.groupOf(i).Ledger.Induction != member.Inducting {
			w.invite(who, new)
		}
		reply := w.reply(w.members[i], w.members[i].nextOwn)
		n := w.member(new)
		o := w.introduceNow(w.members[i], new, w.members[n].readCap)
		w.queue(i, []member.Outgoing{o})
		w.land(i)
		out := w.join(n, reply)
		return append(out, w.writtenSince(i)...)
	}
	n := w.member(new)
	out := w.drive(i, member.Introduce{Name: new, ReadCap: w.members[n].readCap})
	return append(out, w.writtenSince(i)...)
}

func (w *world) joinedNames() []string {
	var names []string
	for _, m := range w.members {
		if m.group != nil {
			names = append(names, m.name)
		}
	}
	slices.Sort(names)
	return names
}

func (w *world) backfill(who string) []string {
	return w.drive(w.existing(who), member.EpochChanged{Epoch: w.replica.epoch})
}

func count(n []string) int {
	if len(n) == 0 {
		return 1
	}
	v, _ := strconv.Atoi(n[0])
	return v
}

func atoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func (w *world) command(words []string) []string {
	arg := func(n int) bool { return len(words) == n }
	switch {
	case words[0] == "option" && arg(3):
		if len(w.members) > 0 {
			fail("set options before new-group")
		}
		var v optValue
		switch words[2] {
		case "on":
			v = optValue{kind: 0, flag: true}
		case "off":
			v = optValue{kind: 0}
		case "none":
			v = optValue{kind: 1}
		default:
			v = optValue{kind: 2, num: atoi(words[2])}
		}
		w.options = append([]option{{strings.ReplaceAll(words[1], "-", "_"), v}}, w.options...)
		return nil
	case words[0] == "new-group":
		var founders []int
		for _, n := range words[1:] {
			founders = append(founders, w.newMember(n))
		}
		var caps [][]byte
		for _, i := range founders {
			caps = append(caps, w.members[i].readCap)
		}
		for _, i := range founders {
			w.found(w.members[i], caps)
			w.makePassive(i)
		}
		return nil
	case words[0] == "send" && len(words) >= 2:
		i := w.existing(words[1])
		content := []byte(strings.Join(words[2:], " "))
		if w.members[i].passive {
			w.queue(i, w.compose(w.members[i], content))
			return w.writtenSince(i)
		}
		out := w.drive(i, member.Send{Content: content})
		return append(out, w.writtenSince(i)...)
	case words[0] == "invite" && arg(3):
		return w.invite(words[1], words[2])
	case words[0] == "introduce" && arg(3):
		return w.introduce(words[1], words[2])
	case words[0] == "land" && arg(2):
		w.land(w.existing(words[1]))
		return nil
	case words[0] == "abandon" && arg(2):
		i := w.existing(words[1])
		m := w.members[i]
		control := func(msg *wire.Message) bool {
			return msg.Introduction != nil || len(msg.Numbers) > 0 || msg.IntroducedAt != nil
		}
		for j := len(m.unwritten) - 1; j >= 0; j-- {
			o := m.unwritten[j]
			if !control(o.Message) {
				m.unwritten = slices.DeleteFunc(slices.Clone(m.unwritten), func(x member.Outgoing) bool { return x.Token == o.Token })
				w.abandoned(m, o.Token)
				break
			}
		}
		return nil
	case words[0] == "remove" && arg(3):
		return w.drive(w.existing(words[1]), member.Remove{Member: w.members[w.existing(words[2])].key()})
	case (words[0] == "read" || words[0] == "scan") && arg(3):
		i := w.existing(words[1])
		if w.members[i].passive {
			return w.readPassively(i, w.existing(words[2]))
		}
		k := w.members[w.existing(words[2])].key()
		if words[0] == "read" {
			return w.drive(i, member.Read{Stream: k})
		}
		return w.drive(i, member.Scan{Stream: k})
	case words[0] == "epoch":
		for range count(words[1:]) {
			w.replica.advance()
		}
		return nil
	case words[0] == "backfill" && arg(2):
		return w.backfill(words[1])
	case words[0] == "tick":
		var out []string
		for range count(words[1:]) {
			w.replica.advance()
			for _, n := range w.joinedNames() {
				out = append(out, w.backfill(n)...)
			}
		}
		return out
	case words[0] == "roster" && arg(3):
		known := w.groupOf(w.existing(words[1])).Known(w.members[w.existing(words[2])].key())
		if len(known) == 0 {
			return []string{"unknown"}
		}
		top := 0
		for _, e := range known {
			top = max(top, e.Index)
		}
		var names []string
		for n := 0; n <= top; n++ {
			var k *member.Key
			for _, e := range known {
				if e.Index == n {
					k = e.Key
					break
				}
			}
			names = append(names, w.nameOf(k))
		}
		return []string{strings.Join(names, " ")}
	case words[0] == "acks" && arg(4):
		sender := w.members[w.existing(words[2])]
		at := sender.chain[atoi(words[3])]
		var msg *wire.Message
		for _, s := range w.members[w.existing(words[1])].seen {
			if s.stream == sender.key() && s.index == at {
				msg = s.msg
				break
			}
		}
		if msg == nil {
			return []string{"not read"}
		}
		g := w.groupOf(w.existing(words[1]))
		var parts []string
		for _, a := range sortedAcks(msg.Acks) {
			k, ok := g.Resolve(sender.key(), a.Member)
			var kp *member.Key
			if ok {
				kp = &k
			}
			parts = append(parts, w.nameOf(kp)+"="+w.whereIdx64(a.Idx64))
		}
		if len(parts) == 0 {
			return []string{"none"}
		}
		return []string{strings.Join(parts, " ")}
	case words[0] == "acked" && arg(2):
		i := w.existing(words[1])
		g := w.groupOf(i)
		keys := g.Ledger.AckedBy.Keys()
		slices.SortStableFunc(keys, func(a, b member.Key) int { return bytes.Compare([]byte(a), []byte(b)) })
		var parts []string
		for _, acker := range keys {
			idx64, _ := g.Ledger.AckedBy.Get(acker)
			if r, ok := g.Sent.Records.Get(idx64); ok {
				parts = append(parts, w.nameOf(&acker)+":"+w.atIndex(w.members[i].key(), r.Index))
			}
		}
		if len(parts) == 0 {
			return []string{"none"}
		}
		return []string{strings.Join(parts, " ")}
	case words[0] == "inbox" && arg(2):
		var lines []string
		for _, d := range w.members[w.existing(words[1])].inbox {
			lines = append(lines, w.atIndex(d.sender, d.index)+` "`+d.text+`"`)
		}
		if len(lines) == 0 {
			return []string{"empty"}
		}
		return lines
	case words[0] == "peek" && arg(3):
		o := w.members[w.existing(words[1])]
		f, _ := w.fetch(o.chain[atoi(words[2])])
		if f.kind == member.ReadData {
			return []string{w.showMsg(f.msg)}
		}
		return []string{f.value()}
	}
	fail("unknown command %s", strings.Join(words, " "))
	return nil
}

// Run runs a scenario, returning it with every checked command's output replaced by what it
// printed now. With record set, every call on a member is recorded.
func Run(script string, record Recorder) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(simError); ok {
				err = errors.New(e.msg)
				return
			}
			panic(r)
		}
	}()
	w := &world{record: record}
	lines := strings.Split(script, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var res []string
	for i := 0; i < len(lines); {
		line := lines[i]
		res = append(res, line)
		i++
		cmd := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if cmd == "" {
			continue
		}
		var words []string
		for _, f := range strings.Split(cmd, " ") {
			if f != "" {
				words = append(words, f)
			}
		}
		printed := w.command(words)
		if i < len(lines) && lines[i] == "----" {
			res = append(res, "----")
			i++
			for i < len(lines) && strings.TrimSpace(lines[i]) != "" {
				i++
			}
			res = append(res, printed...)
		}
	}
	return strings.Join(res, "\n") + "\n", nil
}
