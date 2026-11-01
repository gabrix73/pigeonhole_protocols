package engine

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/katzenpost/pigeonhole_protocols/internal/ordmap"
	"github.com/katzenpost/pigeonhole_protocols/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/protocols/katzenqt1/wire"
	"github.com/katzenpost/pigeonhole_protocols/transport"
)

// Window is how many boxes of an upload are written at once.
const Window = 8

// Backoff is how long to wait, in milliseconds, before reading a box that was not there, after n
// misses before.
func Backoff(n int) int { return min(60000, 2000<<min(n, 5)) }

type Engine struct {
	State        *State
	MaxPlaintext int
	// Epoch is the replicas' epoch as last reported; a group made now starts there, so that
	// what it writes before the next report is not taken for hundreds of epochs old when the
	// report comes.
	Epoch  int
	flight flight
	now    int64
	out    Result
}

func New(s *State, maxPlaintext int) *Engine {
	return &Engine{State: s, MaxPlaintext: maxPlaintext, flight: newFlight()}
}

func (e *Engine) begin(now int64) {
	e.now = now
	e.out = Result{Changes: Changes{Chats: map[ChatID]bool{}, Lines: map[ChatID]map[int]bool{},
		Dropped: map[ChatID]map[int]bool{}, Removed: map[ChatID]bool{}}}
}

func (e *Engine) emit(a Action) { e.out.Actions = append(e.out.Actions, a) }

func (e *Engine) keep(file string, b []byte) {
	e.out.Files = append(e.out.Files, FileWrite{file, b})
}

func (e *Engine) dirty(c *Chat) { e.out.Changes.Chats[c.ID] = true }

func (e *Engine) lineChanged(c *Chat, id int) {
	m := e.out.Changes.Lines[c.ID]
	if m == nil {
		m = map[int]bool{}
		e.out.Changes.Lines[c.ID] = m
	}
	m[id] = true
}

func (e *Engine) lineDropped(c *Chat, id int) {
	if m := e.out.Changes.Lines[c.ID]; m != nil {
		delete(m, id)
	}
	m := e.out.Changes.Dropped[c.ID]
	if m == nil {
		m = map[int]bool{}
		e.out.Changes.Dropped[c.ID] = m
	}
	m[id] = true
}

// say adds a line, returning its id.
func (e *Engine) say(c *Chat, l Line) int {
	l.ID = c.fresh()
	l.Time = e.now
	c.Log = append(c.Log, &l)
	e.dirty(c)
	e.lineChanged(c, l.ID)
	if len(c.Log) > MaxLog {
		for _, d := range c.Log[:len(c.Log)-MaxLog] {
			if d.Attachment != nil {
				e.emit(DoDelete{d.Attachment.File})
			}
			e.lineDropped(c, d.ID)
		}
		c.Log = slices.Clone(c.Log[len(c.Log)-MaxLog:])
	}
	return l.ID
}

func (e *Engine) notice(c *Chat, kind NoticeKind, args ...string) {
	e.say(c, Line{Notice: &Notice{Kind: kind, Args: args}})
}

// Writing

// boxOf is the box an outgoing message is written as. A message the member makes itself carries
// the membership hash it stamped when composed, an Introduction the hash before the member it
// introduces, so a rewrite writes the same box; content carries the hash it was composed with.
func boxOf(o member.Outgoing) []byte { return wire.Box(o.Message) }

func spoolFile(c *Chat, job int, now int64) string {
	return fmt.Sprintf("spool/%s-%d-%d.cbor", slug(c.Name), now, job)
}

// enqueue queues outgoing, each written after the one before; line shows the one carrying
// content, into which the bytes of a file it carries, payload, are put. A message too long for a
// box goes to a substream, written before the I box naming it.
func (e *Engine) enqueue(c *Chat, outgoing []member.Outgoing, content []byte, line *int, payload []byte) {
	max := e.MaxPlaintext
	for _, o := range outgoing {
		g := c.Group
		if g == nil {
			continue
		}
		mine := content != nil && o.Message.Content != nil && bytes.Equal(o.Message.Content, content)
		box := boxOf(o)
		if box != nil && payload != nil && mine {
			if full, ok := wire.PutPayload(box[1:], payload); ok {
				box = wire.Frame(full)
			} else {
				box = nil
			}
		}
		if box != nil {
			var l *int
			if mine {
				l = line
			}
			token := o.Token
			if len(box) <= max {
				c.Jobs = append(c.Jobs, &Job{ID: c.fresh(), Token: &token, Box: box, Line: l})
				e.dirty(c)
				continue
			}
			if blob := box[1:]; len(blob) <= wire.MaxFile+max {
				id := c.fresh()
				file := spoolFile(c, id, e.now)
				e.keep(file, blob)
				e.flight.blobs[jobKey{c.ID, id}] = blob
				u := &Upload{File: file, BoxSize: max, Total: wire.ChunkCount(len(blob), max)}
				c.Jobs = append(c.Jobs, &Job{ID: id, Token: &token, Box: []byte{}, Line: l, Upload: u})
				e.dirty(c)
				continue
			}
		}
		g.Abandoned(o.Token)
		if mine {
			e.notice(c, TooLong)
		} else {
			e.notice(c, NotWritten)
		}
	}
}

// rewrite queues a box the member asks to write again, or to tombstone.
func (e *Engine) rewrite(c *Chat, index member.Index, box []byte) {
	i := index
	c.Jobs = append(c.Jobs, &Job{ID: c.fresh(), Index: &i, Box: box})
	e.dirty(c)
}

// Reading

func fileText(a *Attachment) string { return fmt.Sprintf("[file %s, %s]", a.Name, SizeText(a.Size)) }

func attachmentFile(c *Chat, id int, now int64, name string) string {
	return fmt.Sprintf("attachments/%s/%d-%d-%s", slug(c.Name), now, id, name)
}

// deliver adds a line for content from sender, and keeps the file it carries.
func (e *Engine) deliver(c *Chat, sender member.Key, index member.Index, content []byte) {
	var f wire.FileUpload
	ok := false
	if g := wire.DecodeGcm(content); g != nil {
		f, ok = wire.FileOf(g)
	}
	if !ok {
		e.say(c, Line{Sender: sender, Index: index, Text: wire.TextOf(content)})
		return
	}
	if p, ok := e.flight.arriving[boxKey{sender, index}]; ok {
		f.Payload = p
	}
	name := wire.SafeName(f.Basename)
	a := &Attachment{Name: name, Filetype: f.Filetype, Size: len(f.Payload), File: attachmentFile(c, c.NextID, e.now, name)}
	if len(f.Payload) > wire.MaxFile {
		e.say(c, Line{Sender: sender, Index: index, Text: fmt.Sprintf("[file %s, %s, too large to keep]", name, SizeText(a.Size))})
		return
	}
	e.keep(a.File, f.Payload)
	e.say(c, Line{Sender: sender, Index: index, Text: fileText(a), Attachment: a})
}

// dropLines keeps the lines keep holds of, and deletes the files the others carry.
func (e *Engine) dropLines(c *Chat, keep func(*Line) bool) {
	var kept []*Line
	for _, l := range c.Log {
		if keep(l) {
			kept = append(kept, l)
			continue
		}
		if l.Attachment != nil {
			e.emit(DoDelete{l.Attachment.File})
		}
		e.lineDropped(c, l.ID)
	}
	if len(kept) != len(c.Log) {
		e.dirty(c)
	}
	c.Log = kept
}

// effects does what the member asks.
func (e *Engine) effects(c *Chat, es []member.Effect) {
	for _, ef := range es {
		switch ef := ef.(type) {
		case member.WriteBox:
			box := ef.Payload.Bytes
			if ef.Payload.Message != nil {
				box = wire.Box(ef.Payload.Message)
			}
			if box != nil {
				e.rewrite(c, ef.Index, box)
			}
		case member.WriteTombstone:
			e.rewrite(c, ef.Index, []byte{})
		case member.ReadBox:
			e.emit(DoScanRead{c.ID, ef.Stream, ef.ReadCap, ef.Index})
		case member.DeriveIndexes:
			e.emit(DoDerive{c.ID, ef.Stream, ef.Start, ef.Count})
		case member.Walk:
			e.emit(DoWalk{c.ID, ef.Stream, ef.Start, ef.Targets, ef.Keep})
		case member.Deliver:
			e.deliver(c, ef.Sender, ef.Index, ef.Content)
		case member.Expire:
			e.dropLines(c, func(l *Line) bool { return !(l.Sender == ef.Sender && l.Index == ef.Index) })
		}
	}
}

// messageOf is what a box holds, as a member reads it.
func messageOf(plaintext []byte) *wire.Message {
	if ch := wire.Unframe(plaintext); ch.Kind == wire.ChunkFinal {
		return wire.ToMessage(ch.Data)
	}
	return nil
}

// label is a member as a notice names them: me, or the name they chose after ~.
func label(c *Chat, key member.Key) string {
	if c.Group != nil && c.Group.Me() == key {
		return "me"
	}
	return "~" + c.Names.GetOr(key, "?")
}

// remark notes for the conversation who an Introduction introduced, or a message this client
// cannot show.
func (e *Engine) remark(c *Chat, stream member.Key, plaintext []byte) {
	switch ch := wire.Unframe(plaintext); ch.Kind {
	case wire.ChunkFinal:
		m := wire.ToMessage(ch.Data)
		if m == nil || m.Introduction == nil {
			return
		}
		i := m.Introduction
		k := member.Key(wire.KeyOf(i.ReadCap))
		if !c.Names.Has(k) {
			c.Names.Set(k, i.Name)
			e.dirty(c)
		}
		if c.Group != nil && c.Group.Me() == k {
			return
		}
		e.notice(c, MemberAdded, label(c, stream), i.Name)
	case wire.ChunkContinued:
		e.notice(c, Unreadable, label(c, stream))
	}
}

// Under way

func (e *Engine) startReads(c *Chat) {
	g := c.Group
	if g == nil {
		return
	}
	for _, r := range g.Readers.Values() {
		k := streamKey{c.ID, r.Stream}
		if e.flight.reading[k] || slices.ContainsFunc(c.Downloads, func(d Download) bool { return d.Stream == r.Stream }) {
			continue
		}
		at, ok := c.Cursors.Get(r.Stream)
		if !ok {
			at = r.Next
			c.Cursors.Set(r.Stream, at)
			e.dirty(c)
		}
		e.flight.reading[k] = true
		e.emit(DoRead{c.ID, r.Stream, r.ReadCap, at})
	}
}

func (e *Engine) startWrite(c *Chat) {
	if e.flight.writing[c.ID] || len(c.WriteCap) == 0 || len(c.Jobs) == 0 {
		return
	}
	// While a reply is sealing, nothing takes the next index: the reply names it as where the
	// new member starts reading, and the Introduction, queued first once the reply is sealed,
	// must be the box there.
	if c.Inducting != nil && c.Inducting.Sealing {
		return
	}
	j := c.Jobs[0]
	if j.Upload != nil && j.Upload.Sent < j.Upload.Total {
		return
	}
	if j.Index == nil {
		i := c.NextWrite
		j.Index = &i
		e.dirty(c)
	}
	e.flight.writing[c.ID] = true
	e.emit(DoWrite{c.ID, j.ID, c.WriteCap, *j.Index, j.Box})
}

// startInduction seals the new member's reply, once everything owed is written.
func (e *Engine) startInduction(c *Chat) {
	i, g := c.Inducting, c.Group
	if i == nil || g == nil || i.Payload == nil || i.Sealing || i.Sealed != nil ||
		slices.ContainsFunc(c.Jobs, func(j *Job) bool { return j.Token != nil }) {
		return
	}
	who := wire.OfJoinReply(g.Reply(c.NextWrite), func(key []byte) (string, bool) {
		if member.Key(key) == g.Me() {
			return e.State.Me, true
		}
		return c.Names.Get(member.Key(key))
	})
	e.emit(DoSeal{c.ID, i.Voucher, i.Payload, who.Encode()})
	i.Sealing = true
	e.dirty(c)
}

// startUploads writes the next boxes of each upload, making its substream, reading its message
// back and deriving their indexes first.
func (e *Engine) startUploads(c *Chat) {
	for _, j := range c.Jobs {
		u := j.Upload
		key := jobKey{c.ID, j.ID}
		if u == nil || u.Sent >= u.Total || e.flight.uploading[key] {
			continue
		}
		if len(u.WriteCap) == 0 {
			e.flight.uploading[key] = true
			e.emit(DoSubstream{c.ID, j.ID})
			continue
		}
		blob, ok := e.flight.blobs[key]
		if !ok {
			if !e.flight.loading[key] {
				e.flight.loading[key] = true
				e.emit(DoLoad{c.ID, j.ID, u.File})
			}
			continue
		}
		want := min(Window, u.Total-u.Sent)
		ahead := e.flight.ahead[key]
		if len(ahead) < want {
			e.flight.uploading[key] = true
			e.emit(DoChunkIndexes{c.ID, j.ID, u.Next, min(2*Window, u.Total-u.Sent) - 1})
			continue
		}
		for i, index := range ahead[:want] {
			n := u.Sent + i
			if e.flight.chunksOut[key][n] || slices.ContainsFunc(e.flight.landed[key], func(l landed) bool { return l.n == n }) {
				continue
			}
			if e.flight.chunksOut[key] == nil {
				e.flight.chunksOut[key] = map[int]bool{}
			}
			e.flight.chunksOut[key][n] = true
			e.emit(DoWriteChunk{c.ID, j.ID, n, u.WriteCap, index, wire.SubstreamBox(blob, u.BoxSize, n)})
		}
	}
}

// startDownloads reads the next box of each download.
func (e *Engine) startDownloads(c *Chat) {
	for _, d := range c.Downloads {
		k := streamKey{c.ID, d.Stream}
		if e.flight.reading[k] {
			continue
		}
		at := member.Index(wire.StartOf(d.ReadCap))
		if f, ok := e.flight.fetched[k]; ok {
			at = f.at
		}
		e.flight.reading[k] = true
		e.emit(DoReadChunk{c.ID, d.Stream, d.ReadCap, at})
	}
}

// pump starts whatever can start.
func (e *Engine) pump() {
	for _, c := range e.State.Chats {
		e.startWrite(c)
		e.startReads(c)
		e.startInduction(c)
		e.startUploads(c)
		e.startDownloads(c)
	}
}

func (e *Engine) stopReading(chat ChatID, stream member.Key) {
	delete(e.flight.reading, streamKey{chat, stream})
}

func (e *Engine) missed(chat ChatID, stream member.Key) int {
	k := streamKey{chat, stream}
	n := e.flight.misses[k]
	e.flight.misses[k] = n + 1
	return n
}

func (e *Engine) hit(chat ChatID, stream member.Key) {
	delete(e.flight.misses, streamKey{chat, stream})
}

// followReader moves a cursor that a scan has carried past it.
func (e *Engine) followReader(c *Chat, stream member.Key) {
	if c.Group == nil {
		return
	}
	r, ok1 := c.Group.Readers.Get(stream)
	at, ok2 := c.Cursors.Get(stream)
	if ok1 && ok2 && wire.Counter([]byte(at)) < wire.Counter([]byte(r.Next)) {
		c.Cursors.Set(stream, r.Next)
		e.dirty(c)
	}
}

// Sanitize removes control characters from a name.
func Sanitize(name string) string {
	var out []rune
	for _, ch := range name {
		if !(ch < 0x20 || 0x7f <= ch && ch <= 0x9f) {
			out = append(out, ch)
		}
	}
	if len(out) == 0 {
		return "unnamed"
	}
	return string(out)
}

// finish ends a download: tell the member what came of it, in its place in the stream.
func (e *Engine) finish(c *Chat, d Download, blob []byte, got bool) {
	delete(e.flight.fetched, streamKey{c.ID, d.Stream})
	c.Downloads = slices.DeleteFunc(slices.Clone(c.Downloads), func(x Download) bool { return x.Stream == d.Stream })
	e.dirty(c)
	without := blob
	if got {
		if w, p, ok := wire.TakePayload(blob); ok {
			without = w
			e.flight.arriving = map[boxKey][]byte{{d.Stream, d.Index}: p}
		}
	}
	var m *wire.Message
	if got {
		m = wire.ToMessage(without)
	}
	if got && m != nil {
		e.remark(c, d.Stream, wire.Frame(without))
	} else {
		e.notice(c, NotFetched, label(c, d.Stream))
	}
	if c.Group != nil {
		e.effects(c, c.Group.Observe(d.Stream, d.Index, m, d.Next))
	}
	e.flight.arriving = map[boxKey][]byte{}
}

func readResult(o Outcome) (member.ReadResult, *member.Index) {
	next := o.Next
	switch o.Kind {
	case transport.NotFound:
		return member.ReadResult{Kind: member.ReadNotFound}, nil
	case transport.Tombstone:
		return member.ReadResult{Kind: member.ReadTombstone}, &next
	}
	return member.ReadResult{Kind: member.ReadData, Message: messageOf(o.Plaintext)}, &next
}

// voucherFile holds the voucher code we minted to join group, for the user to copy whole.
func voucherFile(group string) string { return "voucher-" + slug(group) + ".txt" }

// VoucherCode is how a voucher is handed to a member of the group.
func VoucherCode(voucher []byte) string { return base64.StdEncoding.EncodeToString(voucher) }

func (e *Engine) cancelHeld(c *Chat) {
	if c.Group != nil && c.Group.Ledger.Induction == member.Inducting {
		c.Group.CancelInduction()
	}
}

func (e *Engine) handle(in Input) {
	s := e.State
	chat := func(id ChatID) *Chat {
		c := s.Chat(id)
		if c != nil {
			e.dirty(c)
		}
		return c
	}
	switch in := in.(type) {
	case Create:
		if c := s.ChatNamed(in.Name); c != nil {
			e.notice(c, NameTaken, in.Name)
			return
		}
		c := &Chat{ID: in.Chat, Name: in.Name}
		s.Chats = append(s.Chats, c)
		e.dirty(c)
		e.emit(DoCreate{c.ID, false})
	case Join:
		if c := s.ChatNamed(in.Name); c != nil {
			e.notice(c, NameTakenJoining, in.Name)
			return
		}
		c := &Chat{ID: in.Chat, Name: in.Name, Joining: &Joining{}}
		s.Chats = append(s.Chats, c)
		e.dirty(c)
		e.emit(DoCreate{c.ID, true})
	case Created:
		c := chat(in.Chat)
		if c == nil {
			return
		}
		c.WriteCap, c.NextWrite = in.Keypair.WriteCap, member.Index(in.Keypair.First)
		if in.Joining {
			e.emit(DoMint{c.ID, c.WriteCap, s.Me})
			e.notice(c, Minting)
			return
		}
		c.Group = member.Found(in.Keypair.ReadCap, [][]byte{in.Keypair.ReadCap}, member.DefaultRetention(), 256)
		e.effects(c, c.Group.Handle(member.EpochChanged{Epoch: e.Epoch}))
		e.notice(c, NewGroup)
	case Minted:
		c := chat(in.Chat)
		if c == nil {
			return
		}
		code := VoucherCode(in.Minted.Voucher)
		e.emit(DoAwaitReply{c.ID, in.Minted.SecretKey, in.Minted.ReadCap, in.Box1, c.WriteCap})
		c.Joining = &Joining{Code: code, SecretKey: in.Minted.SecretKey, VoucherReadCap: in.Minted.ReadCap, Box1: in.Box1}
		e.keep(voucherFile(c.Name), []byte(code+"\n"))
		e.notice(c, VoucherMinted, code, c.Name, voucherFile(c.Name))
	case Opened:
		c := chat(in.Chat)
		if c == nil || c.Joining == nil || c.Joining.Code == "" || c.Group != nil {
			return
		}
		g, who := joinedFrom(in.Opened)
		if g == nil {
			c.Joining = nil
			e.notice(c, ReplyUnreadable)
			return
		}
		for _, p := range who.PleaseAdds {
			if p != nil {
				c.Names.Set(member.Key(wire.KeyOf(p.ReadCap)), Sanitize(p.Name))
			}
		}
		wc := in.Opened.MutatedWriteCap
		c.Group, c.WriteCap, c.NextWrite = g, wc, member.Index(wc[len(wc)-wire.IndexSize:])
		c.Joining, c.Cursors = nil, ordmap.Map[member.Key, member.Index]{}
		e.effects(c, g.Handle(member.EpochChanged{Epoch: e.Epoch}))
		e.notice(c, Joined)
	case Induct:
		c := chat(in.Chat)
		if c == nil {
			return
		}
		voucher, err := base64.StdEncoding.DecodeString(in.Code)
		switch {
		case c.Group == nil:
			e.notice(c, NotJoinedYet)
		case c.Inducting != nil && c.Inducting.Payload != nil:
			e.notice(c, AlreadyAdding)
		case err != nil:
			e.notice(c, NotAVoucher)
		default:
			c.Inducting = &Inducting{Voucher: voucher}
			e.emit(DoReadVoucher{c.ID, voucher})
			e.notice(c, ReadingVoucher)
		}
	case JoinerPayload:
		c := chat(in.Chat)
		if c == nil || c.Inducting == nil || c.Inducting.Payload != nil || !bytes.Equal(c.Inducting.Voucher, in.Voucher) {
			return
		}
		if c.Group != nil {
			e.enqueue(c, c.Group.BeginInduction(), nil, nil, nil)
		}
		c.Inducting = &Inducting{Voucher: in.Voucher, Payload: in.Payload, VoucherWriteCap: in.VoucherWriteCap, Box1: in.Box1}
	case SealedReply:
		c := chat(in.Chat)
		if c == nil || c.Inducting == nil {
			return
		}
		i := c.Inducting
		i.Sealing = false
		i.Sealed = &Sealed{Name: in.Inducted.Name, MutatedReadCap: in.Inducted.MutatedReadCap, Reply: in.Inducted.SealedReply}
		// The Introduction goes ahead of anything queued while the reply was sealing, so it is
		// the box at the index the reply names.
		if c.Group != nil {
			waiting := c.Jobs
			c.Jobs = nil
			e.enqueue(c, []member.Outgoing{c.Group.IntroduceNow(Sanitize(i.Sealed.Name), i.Sealed.MutatedReadCap)}, nil, nil, nil)
			c.Jobs = append(c.Jobs, waiting...)
			e.dirty(c)
		}
		e.emit(DoPublish{c.ID, i.VoucherWriteCap, i.Box1, i.Sealed.Reply})
	case Published:
		c := chat(in.Chat)
		if c == nil || c.Inducting == nil || c.Inducting.Sealed == nil {
			return
		}
		sealed := c.Inducting.Sealed
		who := Sanitize(sealed.Name)
		c.Inducting = nil
		c.Names.Set(member.Key(wire.KeyOf(sealed.MutatedReadCap)), who)
		e.notice(c, Added, who)
	case Send:
		c := chat(in.Chat)
		if c == nil {
			return
		}
		g := c.Group
		if g == nil {
			e.notice(c, NotJoined)
			return
		}
		content := wire.TextContent(g.Membership(nil), in.Text)
		id := e.say(c, Line{Sender: g.Me(), Text: in.Text, Status: Pending})
		e.enqueue(c, g.Compose(content), content, &id, nil)
	case SendFile:
		c := chat(in.Chat)
		if c == nil {
			return
		}
		g := c.Group
		switch {
		case g == nil:
			e.notice(c, NotJoined)
			return
		case len(in.Bytes) > wire.MaxFile:
			e.notice(c, FileTooLarge, SizeText(wire.MaxFile))
			return
		}
		safe := wire.SafeName(in.Name)
		f := wire.FileUpload{Payload: []byte{}, Filetype: wire.FiletypeOf(safe), Basename: safe}
		content := wire.FileContent(g.Membership(nil), f)
		a := &Attachment{Name: safe, Filetype: f.Filetype, Size: len(in.Bytes), File: attachmentFile(c, c.NextID, e.now, safe)}
		e.keep(a.File, in.Bytes)
		id := e.say(c, Line{Sender: g.Me(), Text: fileText(a), Status: Pending, Attachment: a})
		e.enqueue(c, g.Compose(content), content, &id, in.Bytes)
	case Loaded:
		key := jobKey{in.Chat, in.Job}
		delete(e.flight.loading, key)
		c := chat(in.Chat)
		if c == nil {
			return
		}
		j := c.job(in.Job)
		if j == nil {
			return
		}
		if !in.Lost {
			e.flight.blobs[key] = in.Bytes
			return
		}
		if j.Token != nil && c.Group != nil {
			c.Group.Abandoned(*j.Token)
		}
		c.Jobs = slices.DeleteFunc(slices.Clone(c.Jobs), func(x *Job) bool { return x.ID == in.Job })
		e.notice(c, SendLost)
	case Substream:
		delete(e.flight.uploading, jobKey{in.Chat, in.Job})
		if c := chat(in.Chat); c != nil {
			if j := c.job(in.Job); j != nil && j.Upload != nil {
				j.Upload.WriteCap, j.Upload.Next = in.Keypair.WriteCap, member.Index(in.Keypair.First)
			}
		}
	case ChunkIndexes:
		key := jobKey{in.Chat, in.Job}
		delete(e.flight.uploading, key)
		if c := s.Chat(in.Chat); c != nil {
			if j := c.job(in.Job); j != nil && j.Upload != nil && j.Upload.Next == in.Start {
				e.flight.ahead[key] = append([]member.Index{in.Start}, in.Indexes...)
			}
		}
	case WroteChunk:
		e.wroteChunk(in)
	case ReadChunk:
		e.readChunk(in)
	case Wrote:
		delete(e.flight.writing, in.Chat)
		c := chat(in.Chat)
		if c == nil {
			return
		}
		j := c.job(in.Job)
		if j == nil {
			return
		}
		c.Jobs = slices.DeleteFunc(slices.Clone(c.Jobs), func(x *Job) bool { return x.ID == in.Job })
		if j.Token != nil && c.Group != nil {
			c.Group.Written(*j.Token, in.Index, &member.Payload{Bytes: j.Box})
			c.NextWrite = in.Next
		}
		if j.Line != nil {
			for _, l := range c.Log {
				if l.ID == *j.Line {
					n := wire.Counter([]byte(in.Index))
					l.Status, l.Idx64 = Sent, &n
					e.lineChanged(c, l.ID)
				}
			}
		}
	case Refused:
		// The chat's writes stop here: the job stays first, and nothing writes after it.
		if c := chat(in.Chat); c != nil {
			e.notice(c, Desync)
		}
	case Read:
		e.read(in)
	case Wake:
		e.stopReading(in.Chat, in.Stream)
	case Scan:
		c := chat(in.Chat)
		if c == nil || c.Group == nil {
			return
		}
		for _, stream := range c.Group.Readers.Keys() {
			e.effects(c, c.Group.Handle(member.Scan{Stream: stream}))
		}
		e.notice(c, Scanning)
	case Leave:
		c := s.Chat(in.Chat)
		if c == nil {
			return
		}
		for _, f := range c.Files() {
			e.emit(DoDelete{f})
		}
		s.Chats = slices.DeleteFunc(slices.Clone(s.Chats), func(x *Chat) bool { return x.ID == in.Chat })
		e.flight.forget(in.Chat)
		delete(e.out.Changes.Chats, in.Chat)
		delete(e.out.Changes.Lines, in.Chat)
		delete(e.out.Changes.Dropped, in.Chat)
		e.out.Changes.Removed[in.Chat] = true
	case RemoveMember:
		c := chat(in.Chat)
		if c == nil {
			return
		}
		if c.Group == nil || !c.Group.Readers.Has(in.Who) {
			e.notice(c, NoLongerMember)
			return
		}
		l := label(c, in.Who)
		c.Group.Remove(in.Who)
		e.stopReading(c.ID, in.Who)
		e.hit(c.ID, in.Who)
		delete(e.flight.fetched, streamKey{c.ID, in.Who})
		e.dropLines(c, func(x *Line) bool { return x.Sender != in.Who })
		c.Cursors.Delete(in.Who)
		c.Downloads = slices.DeleteFunc(slices.Clone(c.Downloads), func(d Download) bool { return d.Stream == in.Who })
		e.notice(c, StoppedReading, l)
	case Clear:
		if c := chat(in.Chat); c != nil {
			e.dropLines(c, func(*Line) bool { return false })
		}
	case Rename:
		c := chat(in.Chat)
		if c == nil || in.To == "" || in.To == c.Name {
			return
		}
		if s.ChatNamed(in.To) != nil {
			e.notice(c, NameTaken, in.To)
			return
		}
		old := c.Name
		c.Name = in.To
		e.notice(c, Renamed, old)
	case ScanRead:
		c := chat(in.Chat)
		if c == nil || c.Group == nil {
			return
		}
		res, next := readResult(in.Outcome)
		e.effects(c, c.Group.Handle(member.BoxRead{Stream: in.Stream, Index: in.Index, Result: res, Next: next}))
		e.followReader(c, in.Stream)
	case Walked:
		c := chat(in.Chat)
		if c == nil || c.Group == nil {
			return
		}
		e.effects(c, c.Group.Handle(member.Walked{Stream: in.Stream, Target: in.Target, Skipped: in.Skipped, Steps: in.Steps}))
		e.followReader(c, in.Stream)
	case Derived:
		c := chat(in.Chat)
		if c == nil || c.Group == nil {
			return
		}
		e.effects(c, c.Group.Handle(member.IndexesDerived{Stream: in.Stream, Indexes: in.Indexes}))
	case Epoch:
		e.Epoch = max(e.Epoch, in.N)
		for _, c := range s.Chats {
			if c.Group == nil || c.Group.Epoch >= in.N {
				continue
			}
			e.dirty(c)
			e.effects(c, c.Group.Handle(member.EpochChanged{Epoch: in.N}))
		}
	case Failed:
		c := chat(in.Chat)
		if c == nil {
			return
		}
		// A chat still joining stays so, and joins on when resumed.
		e.cancelHeld(c)
		c.Inducting = nil
		e.notice(c, ActionFailed, in.What)
	}
}

// joinedFrom is the group a reply to our voucher puts us in.
func joinedFrom(o transport.Opened) (*member.Group, *wire.ReplyWho) {
	who := wire.DecodeReplyWho(o.WhoReply)
	if who == nil || len(o.MutatedWriteCap) < wire.KeySize {
		return nil, nil
	}
	reply := who.ToJoinReply()
	if reply == nil {
		reply = who.WithoutRosters()
	}
	if reply == nil {
		return nil, nil
	}
	own := o.MutatedWriteCap[wire.KeySize:]
	for _, m := range reply.Members {
		if m != nil && bytes.Equal(wire.KeyOf(m.ReadCap), wire.KeyOf(own)) {
			return nil, nil
		}
	}
	return member.Joined(own, reply, member.DefaultRetention(), 256), who
}

func (e *Engine) wroteChunk(in WroteChunk) {
	key := jobKey{in.Chat, in.Job}
	delete(e.flight.chunksOut[key], in.N)
	c := e.State.Chat(in.Chat)
	if c == nil {
		return
	}
	j := c.job(in.Job)
	if j == nil || j.Upload == nil || in.N < j.Upload.Sent {
		return
	}
	u := j.Upload
	e.flight.landed[key] = append(e.flight.landed[key], landed{in.N, in.Next})
	// Count the boxes written in a row from the first not yet counted.
	for {
		i := slices.IndexFunc(e.flight.landed[key], func(l landed) bool { return l.n == u.Sent })
		if i < 0 {
			break
		}
		after := e.flight.landed[key][i].after
		e.flight.landed[key] = slices.Delete(e.flight.landed[key], i, i+1)
		if a := e.flight.ahead[key]; len(a) > 0 {
			e.flight.ahead[key] = a[1:]
		}
		u.Sent++
		u.Next = after
	}
	e.dirty(c)
	if u.Sent < u.Total {
		return
	}
	delete(e.flight.blobs, key)
	delete(e.flight.ahead, key)
	delete(e.flight.landed, key)
	e.emit(DoDelete{u.File})
	j.Box = wire.Indirection(u.Total, u.WriteCap[wire.KeySize:])
}

func (e *Engine) readChunk(in ReadChunk) {
	e.stopReading(in.Chat, in.Stream)
	c := e.State.Chat(in.Chat)
	if c == nil {
		return
	}
	di := slices.IndexFunc(c.Downloads, func(d Download) bool { return d.Stream == in.Stream })
	if di < 0 {
		return
	}
	d := c.Downloads[di]
	k := streamKey{in.Chat, in.Stream}
	f, ok := e.flight.fetched[k]
	if !ok {
		f = fetched{at: member.Index(wire.StartOf(d.ReadCap))}
	}
	if f.at != in.Index {
		return
	}
	switch in.Outcome.Kind {
	case transport.NotFound:
		e.flight.reading[k] = true
		e.emit(DoWake{in.Chat, in.Stream, Backoff(e.missed(in.Chat, in.Stream))})
		return
	case transport.Tombstone:
		e.finish(c, d, nil, false)
		return
	}
	e.hit(in.Chat, in.Stream)
	box := in.Outcome.Plaintext
	parts := append(slices.Clone(f.parts), box)
	var tag byte
	if len(box) > 0 {
		tag = box[0]
	}
	switch {
	case tag == 'F':
		blob, ok := wire.Assemble(parts)
		e.finish(c, d, blob, ok)
	case tag == 'C' && len(parts) < wire.MaxChunks(e.MaxPlaintext) && (d.Total == nil || len(parts) < *d.Total):
		e.flight.fetched[k] = fetched{at: in.Outcome.Next, parts: parts}
	default:
		e.finish(c, d, nil, false)
	}
}

func (e *Engine) read(in Read) {
	e.stopReading(in.Chat, in.Stream)
	c := e.State.Chat(in.Chat)
	if c == nil {
		return
	}
	if at, ok := c.Cursors.Get(in.Stream); !ok || at != in.Index {
		return
	}
	switch in.Outcome.Kind {
	case transport.NotFound:
		e.flight.reading[streamKey{in.Chat, in.Stream}] = true
		e.emit(DoWake{in.Chat, in.Stream, Backoff(e.missed(in.Chat, in.Stream))})
		return
	case transport.Tombstone:
		e.hit(in.Chat, in.Stream)
		c.Cursors.Set(in.Stream, in.Outcome.Next)
		e.dirty(c)
		return
	}
	e.hit(in.Chat, in.Stream)
	e.dirty(c)
	plaintext, next := in.Outcome.Plaintext, in.Outcome.Next
	if ch := wire.Unframe(plaintext); ch.Kind == wire.ChunkIndirection {
		total := 0
		var t *int
		if ch.Total != nil {
			total = int(*ch.Total)
			t = &total
		}
		if total <= wire.MaxChunks(e.MaxPlaintext) {
			c.Downloads = append(c.Downloads, Download{Stream: in.Stream, Index: in.Index, Next: next, ReadCap: ch.Data, Total: t})
			c.Cursors.Set(in.Stream, next)
			return
		}
		e.notice(c, FileTooLargeToFetch, label(c, in.Stream))
		if c.Group != nil {
			e.effects(c, c.Group.Observe(in.Stream, in.Index, nil, next))
		}
		c.Cursors.Set(in.Stream, next)
		return
	}
	e.remark(c, in.Stream, plaintext)
	if c.Group != nil {
		e.effects(c, c.Group.Observe(in.Stream, in.Index, messageOf(plaintext), next))
	}
	c.Cursors.Set(in.Stream, next)
}

// Step takes one input at time now, in milliseconds since the Unix epoch.
func (e *Engine) Step(now int64, in Input) Result {
	e.begin(now)
	e.handle(in)
	e.pump()
	return e.out
}

// Resume begins again after a restart: whatever was under way is started afresh.
func (e *Engine) Resume(now int64) Result {
	e.begin(now)
	for _, c := range e.State.Chats {
		if len(c.WriteCap) == 0 {
			e.emit(DoCreate{c.ID, c.Joining != nil})
			continue
		}
		if j := c.Joining; j != nil {
			if j.Code == "" {
				e.emit(DoMint{c.ID, c.WriteCap, e.State.Me})
			} else {
				e.emit(DoAwaitReply{c.ID, j.SecretKey, j.VoucherReadCap, j.Box1, c.WriteCap})
			}
		}
		if i := c.Inducting; i != nil {
			if i.Payload == nil {
				e.emit(DoReadVoucher{c.ID, i.Voucher})
			} else if i.Sealed != nil {
				e.emit(DoPublish{c.ID, i.VoucherWriteCap, i.Box1, i.Sealed.Reply})
			} else if i.Sealing {
				// The sealed reply was never kept, so it was never published: seal it again.
				i.Sealing = false
				e.dirty(c)
			}
		}
	}
	e.pump()
	return e.out
}
