// Package client is a katzenqt1 group chat client: the engine, its state on disk, and its work
// carried out over a transport.
package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
	"github.com/katzenpost/pigeonhole_protocols/go/transport"
)

// RetryMs is how long to wait before trying a failed write or read again.
const RetryMs = 5000

// Files are the files kept under the state directory.
type Files interface {
	Read(name string) ([]byte, error)
	Remove(name string) error
}

// Outcome is what came of an action: an input for the engine now, the action to try again
// later, or an input to hand the engine later.
type Outcome struct {
	Input engine.Input
	Retry engine.Action
	After int
}

func done(in engine.Input) Outcome { return Outcome{Input: in} }

func retry(a engine.Action) Outcome { return Outcome{Retry: a, After: RetryMs} }

// Executor carries out the engine's actions. Sleep waits between attempts of a write that must
// succeed before the action can go on.
type Executor struct {
	Backend transport.Backend
	Files   Files
	Sleep   func(ctx context.Context, ms int) error
}

func next(i member.Index) member.Index {
	n, err := member.NextIndex(i)
	if err != nil {
		panic(err)
	}
	return n
}

func outcome(r transport.Read, index member.Index) engine.Outcome {
	o := engine.Outcome{Kind: r.Kind, Plaintext: r.Plaintext}
	if r.Kind != transport.NotFound {
		o.Next = next(index)
	}
	return o
}

// publish writes a box until it is written.
func (x *Executor) publish(ctx context.Context, writeCap []byte, index member.Index, box []byte) error {
	for {
		err := x.Backend.WriteBox(ctx, writeCap, []byte(index), box)
		if err == nil || errors.Is(err, transport.ErrBoxAlreadyExists) || ctx.Err() != nil {
			return err
		}
		if err := x.Sleep(ctx, RetryMs); err != nil {
			return err
		}
	}
}

func describe(a engine.Action) string {
	switch a := a.(type) {
	case engine.DoCreate:
		return "new stream"
	case engine.DoMint:
		return "mint a voucher"
	case engine.DoAwaitReply:
		return "wait for the voucher's reply"
	case engine.DoReadVoucher:
		return "read a voucher's box 0"
	case engine.DoSeal:
		return "seal the reply to a voucher"
	case engine.DoPublish:
		return "publish the reply to a voucher"
	default:
		return fmt.Sprintf("%T", a)
	}
}

func chatOf(a engine.Action) engine.ChatID {
	switch a := a.(type) {
	case engine.DoCreate:
		return a.Chat
	case engine.DoMint:
		return a.Chat
	case engine.DoAwaitReply:
		return a.Chat
	case engine.DoReadVoucher:
		return a.Chat
	case engine.DoSeal:
		return a.Chat
	case engine.DoPublish:
		return a.Chat
	}
	return ""
}

// Perform carries out one action. It never waits to try again; the caller does.
func (x *Executor) Perform(ctx context.Context, a engine.Action) Outcome {
	o, err := x.perform(ctx, a)
	if err == nil {
		return o
	}
	switch a := a.(type) {
	case engine.DoRead, engine.DoScanRead, engine.DoReadChunk, engine.DoSubstream, engine.DoChunkIndexes,
		engine.DoWrite, engine.DoWriteChunk, engine.DoDerive, engine.DoWalk:
		return retry(a)
	case engine.DoDelete:
		return Outcome{}
	case engine.DoAwaitReply:
		// Waited for again, after a while; the engine says so.
		return done(engine.ReplyFailed{Chat: a.Chat, Box1: a.Box1, What: fmt.Sprintf("%s failed: %v", describe(a), err)})
	}
	return done(engine.Failed{Chat: chatOf(a), What: fmt.Sprintf("%s failed: %v", describe(a), err)})
}

func (x *Executor) perform(ctx context.Context, a engine.Action) (Outcome, error) {
	b := x.Backend
	switch a := a.(type) {
	case engine.DoCreate:
		kp, err := b.NewKeypair(ctx)
		return done(engine.Created{Chat: a.Chat, Joining: a.Joining, Keypair: kp}), err
	case engine.DoWrite:
		err := b.WriteBox(ctx, a.WriteCap, []byte(a.Index), a.Box)
		if errors.Is(err, transport.ErrBoxAlreadyExists) {
			return done(engine.Refused{Chat: a.Chat, Job: a.Job}), nil
		}
		return done(engine.Wrote{Chat: a.Chat, Job: a.Job, Index: a.Index, Next: next(a.Index)}), err
	case engine.DoRead:
		r, err := b.ReadBox(ctx, a.ReadCap, []byte(a.Index))
		return done(engine.Read{Chat: a.Chat, Stream: a.Stream, Index: a.Index, Outcome: outcome(r, a.Index)}), err
	case engine.DoWake:
		return Outcome{Input: engine.Wake{Chat: a.Chat, Stream: a.Stream}, After: a.Ms}, nil
	case engine.DoTick:
		return Outcome{Input: engine.Tick{Chat: a.Chat, N: a.N}, After: a.Ms}, nil
	case engine.DoScanRead:
		r, err := b.ReadBox(ctx, a.ReadCap, []byte(a.Index))
		return done(engine.ScanRead{Chat: a.Chat, Stream: a.Stream, Index: a.Index, Outcome: outcome(r, a.Index)}), err
	case engine.DoWalk:
		target, skipped, steps, err := member.WalkWith(member.NextIndex, a.Start, a.Targets, a.Keep)
		return done(engine.Walked{Chat: a.Chat, Stream: a.Stream, Target: target, Skipped: skipped, Steps: steps}), err
	case engine.DoDerive:
		is, err := member.DeriveWith(member.NextIndex, a.Start, a.Count)
		return done(engine.Derived{Chat: a.Chat, Stream: a.Stream, Indexes: is}), err
	case engine.DoMint:
		m, err := b.VoucherMint(ctx, a.WriteCap, a.Name, a.Form)
		if err != nil {
			return Outcome{}, err
		}
		box0 := member.Index(m.WriteCap[len(m.WriteCap)-wire.IndexSize:])
		if err := x.publish(ctx, m.WriteCap, box0, m.Payload); err != nil {
			return Outcome{}, err
		}
		return done(engine.Minted{Chat: a.Chat, Minted: m, Box1: next(box0)}), nil
	case engine.DoAwaitReply:
		// A read that fails is tried again, as a box not yet written is: the reply may come at
		// any time, and only reading it lets the joiner in. A version 2 reply is framed over
		// boxes 1 on, C pieces then an F piece; version 1 is box 1 alone, unframed.
		var sealed []byte
		index := a.Box1
		for {
			r, err := b.ReadBox(ctx, a.VoucherReadCap, []byte(index))
			switch {
			case err != nil || r.Kind == transport.NotFound:
				return retry(a), nil
			case r.Kind == transport.Tombstone:
				return Outcome{}, errors.New("the voucher's reply was withdrawn")
			}
			if a.Version < 2 {
				sealed = r.Plaintext
				break
			}
			if len(r.Plaintext) == 0 || (r.Plaintext[0] != 'C' && r.Plaintext[0] != 'F') {
				return Outcome{}, errors.New("the voucher's reply is not framed")
			}
			sealed = append(sealed, r.Plaintext[1:]...)
			if r.Plaintext[0] == 'F' {
				break
			}
			next, err := member.NextIndex(index)
			if err != nil {
				return Outcome{}, err
			}
			index = next
		}
		o, err := b.VoucherOpen(ctx, a.SecretKey, sealed, a.WriteCap)
		if err != nil {
			return Outcome{}, err
		}
		return done(engine.Opened{Chat: a.Chat, Opened: o}), nil
	case engine.DoReadVoucher:
		wc, rc, err := b.VoucherDeriveStream(ctx, a.Voucher)
		if err != nil {
			return retry(a), nil
		}
		box0 := member.Index(wire.StartOf(rc))
		r, err := b.ReadBox(ctx, rc, []byte(box0))
		switch {
		case err != nil || r.Kind == transport.NotFound:
			return retry(a), nil
		case r.Kind == transport.Tombstone:
			return done(engine.Failed{Chat: a.Chat, What: "that voucher was withdrawn"}), nil
		}
		return done(engine.JoinerPayload{Chat: a.Chat, Voucher: a.Voucher, VoucherWriteCap: wc, Payload: r.Plaintext, Box1: next(box0)}), nil
	case engine.DoSeal:
		i, err := b.VoucherInduct(ctx, a.Voucher, a.Payload, a.WhoReply)
		return done(engine.SealedReply{Chat: a.Chat, Inducted: i}), err
	case engine.DoPublish:
		if a.Version < 2 {
			if err := x.publish(ctx, a.VoucherWriteCap, a.Box1, a.Reply); err != nil {
				return Outcome{}, err
			}
			return done(engine.Published{Chat: a.Chat}), nil
		}
		size, err := b.MaxPlaintext(ctx)
		if err != nil {
			return Outcome{}, err
		}
		piece := max(1, size-1)
		index := a.Box1
		for n, rest := 0, a.Reply; ; n++ {
			tag, chunk := byte('C'), rest
			if len(rest) <= piece {
				tag, chunk = 'F', rest
			} else {
				chunk = rest[:piece]
			}
			rest = rest[len(chunk):]
			err := x.publish(ctx, a.VoucherWriteCap, index, append([]byte{tag}, chunk...))
			if err != nil && !(errors.Is(err, transport.ErrBoxAlreadyExists) && n > 0) {
				// A piece written before a restart is fine; box 1 taken by another's reply is not.
				return Outcome{}, err
			}
			if tag == 'F' {
				break
			}
			if index, err = member.NextIndex(index); err != nil {
				return Outcome{}, err
			}
		}
		return done(engine.Published{Chat: a.Chat}), nil
	case engine.DoDelete:
		return Outcome{}, x.Files.Remove(a.File)
	case engine.DoLoad:
		bs, err := x.Files.Read(a.File)
		return done(engine.Loaded{Chat: a.Chat, Job: a.Job, Bytes: bs, Lost: err != nil}), nil
	case engine.DoSubstream:
		kp, err := b.NewKeypair(ctx)
		return done(engine.Substream{Chat: a.Chat, Job: a.Job, Keypair: kp}), err
	case engine.DoWriteChunk:
		err := b.WriteBox(ctx, a.WriteCap, []byte(a.Index), a.Box)
		if errors.Is(err, transport.ErrBoxAlreadyExists) {
			return done(engine.Refused{Chat: a.Chat, Job: a.Job}), nil
		}
		if err != nil {
			return Outcome{}, err
		}
		return done(engine.WroteChunk{Chat: a.Chat, Job: a.Job, N: a.N, Next: next(a.Index)}), nil
	case engine.DoChunkIndexes:
		is, err := member.DeriveWith(member.NextIndex, a.Start, a.Count)
		return done(engine.ChunkIndexes{Chat: a.Chat, Job: a.Job, Start: a.Start, Indexes: is}), err
	case engine.DoReadChunk:
		r, err := b.ReadBox(ctx, a.ReadCap, []byte(a.Index))
		return done(engine.ReadChunk{Chat: a.Chat, Stream: a.Stream, Index: a.Index, Outcome: outcome(r, a.Index)}), err
	}
	return Outcome{}, fmt.Errorf("unknown action %T", a)
}
