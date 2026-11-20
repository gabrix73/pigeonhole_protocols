// Package stream carries one message of any size over a Pigeonhole stream, as Rust's
// protocols::stream does: each box holds a flags byte, bit 0 set on the last box, then up to a
// box less one of the message. A service sends a reply larger than a box by publishing it to a
// new stream and sending the read cap over its session; the client fetches it from the read cap.
// Both sides hold only a window of boxes at once.
package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

const end = 1

// MaxMessage is the largest message Fetch should take unless the caller knows better.
const MaxMessage = 500 << 20

var (
	// ErrTooLarge reports a message longer than Fetch's limit.
	ErrTooLarge = errors.New("stream: message over the limit")
	// ErrNotStreamBox reports a box without a valid flags byte.
	ErrNotStreamBox = errors.New("stream: not a stream box")
)

// Tuning sets how many boxes are written or read ahead at once, and how often a box not yet
// written is polled for.
type Tuning struct {
	Window int
	Poll   time.Duration
}

// Mixnet is the tuning for the mixnet, where a box takes tens of seconds; nil means it.
var Mixnet = &Tuning{Window: 8, Poll: common.DefaultPollInterval}

// Encode makes a box: the flags byte, then the data.
func Encode(data []byte, last bool) []byte {
	f := byte(0)
	if last {
		f = end
	}
	return append([]byte{f}, data...)
}

// Decode returns the data a box holds and whether the message ends with it.
func Decode(box []byte) ([]byte, bool, error) {
	if len(box) == 0 || box[0]&^end != 0 {
		return nil, false, ErrNotStreamBox
	}
	return box[1:], box[0]&end != 0, nil
}

// Publish writes all of r to a new stream, its end box last, and returns the stream's read cap,
// which holds its first index. Send it, as ReadCap.MarshalBinary, over the session.
func Publish(ctx context.Context, ph common.Pigeonhole, r io.Reader, t *Tuning) (*bacap.ReadCap, error) {
	wc, rc, idx, err := ph.NewStream()
	if err != nil {
		return nil, err
	}
	if _, err := Write(ctx, ph, wc, idx, r, t); err != nil {
		return nil, err
	}
	return rc, nil
}

// Write writes all of r from idx on, its end box last, and returns the index after the end box.
func Write(ctx context.Context, ph common.Pigeonhole, wc *bacap.WriteCap, idx *bacap.MessageBoxIndex, r io.Reader, t *Tuning) (*bacap.MessageBoxIndex, error) {
	if t == nil {
		t = Mixnet
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(t.Window)
	buf := make([]byte, ph.MaxPlaintext()-1)
	for gctx.Err() == nil {
		n, err := io.ReadFull(r, buf)
		last := err == io.EOF || err == io.ErrUnexpectedEOF
		if err != nil && !last {
			g.Wait()
			return nil, fmt.Errorf("stream: input: %w", err)
		}
		box, i := Encode(buf[:n], last), idx
		g.Go(func() error {
			_, err := common.WriteRetry(gctx, ph, wc, i, box)
			return err
		})
		if idx, err = idx.NextIndex(); err != nil {
			g.Wait()
			return nil, err
		}
		if last {
			break
		}
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return idx, ctx.Err()
}

// Fetch reads the message at rc's first index into w, box by box, to its end box. A box not yet
// written is polled for until ctx ends; a tombstone fails, and more than limit bytes is
// ErrTooLarge, with no more than limit written to w.
func Fetch(ctx context.Context, ph common.Pigeonhole, rc *bacap.ReadCap, w io.Writer, limit int64, t *Tuning) error {
	if t == nil {
		t = Mixnet
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type read struct {
		box []byte
		err error
	}
	// The reads of the next Window boxes, in index order.
	var ahead []chan read
	idx := rc.GetMessageBoxIndex()
	start := func() error {
		ch, i := make(chan read, 1), idx
		go func() {
			box, _, err := common.ReadWait(ctx, ph, rc, i, t.Poll)
			ch <- read{box, err}
		}()
		ahead = append(ahead, ch)
		var err error
		idx, err = idx.NextIndex()
		return err
	}
	var total int64
	for {
		for len(ahead) < t.Window {
			if err := start(); err != nil {
				return err
			}
		}
		r := <-ahead[0]
		ahead = ahead[1:]
		if r.err != nil {
			return r.err
		}
		data, last, err := Decode(r.box)
		if err != nil {
			return err
		}
		if total += int64(len(data)); total > limit {
			return ErrTooLarge
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
		if last {
			return nil
		}
	}
}
