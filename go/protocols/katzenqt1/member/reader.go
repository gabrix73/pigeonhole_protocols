package member

import (
	"slices"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

// A reader reads one member's stream in order, one box at a time. A scan rechecks boxes
// previously stepped past and may jump ahead to a box another member acknowledged, keeping the
// boxes it skips. A reader acknowledges the end of the unbroken run it has read (run).

type Mode int

const (
	Idle Mode = iota
	Reading
	Scanning
)

// Kept is a box a scan stepped past without reading: with the count it was passed at and the
// box before it.
type Kept struct {
	Index  Index
	Passed int
	Before *Index
}

// Lost is the first box passed unread and no longer kept; acknowledgements stop before it.
type Lost struct {
	Passed int
	Before *Index
}

type Reader struct {
	Stream  Key
	ReadCap []byte
	// Next is the index of the next box to read.
	Next Index
	// Last is the last box read in order, data or tombstone.
	Last *Index
	// Passed is how many boxes this reader has passed.
	Passed int
	// Kept holds boxes a scan stepped past, oldest first.
	Kept []Kept
	Lost *Lost
	Mode Mode
	// Tried is the Idx64 of each acknowledged box ahead that a scan has already looked for, while
	// it is still heard: no more than there are members.
	Tried []uint64
}

func (r *Reader) readBox(i Index, recheck bool) Effect {
	return ReadBox{Stream: r.Stream, ReadCap: r.ReadCap, Index: i, Recheck: recheck}
}

func (r *Reader) read() []Effect {
	if r.Mode != Idle {
		return nil
	}
	r.Mode = Reading
	return []Effect{r.readBox(r.Next, false)}
}

// ahead is the acknowledged boxes ahead of here a scan has not looked for yet, each once. A walk
// only goes forward, so one behind is never found.
func (r *Reader) ahead(heard []uint64) []uint64 {
	var out []uint64
	here := counter(r.Next)
	for _, h := range heard {
		if h > here && !slices.Contains(r.Tried, h) && !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return out
}

// prune keeps what a scan still needs to remember having looked for: boxes ahead that are still
// heard.
func (r *Reader) prune(heard []uint64) {
	here := counter(r.Next)
	r.Tried = slices.DeleteFunc(r.Tried, func(t uint64) bool { return t <= here || !slices.Contains(heard, t) })
}

func (r *Reader) rechecks() []Effect {
	es := make([]Effect, 0, len(r.Kept)+1)
	for _, k := range r.Kept {
		es = append(es, r.readBox(k.Index, true))
	}
	return es
}

// scan rechecks what was kept, then looks for acknowledged boxes ahead, or probes forward from
// here.
func (r *Reader) scan(heard []uint64, window int) []Effect {
	r.prune(heard)
	ahead := r.ahead(heard)
	es := r.rechecks()
	r.Mode = Scanning
	if len(ahead) == 0 {
		return append(es, r.readBox(r.Next, false))
	}
	r.Tried = append(r.Tried, ahead...)
	return append(es, Walk{Stream: r.Stream, Start: r.Next, Targets: ahead, Keep: window})
}

// run is the end of the unbroken run read: how far this stream may be acknowledged.
func (r *Reader) run() *Index {
	type gap struct {
		passed int
		before *Index
	}
	var gs []gap
	for _, k := range r.Kept {
		gs = append(gs, gap{k.Passed, k.Before})
	}
	if r.Lost != nil {
		gs = append(gs, gap{r.Lost.Passed, r.Lost.Before})
	}
	if len(gs) == 0 {
		return r.Last
	}
	m := gs[0]
	for _, g := range gs[1:] {
		if g.passed < m.passed {
			m = g
		}
	}
	return m.before
}

func (r *Reader) lose(at int, before *Index) {
	if r.Lost == nil || at < r.Lost.Passed {
		r.Lost = &Lost{at, before}
	}
}

// forget drops kept boxes more than window behind, as lost.
func (r *Reader) forget(window int) {
	kept := r.Kept[:0:0]
	for _, k := range r.Kept {
		if k.Passed+window < r.Passed {
			r.lose(k.Passed, k.Before)
		} else {
			kept = append(kept, k)
		}
	}
	r.Kept = kept
}

// jump goes to t past steps boxes, keeping the last skipped of them; any before those are given
// up on.
func (r *Reader) jump(t Index, skipped []Index, steps int) {
	start := r.Passed + steps - len(skipped)
	if start > r.Passed {
		r.lose(r.Passed, r.Last)
	}
	before := r.Last
	for n, i := range skipped {
		r.Kept = append(r.Kept, Kept{Index: i, Passed: start + n, Before: before})
		i := i
		before = &i
	}
	r.Passed += steps
	r.Next = t
}

// walked takes the result of a walk: jump to target, keeping the boxes passed.
func (r *Reader) walked(target *Index, skipped []Index, steps, window int) []Effect {
	if target == nil {
		return []Effect{r.readBox(r.Next, false)}
	}
	r.jump(*target, skipped, steps)
	r.forget(window)
	return []Effect{r.readBox(*target, false)}
}

func messageOf(res ReadResult) *wire.Message {
	if res.Kind == ReadData {
		return res.Message
	}
	return nil
}

// found takes one box read: its message if it is new data to ingest, and what to read next.
func (r *Reader) found(index Index, res ReadResult, next *Index, window int) (*wire.Message, []Effect) {
	for n, k := range r.Kept {
		if k.Index == index {
			if res.Kind == ReadNotFound {
				return nil, nil
			}
			r.Kept = slices.Delete(slices.Clone(r.Kept), n, n+1)
			return messageOf(res), nil
		}
	}
	if index != r.Next || r.Mode == Idle {
		return nil, nil
	}
	if res.Kind == ReadNotFound || next == nil {
		r.Mode = Idle
		return nil, nil
	}
	i := index
	r.Last = &i
	r.Next = *next
	r.Passed++
	r.forget(window)
	return messageOf(res), []Effect{r.readBox(*next, false)}
}
