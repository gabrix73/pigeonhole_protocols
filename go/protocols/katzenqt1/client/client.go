package client

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/store"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
	"github.com/katzenpost/pigeonhole_protocols/go/transport"
)

var (
	ErrClosed        = errors.New("client: closed")
	ErrNameTaken     = errors.New("client: a group already has that name")
	ErrEmptyName     = errors.New("client: a group needs a name")
	ErrNoSuchChat    = errors.New("client: no such group")
	ErrNotJoined     = errors.New("client: the group has not been joined yet")
	ErrAlreadyAdding = errors.New("client: already adding a member")
	ErrNotAVoucher   = errors.New("client: not a voucher code")
	ErrNoSuchMember  = errors.New("client: no such member")
	ErrRemoveSelf    = errors.New("client: we cannot remove ourselves")
	ErrFileTooLarge  = errors.New("client: file too large to send")
	ErrEmptyMessage  = errors.New("client: nothing to send")
)

type Config struct {
	// StateDir holds the state and the files it names.
	StateDir string
	// Name is our display name, when the state has none yet.
	Name    string
	Backend transport.Backend
	// EpochPoll is how often the replicas' epoch is asked for; a minute by default.
	EpochPoll time.Duration
	// NoSync is for tests only: see store.Options.
	NoSync bool
	// WireVersion is the wire version written and minted: 3 the map form and form 1
	// vouchers, 4 the array form and form 2 vouchers; 4 when zero. Both are read, and a
	// voucher is answered in its own form.
	WireVersion uint64
}

// Event says what changed; an app asks for what it shows with Chats and Lines.
type Event struct {
	Chat engine.ChatID
	// Removed says the group is gone.
	Removed bool
	// Lines are the lines added or changed.
	Lines []int
	// Dropped are the lines deleted.
	Dropped []int
	// Err, when set, says the client stopped.
	Err error
}

type request struct {
	in    engine.Input
	check func(*engine.State) error
	query func(*engine.State)
	done  chan error
}

// Client is a katzenqt1 group chat client. Its methods may be called from any goroutine.
type Client struct {
	cfg    Config
	st     *store.Store
	eng    *engine.Engine
	exec   *Executor
	inbox  chan request
	ctx    context.Context
	cancel context.CancelFunc
	work   sync.WaitGroup
	loop   sync.WaitGroup

	mu     sync.Mutex
	subs   []*subscriber
	err    error
	closed bool
}

// subscriber hands events on in order, however slowly they are read, so that the engine never
// waits on an app.
type subscriber struct {
	mu     sync.Mutex
	queue  []Event
	wake   chan struct{}
	out    chan Event
	closed bool
}

func newSubscriber() *subscriber {
	s := &subscriber{wake: make(chan struct{}, 1), out: make(chan Event)}
	go s.forward()
	return s
}

func (s *subscriber) push(e Event) {
	s.mu.Lock()
	s.queue = append(s.queue, e)
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *subscriber) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *subscriber) forward() {
	for {
		s.mu.Lock()
		q, closed := s.queue, s.closed
		s.queue = nil
		s.mu.Unlock()
		for _, e := range q {
			s.out <- e
		}
		if closed && len(q) == 0 {
			close(s.out)
			return
		}
		if len(q) == 0 {
			<-s.wake
		}
	}
}

func sleep(ctx context.Context, ms int) error {
	t := time.NewTimer(time.Duration(ms) * time.Millisecond)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func now() int64 { return time.Now().UnixMilli() }

// Open loads the state in cfg.StateDir and carries on with whatever was under way.
func Open(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.EpochPoll == 0 {
		cfg.EpochPoll = time.Minute
	}
	if cfg.WireVersion == 0 {
		cfg.WireVersion = wire.CurrentVersion
	}
	if cfg.WireVersion < wire.MapVersion || cfg.WireVersion > wire.CurrentVersion {
		return nil, fmt.Errorf("client: wire version %d is not 3, 4 or 5", cfg.WireVersion)
	}
	st, err := store.Open(cfg.StateDir, store.Options{NoSync: cfg.NoSync})
	if err != nil {
		return nil, err
	}
	s, err := st.Load(cfg.Name)
	if err != nil {
		st.Close()
		return nil, err
	}
	max, err := cfg.Backend.MaxPlaintext(ctx)
	if err != nil {
		st.Close()
		return nil, err
	}
	c := &Client{cfg: cfg, st: st, eng: engine.New(s, max), inbox: make(chan request)}
	c.eng.WireVersion = cfg.WireVersion
	// The replicas' epoch before anything is written, when the backend can say; the epoch
	// watcher reports it again later.
	if e, err := cfg.Backend.ReplicaEpoch(ctx); err == nil {
		c.eng.Epoch = int(e)
	}
	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.exec = &Executor{Backend: cfg.Backend, Files: store.Files{S: st}, Sleep: sleep}
	res := c.eng.Resume(now())
	if err := st.Commit(s, &res); err != nil {
		st.Close()
		return nil, err
	}
	c.loop.Add(1)
	go c.run()
	c.release(res)
	c.work.Add(1)
	go c.watchEpoch()
	return c, nil
}

func (c *Client) run() {
	defer c.loop.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case r := <-c.inbox:
			if r.query != nil {
				r.query(c.eng.State)
				r.done <- nil
				continue
			}
			if r.check != nil {
				if err := r.check(c.eng.State); err != nil {
					r.done <- err
					continue
				}
			}
			res := c.eng.Step(now(), r.in)
			if err := c.st.Commit(c.eng.State, &res); err != nil {
				// What the step did is not on disk, so none of it may go out: stop.
				c.fail(err)
				if r.done != nil {
					r.done <- err
				}
				return
			}
			if r.done != nil {
				r.done <- nil
			}
			c.release(res)
		}
	}
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	subs := c.subs
	c.mu.Unlock()
	for _, s := range subs {
		s.push(Event{Err: err})
	}
	c.cancel()
}

// release tells subscribers what a saved step changed, and starts the work it asks for.
func (c *Client) release(res engine.Result) {
	c.notify(res.Changes)
	for _, a := range res.Actions {
		c.launch(a, 0)
	}
}

func (c *Client) notify(ch engine.Changes) {
	events := map[engine.ChatID]*Event{}
	ev := func(id engine.ChatID) *Event {
		if e := events[id]; e != nil {
			return e
		}
		e := &Event{Chat: id}
		events[id] = e
		return e
	}
	for id := range ch.Chats {
		ev(id)
	}
	for id, ls := range ch.Lines {
		e := ev(id)
		for l := range ls {
			e.Lines = append(e.Lines, l)
		}
	}
	for id, ls := range ch.Dropped {
		e := ev(id)
		for l := range ls {
			e.Dropped = append(e.Dropped, l)
		}
	}
	for id := range ch.Removed {
		ev(id).Removed = true
	}
	c.mu.Lock()
	subs := c.subs
	c.mu.Unlock()
	for _, e := range events {
		for _, s := range subs {
			s.push(*e)
		}
	}
}

// launch carries out an action after waiting ms, and hands the engine what came of it.
func (c *Client) launch(a engine.Action, ms int) {
	c.work.Add(1)
	go func() {
		defer c.work.Done()
		if ms > 0 && (sleep(c.ctx, ms) != nil || !c.wanted(a)) {
			return
		}
		o := c.exec.Perform(c.ctx, a)
		if c.ctx.Err() != nil {
			return
		}
		switch {
		case o.Retry != nil:
			c.launch(o.Retry, o.After)
		case o.Input != nil && o.After > 0:
			if sleep(c.ctx, o.After) == nil {
				c.post(o.Input)
			}
		case o.Input != nil:
			c.post(o.Input)
		}
	}()
}

// wanted says whether an action tried again is still of use.
func (c *Client) wanted(a engine.Action) bool {
	ok := false
	return c.query(func(s *engine.State) { ok = s.Wanted(a) }) == nil && ok
}

func (c *Client) post(in engine.Input) {
	select {
	case c.inbox <- request{in: in}:
	case <-c.ctx.Done():
	}
}

func (c *Client) watchEpoch() {
	defer c.work.Done()
	for {
		if e, err := c.cfg.Backend.ReplicaEpoch(c.ctx); err == nil {
			c.post(engine.Epoch{N: int(e)})
		}
		if sleep(c.ctx, int(c.cfg.EpochPoll/time.Millisecond)) != nil {
			return
		}
	}
}

// do hands the engine a user's command, once check finds nothing wrong with it.
func (c *Client) do(in engine.Input, check func(*engine.State) error) error {
	r := request{in: in, check: check, done: make(chan error, 1)}
	select {
	case c.inbox <- r:
	case <-c.ctx.Done():
		return c.stopped()
	}
	select {
	case err := <-r.done:
		return err
	case <-c.ctx.Done():
		return c.stopped()
	}
}

func (c *Client) query(f func(*engine.State)) error {
	r := request{query: f, done: make(chan error, 1)}
	select {
	case c.inbox <- r:
	case <-c.ctx.Done():
		return c.stopped()
	}
	select {
	case <-r.done:
		return nil
	case <-c.ctx.Done():
		return c.stopped()
	}
}

func (c *Client) stopped() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return ErrClosed
}

// Err is why the client stopped, if it did.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Subscribe returns a channel of what changes from now on, closed when the client is.
func (c *Client) Subscribe() <-chan Event {
	s := newSubscriber()
	c.mu.Lock()
	c.subs = append(c.subs, s)
	c.mu.Unlock()
	return s.out
}

// Close stops all work under way and waits for it; nothing is lost, since a client opened on
// the same state carries on with it.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	c.cancel()
	c.loop.Wait()
	c.work.Wait()
	c.mu.Lock()
	for _, s := range c.subs {
		s.close()
	}
	c.subs = nil
	c.mu.Unlock()
	return c.st.Close()
}

func newID() engine.ChatID {
	b := make([]byte, 16)
	rand.Read(b)
	return engine.ChatID(hex.EncodeToString(b))
}

func nameFree(name string) func(*engine.State) error {
	return func(s *engine.State) error {
		switch {
		case name == "":
			return ErrEmptyName
		case s.ChatNamed(name) != nil:
			return ErrNameTaken
		}
		return nil
	}
}

func joined(id engine.ChatID, then func(*engine.Chat) error) func(*engine.State) error {
	return func(s *engine.State) error {
		c := s.Chat(id)
		switch {
		case c == nil:
			return ErrNoSuchChat
		case c.Group == nil:
			return ErrNotJoined
		}
		if then != nil {
			return then(c)
		}
		return nil
	}
}

func exists(id engine.ChatID) func(*engine.State) error {
	return func(s *engine.State) error {
		if s.Chat(id) == nil {
			return ErrNoSuchChat
		}
		return nil
	}
}

// Create founds a group.
func (c *Client) Create(name string) (engine.ChatID, error) {
	id := newID()
	return id, c.do(engine.Create{Chat: id, Name: name}, nameFree(name))
}

// Join mints a voucher to join a group we will call name; its code shows in the group's view
// once minted, for a member of the group to Invite with.
func (c *Client) Join(name string) (engine.ChatID, error) {
	id := newID()
	return id, c.do(engine.Join{Chat: id, Name: name}, nameFree(name))
}

// Invite adds the member whose voucher code is code.
func (c *Client) Invite(id engine.ChatID, code string) error {
	return c.do(engine.Induct{Chat: id, Code: code}, joined(id, func(ch *engine.Chat) error {
		if ch.Inducting != nil {
			return ErrAlreadyAdding
		}
		if _, err := decodeCode(code); err != nil {
			return ErrNotAVoucher
		}
		return nil
	}))
}

func (c *Client) Send(id engine.ChatID, text string) error {
	if text == "" {
		return ErrEmptyMessage
	}
	return c.do(engine.Send{Chat: id, Text: text}, joined(id, nil))
}

func (c *Client) SendFile(id engine.ChatID, name string, b []byte) error {
	if len(b) > wire.MaxFile {
		return ErrFileTooLarge
	}
	return c.do(engine.SendFile{Chat: id, Name: name, Bytes: b}, joined(id, nil))
}

// Ping asks the group's members to play their ping sound.
func (c *Client) Ping(id engine.ChatID) error { return c.do(engine.Ping{Chat: id}, joined(id, nil)) }

// Scan looks again for messages missed.
func (c *Client) Scan(id engine.ChatID) error { return c.do(engine.Scan{Chat: id}, joined(id, nil)) }

// Remove stops reading a member and deletes what they sent; they can still read the group.
func (c *Client) Remove(id engine.ChatID, who member.Key) error {
	return c.do(engine.RemoveMember{Chat: id, Who: who}, joined(id, func(ch *engine.Chat) error {
		if who == ch.Group.Me() {
			return ErrRemoveSelf
		}
		if !ch.Group.Readers.Has(who) {
			return ErrNoSuchMember
		}
		return nil
	}))
}

// Leave forgets a group and deletes all it holds here.
func (c *Client) Leave(id engine.ChatID) error { return c.do(engine.Leave{Chat: id}, exists(id)) }

// Clear deletes a group's lines here.
func (c *Client) Clear(id engine.ChatID) error { return c.do(engine.Clear{Chat: id}, exists(id)) }

func (c *Client) Rename(id engine.ChatID, to string) error {
	return c.do(engine.Rename{Chat: id, To: to}, func(s *engine.State) error {
		if err := exists(id)(s); err != nil {
			return err
		}
		if o := s.ChatNamed(to); o != nil && o.ID != id {
			return ErrNameTaken
		}
		if to == "" {
			return ErrEmptyName
		}
		return nil
	})
}
