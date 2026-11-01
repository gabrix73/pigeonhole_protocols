// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sort"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
)

var (
	linksBucket    = []byte("links")
	sessionsBucket = []byte("sessions")
	// vouchersBucket holds the vouchers read from links and not yet
	// handled, so a crash does not lose one a router has acknowledged.
	vouchersBucket = []byte("vouchers")
)

const (
	// voucherDedupTTL is how long an opened voucher is remembered, so one
	// forwarded twice is handled once.
	voucherDedupTTL = time.Hour
	// incomingQueueSize bounds the vouchers waiting to be accepted.
	incomingQueueSize = 256
	// DefaultRegisterTimeout is the default time a registration has to
	// complete, longer than the router's default induction deadline.
	DefaultRegisterTimeout = 15 * time.Minute
	// DefaultHandshakeTimeout is the default time a client's voucher has
	// to be inducted before Run gives up on it.
	DefaultHandshakeTimeout = 10 * time.Minute
	// closeTimeout bounds the withdrawal Close sends.
	closeTimeout = 2 * time.Minute
)

// rescanInterval is how often the service looks for new routers.
var rescanInterval = 10 * time.Minute

// LoadServiceKey loads the service's keypair from dataDir, generating one
// on first use.
func LoadServiceKey(dataDir string) (*common.ServiceKey, error) {
	pub, priv, err := common.LoadOrGenerateKeypair(dataDir, "service", common.DefaultNIKE)
	if err != nil {
		return nil, err
	}
	return &common.ServiceKey{Scheme: common.DefaultNIKE, Public: pub, Private: priv}, nil
}

// Config configures a Service.
type Config struct {
	// Key is the service's keypair; see LoadServiceKey.
	Key *common.ServiceKey
	// DataDir holds the service's database.
	DataDir string
	// DisplayName is the name the service gives itself to clients.
	DisplayName string
	// Advertiser publishes the service's descriptor; nil to not advertise.
	Advertiser discovery.Advertiser
	// PollInterval is how often a pending read is retried.
	PollInterval time.Duration
	// MaxConcurrentSessions bounds the sessions Run serves at once.
	MaxConcurrentSessions int
	// Retention is how long a sent message is kept rewritten.
	Retention time.Duration
	// RegisterTimeout is how long a registration with a router has to
	// complete before it is abandoned and retried on the next rescan;
	// zero means DefaultRegisterTimeout.
	RegisterTimeout time.Duration
	// HandshakeTimeout is how long Run waits for a client's handshake;
	// zero means DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// LinkTTL is the lease asked of each router, renewed once half of it
	// has passed; zero means voucher_router.MaxLinkTTL, the most a router
	// grants.
	LinkTTL time.Duration
	// AdvertiseTTL is the lease asked of each directory, renewed once half
	// of it has passed; zero means discovery.MaxEntryTTL, the most a
	// directory grants.
	AdvertiseTTL time.Duration
	Log          *logging.Logger
}

// Handler serves one session. The session ends when OnSession returns.
type Handler interface {
	OnSession(ctx context.Context, s *Session)
}

// HandlerFunc adapts a function to a Handler.
type HandlerFunc func(ctx context.Context, s *Session)

// OnSession calls f.
func (f HandlerFunc) OnSession(ctx context.Context, s *Session) { f(ctx, s) }

// Session is a service's connection with one client.
type Session struct {
	*voucher_router.Conn
	id      [16]byte
	service *Service
}

// Close ends the session and forgets it.
func (s *Session) Close() error {
	return s.service.dropSession(s)
}

// Incoming is a client's opened voucher: the capability for one new
// session. Handshake turns it into the session.
type Incoming struct {
	service  *Service
	voucher  []byte
	restored *Session
}

// Handshake runs the service's side of the contact voucher handshake and
// returns the new session.
func (in *Incoming) Handshake(ctx context.Context) (*Session, error) {
	if in.restored != nil {
		return in.restored, nil
	}
	s := in.service
	conn, err := voucher_router.Induct(ctx, s.ph, in.voucher, s.cfg.DisplayName, s.cfg.PollInterval)
	if err != nil {
		// A handshake cut short by shutdown is tried again after a restart.
		if !errors.Is(ctx.Err(), context.Canceled) {
			s.forgetVoucher(in.voucher)
		}
		return nil, err
	}
	sess := &Session{Conn: conn, service: s}
	if _, err := rand.Read(sess.id[:]); err != nil {
		return nil, err
	}
	if err := s.addSession(sess); err != nil {
		return nil, err
	}
	s.forgetVoucher(in.voucher)
	return sess, nil
}

// Listener yields the vouchers clients send the service.
type Listener struct {
	incoming chan *Incoming
	done     <-chan struct{}
}

// ErrClosed reports that the service has stopped.
var ErrClosed = errors.New("pigeonservice: service closed")

// Accept returns the next client's voucher.
func (l *Listener) Accept(ctx context.Context) (*Incoming, error) {
	select {
	case in := <-l.incoming:
		return in, nil
	case <-l.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Service is a pigeonhole service: it holds links with voucher routers,
// advertises them, and accepts the clients who reach it through them.
type Service struct {
	cfg Config
	ph  common.Pigeonhole
	key *common.ServiceKey
	db  *bolt.DB
	log *logging.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	incoming chan *Incoming

	mu          sync.Mutex
	links       map[[32]byte]*linkState
	registering map[[32]byte]bool
	sessions    map[[16]byte]*Session
	vouchers    map[[32]byte]time.Time
	unhandled   [][]byte
	listening   bool
	// advertised is the expiry of the last advertisement taken.
	advertised uint64
}

type linkState struct {
	node common.ServiceNode
	conn *voucher_router.Conn
	// expiry is the link's lease, Unix seconds.
	expiry uint64
	stop   context.CancelFunc
}

type storedLink struct {
	NodeIDHash [32]byte
	Endpoint   []byte
	Conn       voucher_router.ConnState
	Expiry     uint64 `cbor:",omitempty"`
}

// NewService opens a service's database and restores its links and
// sessions. Call Listen or Run to start it.
func NewService(cfg Config, ph common.Pigeonhole) (*Service, error) {
	if cfg.Key == nil || cfg.Log == nil {
		return nil, errors.New("pigeonservice: Key and Log are required")
	}
	if cfg.DisplayName == "" {
		cfg.DisplayName = "service"
	}
	if cfg.MaxConcurrentSessions <= 0 {
		cfg.MaxConcurrentSessions = 64
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 7 * 24 * time.Hour
	}
	if cfg.RegisterTimeout <= 0 {
		cfg.RegisterTimeout = DefaultRegisterTimeout
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if cfg.LinkTTL <= 0 {
		cfg.LinkTTL = voucher_router.MaxLinkTTL
	}
	if cfg.AdvertiseTTL <= 0 {
		cfg.AdvertiseTTL = discovery.MaxEntryTTL
	}
	db, err := bolt.Open(filepath.Join(cfg.DataDir, "service.db"), 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{
		cfg:         cfg,
		ph:          ph,
		key:         cfg.Key,
		db:          db,
		log:         cfg.Log,
		ctx:         ctx,
		cancel:      cancel,
		incoming:    make(chan *Incoming, incomingQueueSize),
		links:       make(map[[32]byte]*linkState),
		registering: make(map[[32]byte]bool),
		sessions:    make(map[[16]byte]*Session),
		vouchers:    make(map[[32]byte]time.Time),
	}
	if err := s.restore(); err != nil {
		db.Close()
		cancel()
		return nil, err
	}
	return s, nil
}

// Close stops the service, withdrawing it from the directories it is
// advertised in. Its links with routers are kept for the next Listen; a
// router forgets one that is not renewed within its lease.
func (s *Service) Close() error {
	s.mu.Lock()
	advertised := s.advertised != 0
	s.mu.Unlock()
	if advertised {
		ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
		if err := s.cfg.Advertiser.Withdraw(ctx, s.ID()); err != nil {
			s.log.Warningf("withdrawing: %v", err)
		}
		cancel()
	}
	s.cancel()
	s.wg.Wait()
	return s.db.Close()
}

// ID returns the service's ServiceID.
func (s *Service) ID() common.ServiceID {
	return s.key.ID()
}

// Descriptor returns the service's current descriptor.
func (s *Service) Descriptor() *common.ServiceDescriptor {
	d := &common.ServiceDescriptor{NIKEScheme: s.key.Scheme.Name(), PublicKey: s.key.Public.Bytes()}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range s.links {
		d.Routers = append(d.Routers, common.RouterRef{NodeIDHash: l.node.NodeIDHash, Endpoint: string(l.node.Endpoint)})
	}
	sort.Slice(d.Routers, func(i, j int) bool {
		return bytes.Compare(d.Routers[i].NodeIDHash[:], d.Routers[j].NodeIDHash[:]) < 0
	})
	return d
}

func (s *Service) restore() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		links, err := tx.CreateBucketIfNotExists(linksBucket)
		if err != nil {
			return err
		}
		sessions, err := tx.CreateBucketIfNotExists(sessionsBucket)
		if err != nil {
			return err
		}
		vouchers, err := tx.CreateBucketIfNotExists(vouchersBucket)
		if err != nil {
			return err
		}
		if err := vouchers.ForEach(func(k, v []byte) error {
			s.vouchers[[32]byte(k)] = time.Now()
			s.unhandled = append(s.unhandled, append([]byte(nil), v...))
			return nil
		}); err != nil {
			return err
		}
		if err := links.ForEach(func(_, v []byte) error {
			var sl storedLink
			if err := common.Unmarshal(v, &sl); err != nil {
				return err
			}
			conn, err := voucher_router.RestoreConn(s.ph, &sl.Conn, s.cfg.PollInterval)
			if err != nil {
				return err
			}
			s.links[sl.NodeIDHash] = &linkState{node: common.ServiceNode{NodeIDHash: sl.NodeIDHash, Endpoint: sl.Endpoint}, conn: conn, expiry: sl.Expiry}
			return nil
		}); err != nil {
			return err
		}
		return sessions.ForEach(func(k, v []byte) error {
			var st voucher_router.ConnState
			if err := common.Unmarshal(v, &st); err != nil {
				return err
			}
			conn, err := voucher_router.RestoreConn(s.ph, &st, s.cfg.PollInterval)
			if err != nil {
				return err
			}
			sess := &Session{Conn: conn, service: s}
			copy(sess.id[:], k)
			s.sessions[sess.id] = sess
			return nil
		})
	})
}

func (s *Service) put(bucket, key []byte, v any) {
	blob, err := common.Marshal(v)
	if err == nil {
		err = s.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(bucket).Put(key, blob)
		})
	}
	if err != nil {
		s.log.Errorf("saving state: %v", err)
	}
}

func (s *Service) saveLink(l *linkState) {
	s.saveLinkWith(l, nil)
}

// saveLinkWith saves a link together with a voucher just read from it, in
// one transaction, so the voucher is not lost once the read index moves.
func (s *Service) saveLinkWith(l *linkState, voucher []byte) {
	st, err := l.conn.State()
	if err == nil {
		s.mu.Lock()
		expiry := l.expiry
		s.mu.Unlock()
		var blob []byte
		blob, err = common.Marshal(&storedLink{NodeIDHash: l.node.NodeIDHash, Endpoint: l.node.Endpoint, Conn: *st, Expiry: expiry})
		if err == nil {
			err = s.db.Update(func(tx *bolt.Tx) error {
				if voucher != nil {
					key := hash.Sum256(voucher)
					if err := tx.Bucket(vouchersBucket).Put(key[:], voucher); err != nil {
						return err
					}
				}
				return tx.Bucket(linksBucket).Put(l.node.NodeIDHash[:], blob)
			})
		}
	}
	if err != nil {
		s.log.Errorf("saving a link: %v", err)
	}
}

func (s *Service) forgetVoucher(voucher []byte) {
	key := hash.Sum256(voucher)
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(vouchersBucket).Delete(key[:])
	}); err != nil {
		s.log.Errorf("forgetting a voucher: %v", err)
	}
}

func (s *Service) saveSession(sess *Session) {
	st, err := sess.State()
	if err != nil {
		s.log.Errorf("saving a session: %v", err)
		return
	}
	s.mu.Lock()
	_, live := s.sessions[sess.id]
	s.mu.Unlock()
	if live {
		s.put(sessionsBucket, sess.id[:], st)
	}
}

func (s *Service) addSession(sess *Session) error {
	s.mu.Lock()
	s.sessions[sess.id] = sess
	s.mu.Unlock()
	sess.OnChange(func(*voucher_router.Conn) { s.saveSession(sess) })
	s.saveSession(sess)
	return nil
}

func (s *Service) dropSession(sess *Session) error {
	s.mu.Lock()
	delete(s.sessions, sess.id)
	s.mu.Unlock()
	sess.OnChange(nil)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(sessionsBucket).Delete(sess.id[:])
	})
}

// Listen starts the service: it resumes its links, registers with every
// router in the PKI it has no link with, advertises itself, and returns
// the listener for its clients. Sessions restored from the database are
// the first things Accept returns.
func (s *Service) Listen(ctx context.Context) (*Listener, error) {
	s.mu.Lock()
	if s.listening {
		s.mu.Unlock()
		return nil, errors.New("pigeonservice: already listening")
	}
	s.listening = true
	links := make([]*linkState, 0, len(s.links))
	for _, l := range s.links {
		links = append(links, l)
	}
	restored := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		restored = append(restored, sess)
	}
	unhandled := s.unhandled
	s.unhandled = nil
	s.mu.Unlock()

	for _, sess := range restored {
		sess.OnChange(func(*voucher_router.Conn) { s.saveSession(sess) })
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for _, sess := range restored {
			select {
			case s.incoming <- &Incoming{service: s, restored: sess}:
			case <-s.ctx.Done():
				return
			}
		}
		for _, v := range unhandled {
			select {
			case s.incoming <- &Incoming{service: s, voucher: v}:
			case <-s.ctx.Done():
				return
			}
		}
	}()
	for _, l := range links {
		s.startLink(l)
	}
	s.wg.Add(2)
	go s.registrar()
	go s.refresher()
	if len(links) > 0 {
		s.advertise()
	}
	return &Listener{incoming: s.incoming, done: s.ctx.Done()}, nil
}

// Run listens and serves each session with h in its own goroutine, at most
// MaxConcurrentSessions at once, until ctx ends.
func (s *Service) Run(ctx context.Context, h Handler) error {
	l, err := s.Listen(ctx)
	if err != nil {
		return err
	}
	sem := make(chan struct{}, s.cfg.MaxConcurrentSessions)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		in, err := l.Accept(ctx)
		if err != nil {
			return err
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			hctx, cancel := context.WithTimeout(ctx, s.cfg.HandshakeTimeout)
			sess, err := in.Handshake(hctx)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					s.log.Warningf("handshake with a client: %v", err)
				}
				return
			}
			h.OnSession(ctx, sess)
			// Sessions interrupted by shutdown are kept for the next Listen.
			if ctx.Err() == nil {
				_ = sess.Close()
			}
		}()
	}
}

// startLink starts reading a link. readLink saves the link itself, with
// each voucher it reads.
func (s *Service) startLink(l *linkState) {
	ctx, stop := context.WithCancel(s.ctx)
	s.mu.Lock()
	l.stop = stop
	s.mu.Unlock()
	s.wg.Add(1)
	go s.readLink(ctx, l)
}

// readLink reads the vouchers one router forwards. A link that fails to
// read is dropped, so the next rescan registers with its router again.
func (s *Service) readLink(ctx context.Context, l *linkState) {
	defer s.wg.Done()
	for {
		msg, err := l.conn.Recv(ctx)
		if err != nil {
			if s.ctx.Err() == nil && ctx.Err() == nil {
				s.log.Errorf("reading a link: %v", err)
				s.dropLink(l)
			}
			return
		}
		voucher, err := voucher_router.OpenForward(s.key, msg)
		if err != nil || len(voucher) != 32 || s.seen(voucher) {
			if err != nil {
				s.log.Warningf("a router forwarded something that does not open: %v", err)
			}
			s.saveLink(l)
			continue
		}
		s.saveLinkWith(l, voucher)
		select {
		case s.incoming <- &Incoming{service: s, voucher: voucher}:
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Service) seen(voucher []byte) bool {
	key := hash.Sum256(voucher)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, at := range s.vouchers {
		if now.Sub(at) > voucherDedupTTL {
			delete(s.vouchers, k)
		}
	}
	if _, ok := s.vouchers[key]; ok {
		return true
	}
	s.vouchers[key] = now
	return false
}

// registrar registers with routers the service has no link with, now and
// whenever it rescans the PKI.
func (s *Service) registrar() {
	defer s.wg.Done()
	t := time.NewTicker(rescanInterval)
	defer t.Stop()
	for {
		s.registerAll()
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) registerAll() {
	nodes, err := s.ph.Services(voucher_router.RouterCapability)
	if err != nil {
		s.log.Warningf("listing routers: %v", err)
		return
	}
	now := uint64(time.Now().Unix())
	for i := range nodes {
		node := nodes[i]
		s.mu.Lock()
		l, linked := s.links[node.NodeIDHash]
		busy := s.registering[node.NodeIDHash]
		renew := linked && l.expiry < now+uint64(s.cfg.LinkTTL/time.Second)/2
		if (!linked || renew) && !busy {
			s.registering[node.NodeIDHash] = true
		}
		s.mu.Unlock()
		if busy || (linked && !renew) {
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				s.mu.Lock()
				delete(s.registering, node.NodeIDHash)
				s.mu.Unlock()
			}()
			if renew {
				s.renew(l)
				return
			}
			ctx, cancel := context.WithTimeout(s.ctx, s.cfg.RegisterTimeout)
			defer cancel()
			expiry := common.LeaseExpiry(s.cfg.LinkTTL)
			conn, err := voucher_router.Register(ctx, s.ph, s.key, &node, s.cfg.PollInterval, expiry)
			if err != nil {
				if s.ctx.Err() == nil {
					s.log.Warningf("registering with router %x: %v", node.NodeIDHash[:8], err)
				}
				return
			}
			l := &linkState{node: node, conn: conn, expiry: expiry}
			s.mu.Lock()
			s.links[node.NodeIDHash] = l
			s.mu.Unlock()
			s.saveLink(l)
			s.startLink(l)
			s.log.Noticef("linked with router %x", node.NodeIDHash[:8])
			s.advertise()
		}()
	}
	s.mu.Lock()
	due := len(s.links) > 0 && s.advertised < now+uint64(s.cfg.AdvertiseTTL/time.Second)/2
	s.mu.Unlock()
	if due {
		s.advertise()
	}
}

// renew asks the router for a new lease on a link. A router that no longer
// knows the link is left for the next rescan to register with again.
func (s *Service) renew(l *linkState) {
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.RegisterTimeout)
	defer cancel()
	expiry := common.LeaseExpiry(s.cfg.LinkTTL)
	err := voucher_router.Renew(ctx, s.ph, s.key, &l.node, expiry)
	var se *common.StatusError
	switch {
	case err == nil:
		s.mu.Lock()
		l.expiry = expiry
		s.mu.Unlock()
		s.saveLink(l)
	case errors.As(err, &se) && (se.Status == common.StatusUnknownService || se.Status == common.StatusStale):
		s.log.Warningf("router %x forgot our link: %v", l.node.NodeIDHash[:8], err)
		s.dropLink(l)
	case s.ctx.Err() == nil:
		s.log.Warningf("renewing with router %x: %v", l.node.NodeIDHash[:8], err)
	}
}

// dropLink forgets a link and advertises without its router.
func (s *Service) dropLink(l *linkState) {
	s.mu.Lock()
	if s.links[l.node.NodeIDHash] != l {
		s.mu.Unlock()
		return
	}
	delete(s.links, l.node.NodeIDHash)
	stop := l.stop
	s.mu.Unlock()
	if stop != nil {
		stop()
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(linksBucket).Delete(l.node.NodeIDHash[:])
	}); err != nil {
		s.log.Errorf("deleting a link: %v", err)
	}
	s.advertise()
}

func (s *Service) advertise() {
	if s.cfg.Advertiser == nil {
		return
	}
	granted, err := s.cfg.Advertiser.Advertise(s.ctx, s.Descriptor(), common.LeaseExpiry(s.cfg.AdvertiseTTL))
	if err != nil {
		if s.ctx.Err() == nil {
			s.log.Warningf("advertising: %v", err)
		}
		return
	}
	s.mu.Lock()
	s.advertised = granted
	s.mu.Unlock()
}

// refresher rewrites recently sent boxes on links and sessions, so they
// survive replica garbage collection.
func (s *Service) refresher() {
	defer s.wg.Done()
	t := time.NewTicker(max(s.cfg.Retention/7, time.Minute))
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		conns := make([]*voucher_router.Conn, 0, len(s.links)+len(s.sessions))
		for _, l := range s.links {
			conns = append(conns, l.conn)
		}
		for _, sess := range s.sessions {
			conns = append(conns, sess.Conn)
		}
		s.mu.Unlock()
		for _, c := range conns {
			if err := c.Refresh(s.ctx, s.cfg.Retention); err != nil && s.ctx.Err() == nil {
				s.log.Warningf("refreshing: %v", err)
			}
		}
	}
}

// Dial connects a client to the service d describes: it mints a voucher,
// routes it sealed to the service, and waits for the service's reply.
func Dial(ctx context.Context, ph common.Pigeonhole, d *common.ServiceDescriptor, displayName string, pollInterval time.Duration) (*voucher_router.Conn, error) {
	pending, err := voucher_router.Mint(ctx, ph, displayName)
	if err != nil {
		return nil, err
	}
	if err := voucher_router.Route(ctx, ph, d, pending.Voucher); err != nil {
		return nil, err
	}
	return pending.Await(ctx, ph, pollInterval)
}
