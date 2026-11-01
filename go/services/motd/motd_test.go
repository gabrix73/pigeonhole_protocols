package motd_test

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonservice/common/phtest"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	client "github.com/katzenpost/pigeonhole_protocols/go/clients/motd"
	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
	"github.com/katzenpost/pigeonhole_protocols/go/services/motd"
)

const poll = 10 * time.Millisecond

var day = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

type clockAt time.Time

func (c clockAt) Now() time.Time { return time.Time(c) }

// fakeConn is a connection whose peer is the test: it reads what the test puts in in, and
// what it sends comes out of out. Closing in ends it.
type fakeConn struct {
	in, out chan []byte
}

func newFakeConn() *fakeConn { return &fakeConn{in: make(chan []byte, 4), out: make(chan []byte, 4)} }

func (c *fakeConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case m, ok := <-c.in:
		if !ok {
			return nil, io.EOF
		}
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *fakeConn) Send(ctx context.Context, msg []byte) error {
	c.out <- msg
	return nil
}

// serve runs Serve on a fake connection, returning the connection and Serve's result.
func serve(t *testing.T, source motd.Source, clock motd.Clock) (*fakeConn, chan error) {
	c := newFakeConn()
	done := make(chan error, 1)
	go func() { done <- motd.Serve(context.Background(), c, source, clock) }()
	return c, done
}

func request(t *testing.T) []byte {
	b, err := common.Marshal(&motd.Request{})
	require.NoError(t, err)
	return b
}

func reply(t *testing.T, c *fakeConn) motd.Reply {
	var r motd.Reply
	select {
	case raw := <-c.out:
		require.NoError(t, common.Unmarshal(raw, &r))
	case <-time.After(5 * time.Second):
		t.Fatal("no reply")
	}
	return r
}

func TestServeDatesRepliesInUTC(t *testing.T) {
	east := time.FixedZone("UTC+10", 10*3600)
	for _, tc := range []struct {
		now  time.Time
		want string
	}{
		{time.Date(2026, 10, 28, 23, 59, 59, 0, time.UTC), "2026-10-28"},
		{time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC), "2026-10-29"},
		// Already the 29th in UTC+10, still the 28th in UTC.
		{time.Date(2026, 10, 29, 9, 0, 0, 0, east), "2026-10-28"},
	} {
		c, _ := serve(t, func() (string, error) { return "hi", nil }, clockAt(tc.now))
		c.in <- request(t)
		require.Equal(t, motd.Reply{Message: "hi", Day: tc.want}, reply(t, c), "at %v", tc.now)
		close(c.in)
	}
}

func TestServeReadsTheSourceForEachRequest(t *testing.T) {
	msgs := []string{"one", "two"}
	n := 0
	c, done := serve(t, func() (string, error) { n++; return msgs[n-1], nil }, clockAt(day))
	c.in <- request(t)
	require.Equal(t, "one", reply(t, c).Message)
	c.in <- request(t)
	require.Equal(t, "two", reply(t, c).Message)
	close(c.in)
	require.ErrorIs(t, <-done, io.EOF)
}

func TestServeAnswersARequestThatDoesNotDecode(t *testing.T) {
	c, _ := serve(t, func() (string, error) { return "hi", nil }, clockAt(day))
	c.in <- []byte{0xff, 0x00}
	require.Equal(t, motd.Reply{Error: "bad request"}, reply(t, c))
	c.in <- request(t)
	require.Equal(t, "hi", reply(t, c).Message)
	close(c.in)
}

func TestServeAnswersWhenTheSourceFails(t *testing.T) {
	fail := true
	c, _ := serve(t, func() (string, error) {
		if fail {
			return "", errors.New("no message today")
		}
		return "hi", nil
	}, clockAt(day))
	c.in <- request(t)
	require.Equal(t, motd.Reply{Error: "no message available"}, reply(t, c))
	fail = false
	c.in <- request(t)
	require.Equal(t, "hi", reply(t, c).Message)
	close(c.in)
}

func TestFetchReportsAnError(t *testing.T) {
	c, _ := serve(t, func() (string, error) { return "", errors.New("gone") }, clockAt(day))
	_, err := client.Fetch(context.Background(), &fakeConn{in: c.out, out: c.in})
	require.ErrorContains(t, err, "no message available")
	close(c.in)
}

func TestFetch(t *testing.T) {
	c, _ := serve(t, func() (string, error) { return "hi", nil }, clockAt(day))
	// Fetch is the client: it sends on the service's in and reads its out.
	got, err := client.Fetch(context.Background(), &fakeConn{in: c.out, out: c.in})
	require.NoError(t, err)
	require.Equal(t, &motd.Reply{Message: "hi", Day: "2026-10-28"}, got)
	close(c.in)
}

func TestFetchRejectsABadReply(t *testing.T) {
	c := newFakeConn()
	c.in <- []byte{0xff}
	_, err := client.Fetch(context.Background(), c)
	require.ErrorIs(t, err, client.ErrBadReply)
}

func pluginKey(t *testing.T) *common.PluginKey {
	pub, priv, err := common.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	return &common.PluginKey{Scheme: common.DefaultNIKE, Public: pub, Private: priv}
}

func TestMOTD(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	logBackend, err := log.New("", "info", false)
	require.NoError(t, err)
	net := phtest.NewNetwork()

	rkey := pluginKey(t)
	r, err := voucher_router.New(voucher_router.Config{
		Key: rkey, DBPath: filepath.Join(t.TempDir(), "router.db"),
		PollInterval: poll, Retention: time.Hour, Log: logBackend.GetLogger("router"),
	}, net)
	require.NoError(t, err)
	defer r.Close()
	net.AddService(voucher_router.RouterCapability, [32]byte{0xa0}, voucher_router.RouterCapability, common.PluginParams(rkey),
		func(_ context.Context, p []byte) []byte { return r.Handle(p) })
	dkey := pluginKey(t)
	d, err := discovery.New(discovery.Config{
		Key: dkey, DBPath: filepath.Join(t.TempDir(), "directory.db"),
		RefreshInterval: time.Hour, Log: logBackend.GetLogger("directory"),
	}, net)
	require.NoError(t, err)
	defer d.Close()
	net.AddService(discovery.DirectoryCapability, [32]byte{0xdd}, discovery.DirectoryCapability, common.PluginParams(dkey),
		func(_ context.Context, p []byte) []byte { return d.Handle(p) })

	dataDir := t.TempDir()
	key, err := common.LoadServiceKey(dataDir)
	require.NoError(t, err)
	adv, err := discovery.NewClient(net, key, poll)
	require.NoError(t, err)
	svc, err := ps.NewService(ps.Config{
		Key: key, DataDir: dataDir, DisplayName: "motd", Advertiser: adv,
		PollInterval: poll, Log: logBackend.GetLogger("motd"),
	}, net)
	require.NoError(t, err)
	var message atomic.Value
	message.Store("Be excellent to each other.")
	go svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
		_ = motd.Serve(ctx, s, func() (string, error) { return message.Load().(string), nil }, clockAt(day))
	}))
	t.Cleanup(func() { cancel(); svc.Close() })

	reader, err := discovery.NewClient(net, nil, poll)
	require.NoError(t, err)
	var desc *common.ServiceDescriptor
	require.Eventually(t, func() bool {
		desc, err = reader.Lookup(ctx, svc.ID())
		return err == nil && len(desc.Routers) == 1
	}, 30*time.Second, 20*time.Millisecond)

	conn, err := ps.Dial(ctx, net, desc, "client", poll)
	require.NoError(t, err)
	reply, err := client.Fetch(ctx, conn)
	require.NoError(t, err)
	require.Equal(t, "Be excellent to each other.", reply.Message)
	require.Equal(t, "2026-10-28", reply.Day)

	message.Store("Tomorrow is another day.")
	reply, err = client.Fetch(ctx, conn)
	require.NoError(t, err)
	require.Equal(t, "Tomorrow is another day.", reply.Message, "each request reads the current message")
}
