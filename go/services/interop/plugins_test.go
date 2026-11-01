package interop

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/protocols/sealedbox"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
)

// TestDirectory advertises a descriptor to every directory, looks it up, finds it in the
// snapshot stream, and checks that a forged advertisement is refused.
func TestDirectory(t *testing.T) {
	n := newNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	t.Cleanup(cancel)
	ph := n.pigeonhole()
	key, err := common.LoadServiceKey(t.TempDir())
	require.NoError(t, err)
	adv, err := discovery.NewAll(ph, key, n.poll)
	require.NoError(t, err)
	d := &common.ServiceDescriptor{
		NIKEScheme: key.Scheme.Name(),
		PublicKey:  key.Public.Bytes(),
		Routers:    []common.RouterRef{{NodeIDHash: [32]byte{1}, Endpoint: voucher_router.RouterCapability}},
	}
	require.NoError(t, adv.Advertise(ctx, d))

	reader, err := discovery.NewAll(ph, nil, n.poll)
	require.NoError(t, err)
	got, err := reader.Lookup(ctx, key.ID())
	require.NoError(t, err)
	require.Equal(t, d, got)
	for listed := false; !listed; {
		require.NoError(t, ctx.Err(), "the snapshot never listed the service")
		all, err := reader.List(ctx)
		// The directory is busy until it has published its first snapshot.
		var busy *common.StatusError
		if errors.As(err, &busy) && busy.Status == common.StatusBusy {
			time.Sleep(n.poll)
			continue
		}
		require.NoError(t, err)
		for _, x := range all {
			listed = listed || x.ID() == key.ID()
		}
		if !listed {
			time.Sleep(n.poll)
		}
	}

	nodes, err := ph.Services(discovery.DirectoryCapability)
	require.NoError(t, err)
	mallory, err := common.LoadServiceKey(t.TempDir())
	require.NoError(t, err)
	dirPub, err := common.PluginPublicKey(&nodes[0], common.DefaultNIKE)
	require.NoError(t, err)
	forged := &discovery.AdvertiseRequest{Descriptor: *d, Seq: uint64(time.Now().UnixNano())}
	require.NoError(t, discovery.SignAdvertise(mallory, dirPub, forged))
	payload, err := common.Marshal(&discovery.DirectoryRequest{Advertise: forged})
	require.NoError(t, err)
	raw, err := ph.Request(ctx, &nodes[0].NodeIDHash, nodes[0].Endpoint, payload)
	require.NoError(t, err)
	var reply discovery.DirectoryReply
	require.NoError(t, common.Unmarshal(raw, &reply))
	require.Equal(t, common.StatusBadMAC, reply.Status)
}

// TestRouter registers a service with a voucher router, routes a sealed voucher through it,
// and reads it off the link.
func TestRouter(t *testing.T) {
	n := newNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	t.Cleanup(cancel)
	ph := n.pigeonhole()
	key, err := common.LoadServiceKey(t.TempDir())
	require.NoError(t, err)
	nodes, err := ph.Services(voucher_router.RouterCapability)
	require.NoError(t, err)
	require.NotEmpty(t, nodes, "the PKI lists a voucher router")
	node := nodes[0]
	link, err := voucher_router.Register(ctx, ph, key, &node, n.poll)
	require.NoError(t, err)
	d := &common.ServiceDescriptor{
		NIKEScheme: key.Scheme.Name(),
		PublicKey:  key.Public.Bytes(),
		Routers:    []common.RouterRef{{NodeIDHash: node.NodeIDHash, Endpoint: string(node.Endpoint)}},
	}
	voucher := make([]byte, 32)
	copy(voucher, "a voucher for the mixnet")
	require.NoError(t, voucher_router.Route(ctx, ph, d, voucher))
	msg, err := link.Recv(ctx)
	require.NoError(t, err)
	var lm voucher_router.LinkMessage
	require.NoError(t, common.Unmarshal(msg, &lm))
	opened, err := sealedbox.NewScheme(key.Scheme).Open(key.Private, key.Public, lm.Forward)
	require.NoError(t, err)
	require.Equal(t, voucher, opened)
}

// TestEcho runs an echo service on one thin connection and talks to it from others: through
// the directory, a voucher router and the contact voucher handshake, more clients at once than
// the service serves concurrently.
func TestEcho(t *testing.T) {
	n := newNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	t.Cleanup(cancel)
	servicePh := n.pigeonhole()
	dataDir := t.TempDir()
	key, err := common.LoadServiceKey(dataDir)
	require.NoError(t, err)
	adv, err := discovery.NewAll(servicePh, key, n.poll)
	require.NoError(t, err)
	const limit = 2
	svc, err := ps.NewService(ps.Config{
		Key: key, DataDir: dataDir, DisplayName: "echo", Advertiser: adv,
		PollInterval: n.poll, MaxConcurrentSessions: limit, Retention: time.Hour, Log: n.log.GetLogger("echo"),
	}, servicePh)
	require.NoError(t, err)
	go svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
		defer s.Close()
		msg, err := s.Recv(ctx)
		if err != nil {
			return
		}
		_ = s.Send(ctx, append([]byte("echo: "), msg...))
	}))
	t.Cleanup(func() { cancel(); svc.Close() })

	clientPh := n.pigeonhole()
	d := lookupLinked(t, ctx, n, clientPh, svc.ID())
	const clients = limit + 1
	errs := make(chan error, clients)
	for i := range clients {
		go func() {
			conn, err := ps.Dial(ctx, clientPh, d, "client", n.poll)
			if err != nil {
				errs <- fmt.Errorf("client %d: dial: %w", i, err)
				return
			}
			msg := []byte{'h', 'i', ' ', byte('a' + i)}
			if err := conn.Send(ctx, msg); err != nil {
				errs <- fmt.Errorf("client %d: send: %w", i, err)
				return
			}
			reply, err := conn.Recv(ctx)
			if err != nil {
				errs <- fmt.Errorf("client %d: receive: %w", i, err)
				return
			}
			if string(reply) != "echo: "+string(msg) {
				errs <- fmt.Errorf("client %d: unexpected reply %q", i, reply)
				return
			}
			t.Logf("client %d echoed", i)
			errs <- nil
		}()
	}
	for range clients {
		require.NoError(t, <-errs)
	}
}
