package interop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/protocols/sealedbox"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
)

// TestDirectory advertises a descriptor to every directory, looks it up, finds it in the
// snapshot stream, and checks that a forged advertisement is refused.
func testDirectory(t *testing.T) {
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
	_, err = adv.Advertise(ctx, d, common.LeaseExpiry(discovery.MaxEntryTTL))
	require.NoError(t, err)

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
	forged := &discovery.AdvertiseRequest{Descriptor: *d, Seq: uint64(time.Now().UnixNano()), Expiry: common.LeaseExpiry(discovery.MaxEntryTTL)}
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
func testRouter(t *testing.T) {
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
	link, err := voucher_router.Register(ctx, ph, key, &node, n.poll, common.LeaseExpiry(voucher_router.MaxLinkTTL))
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
