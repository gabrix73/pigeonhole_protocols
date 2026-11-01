// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
)

// leasedService is a service whose leases are short, so renewals happen
// within a test.
func (w *world) leasedService(t *testing.T, ttl time.Duration) *ps.Service {
	t.Helper()
	dataDir := t.TempDir()
	key, err := common.LoadServiceKey(dataDir)
	require.NoError(t, err)
	adv, err := discovery.NewClient(w.net, key, poll)
	require.NoError(t, err)
	svc, err := ps.NewService(ps.Config{
		Key: key, DataDir: dataDir, DisplayName: "echo", Advertiser: adv,
		PollInterval: poll, Retention: time.Hour, LinkTTL: ttl, AdvertiseTTL: ttl,
		Log: w.log.GetLogger("service"),
	}, w.net)
	require.NoError(t, err)
	return svc
}

// TestLeasesAreRenewed runs a service past its leases: it renews its links
// and its advertisement, so clients still find and reach it.
func TestLeasesAreRenewed(t *testing.T) {
	defer ps.SetRescanInterval(100 * time.Millisecond)()
	w := newWorld(t)
	svc := w.leasedService(t, 20*time.Second)
	ctx, cancel := context.WithCancel(testCtx(t))
	go svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) { echoOnce(t, ctx, s) }))
	t.Cleanup(func() { cancel(); svc.Close() })
	w.lookupLinked(t, svc.ID(), 2)

	time.Sleep(24 * time.Second)
	d := w.lookupLinked(t, svc.ID(), 2)
	conn, err := ps.Dial(ctx, w.net, d, "alice", poll)
	require.NoError(t, err, "the routers still hold the links")
	require.NoError(t, conn.Send(ctx, []byte("hi")))
	got, err := conn.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, "echo: hi", string(got))
}

// TestCloseWithdraws stops a service: the directory no longer lists it,
// while its links come back on the next start.
func TestCloseWithdraws(t *testing.T) {
	w := newWorld(t)
	svc := w.service(t, t.TempDir(), 4)
	ctx, cancel := context.WithCancel(testCtx(t))
	done := make(chan struct{})
	go func() { svc.Run(ctx, ps.HandlerFunc(func(context.Context, *ps.Session) {})); close(done) }()
	w.lookupLinked(t, svc.ID(), 2)
	cancel()
	<-done
	require.NoError(t, svc.Close())

	reader, err := discovery.NewClient(w.net, nil, poll)
	require.NoError(t, err)
	_, err = reader.Lookup(testCtx(t), svc.ID())
	var se *common.StatusError
	require.ErrorAs(t, err, &se)
	require.Equal(t, common.StatusUnknownService, se.Status)
}
