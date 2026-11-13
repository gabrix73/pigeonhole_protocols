package interop

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/localnet"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
)

// network is where a test runs: katzenpost's localnet, with the Go router and directory in the
// test process, or, when THIN_CONFIG names a thin client config, a running mixnet such as the
// docker testnet, whose service nodes run the router and directory plugins.
type network struct {
	// thin connects a new thin client to the daemon.
	thin func() *thin.ThinClient
	// daemon is the daemon's address, as eliza's --daemon takes it.
	daemon string
	// dir holds the test's logs.
	dir  string
	log  *log.Backend
	poll time.Duration
	// timeout bounds one test.
	timeout time.Duration
}

func (n *network) pigeonhole() common.Pigeonhole { return common.NewThinPigeonhole(n.thin()) }

// shared is the one network TestInterop builds for all its subtests: a localnet costs a
// minute or more of CTIDH keys and consensus, so the tests share it rather than each making one.
var shared *network

func newNetwork(t *testing.T) *network {
	if shared != nil {
		return shared
	}
	if testing.Short() {
		t.Skip("needs a mixnet: localnet's real CTIDH replicas or a running testnet; minutes")
	}
	if path := os.Getenv("THIN_CONFIG"); path != "" {
		return mixnet(t, path)
	}
	return localnetWorld(t)
}

// mixnet connects to the running mixnet whose thin client config is at path.
func mixnet(t *testing.T, path string) *network {
	cfg, err := thin.LoadFile(path)
	require.NoError(t, err)
	var daemon string
	switch {
	case cfg.Dial.Tcp != nil:
		daemon = cfg.Dial.Tcp.Address
	case cfg.Dial.Unix != nil:
		daemon = cfg.Dial.Unix.Address
	default:
		t.Fatalf("%s: eliza dials only TCP or unix sockets", path)
	}
	dir := t.TempDir()
	logBackend, err := log.New(filepath.Join(dir, "test.log"), "INFO", false)
	require.NoError(t, err)
	n := &network{daemon: daemon, dir: dir, log: logBackend, poll: time.Second, timeout: 45 * time.Minute}
	var clients []*thin.ThinClient
	var mu sync.Mutex
	n.thin = func() *thin.ThinClient {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for {
			c := thin.NewThinClient(cfg, &config.Logging{File: filepath.Join(dir, "thin.log"), Level: "INFO"})
			err := c.Dial()
			if err == nil && c.IsConnected() {
				mu.Lock()
				clients = append(clients, c)
				mu.Unlock()
				return c
			}
			if err == nil {
				c.Close()
			}
			select {
			case <-ctx.Done():
				require.NoError(t, err, "the thin client did not connect to %s", daemon)
				require.Fail(t, "the daemon is not connected to the mixnet")
			case <-time.After(time.Second):
			}
		}
	}
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range clients {
			c.Close()
		}
	})
	return n
}

// localnetWorld is a localnet with storage, a voucher router and a directory.
func localnetWorld(t *testing.T) *network {
	n := localnet.New(t)
	n.AddStorage(3)
	routerKey, dirKey := pluginKey(t), pluginKey(t)
	var r *voucher_router.Router
	var d *discovery.Directory
	var ready sync.WaitGroup
	ready.Add(1)
	n.AddHandler(voucher_router.RouterCapability, common.PluginParams(routerKey), func(p []byte) []byte {
		ready.Wait()
		return r.Handle(p)
	})
	n.AddHandler(discovery.DirectoryCapability, common.PluginParams(dirKey), func(p []byte) []byte {
		ready.Wait()
		return d.Handle(p)
	})
	n.AddHandler(keepAliveCapability, nil, bytes.Clone)
	n.Start()
	keepAlive(t, n.ThinClient())
	var err error
	r, err = voucher_router.New(voucher_router.Config{
		Key: routerKey, DBPath: filepath.Join(t.TempDir(), "router.db"),
		PollInterval: localPoll, Retention: time.Hour, Log: n.Log.GetLogger("router"),
	}, common.NewThinPigeonhole(n.ThinClient()))
	require.NoError(t, err)
	t.Cleanup(func() { r.Close() })
	d, err = discovery.New(discovery.Config{
		Key: dirKey, DBPath: filepath.Join(t.TempDir(), "directory.db"),
		RefreshInterval: time.Hour, Log: n.Log.GetLogger("directory"),
	}, common.NewThinPigeonhole(n.ThinClient()))
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	ready.Done()
	return &network{
		thin: n.ThinClient, daemon: filepath.Join(n.Dir(), "kpclientd.sock"),
		dir: n.Dir(), log: n.Log, poll: localPoll, timeout: 20 * time.Minute,
	}
}

const keepAliveCapability = "keepalive"

// keepAlive echoes through localnet's gateway every few seconds until the test ends. A real
// gateway sends the daemon a NoOp now and then; localnet's sends nothing on an idle link, and
// the daemon drops a link silent for 15s and cannot redial it, since localnet's consensus
// gives the gateway a placeholder address (tcp://127.0.0.1:1). A client queueing several EncryptReads, each seconds of CTIDH
// on a slow runner, is that silent (kp-fa's tune-in), and every read after it hangs.
func keepAlive(t *testing.T, c *thin.ThinClient) {
	svc, err := c.GetService(keepAliveCapability)
	require.NoError(t, err)
	node := hash.Sum256(svc.MixDescriptor.IdentityKey)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			echo, stop := context.WithTimeout(ctx, 10*time.Second)
			_, _ = c.BlockingSendMessage(echo, []byte(keepAliveCapability), &node, svc.RecipientQueueID)
			stop()
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
}

// TestInterop runs every interop test on one network.
func TestInterop(t *testing.T) {
	shared = newNetwork(t)
	t.Cleanup(func() { shared = nil })
	t.Run("Directory", testDirectory)
	t.Run("Router", testRouter)
	t.Run("StatusBot", testStatusBot)
	t.Run("ZulipBridge", testZulipBridge)
	t.Run("PigeonholeCp", testPigeonholeCp)
	t.Run("KpFa", testKpFa)
}
