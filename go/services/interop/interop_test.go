// Package interop runs the services against a real client daemon, real
// couriers and storage replicas, and the Go voucher router and service
// directory: all in one process with katzenpost's localnet, or on a running
// mixnet such as the docker testnet when THIN_CONFIG names its thin client
// config.
package interop

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/nike/pem"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonservice/discovery"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
	client "github.com/katzenpost/pigeonhole_protocols/go/clients/motd"
	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
	"github.com/katzenpost/pigeonhole_protocols/go/services/motd"
)

// localPoll is the poll interval on localnet, which answers at once.
const localPoll = 200 * time.Millisecond

func pluginKey(t *testing.T) *common.PluginKey {
	pub, priv, err := common.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	return &common.PluginKey{Scheme: common.DefaultNIKE, Public: pub, Private: priv}
}

func lookupLinked(t *testing.T, ctx context.Context, n *network, ph common.Pigeonhole, id common.ServiceID) *common.ServiceDescriptor {
	reader, err := discovery.NewAll(ph, nil, n.poll)
	require.NoError(t, err)
	for {
		d, err := reader.Lookup(ctx, id)
		if err == nil && len(d.Routers) > 0 {
			return d
		}
		require.NoError(t, ctx.Err(), "the directory never listed the service")
		time.Sleep(n.poll)
	}
}

func TestMOTD(t *testing.T) {
	n := newNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	t.Cleanup(cancel)

	ph := n.pigeonhole()
	dataDir := t.TempDir()
	key, err := common.LoadServiceKey(dataDir)
	require.NoError(t, err)
	adv, err := discovery.NewAll(ph, key, n.poll)
	require.NoError(t, err)
	svc, err := ps.NewService(ps.Config{
		Key: key, DataDir: dataDir, DisplayName: "motd", Advertiser: adv,
		PollInterval: n.poll, Log: n.log.GetLogger("motd"),
	}, ph)
	require.NoError(t, err)
	go svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
		_ = motd.Serve(ctx, s, func() (string, error) { return "hello from the mixnet", nil }, motd.SystemClock{})
	}))
	t.Cleanup(func() { cancel(); svc.Close() })

	clientPh := n.pigeonhole()
	d := lookupLinked(t, ctx, n, clientPh, svc.ID())
	conn, err := ps.Dial(ctx, clientPh, d, "client", n.poll)
	require.NoError(t, err)
	reply, err := client.Fetch(ctx, conn)
	require.NoError(t, err)
	require.Equal(t, "hello from the mixnet", reply.Message)
}

// The katzenqt chat framing: 'F' and a CBOR GroupChatMessage.
func chatText(t *testing.T, text string) []byte {
	b, err := cbor.Marshal(map[string]any{"version": 3, "membership_hash": make([]byte, 32), "msg_type": 0, "text": text})
	require.NoError(t, err)
	return append([]byte{'F'}, b...)
}

func chatRecv(t *testing.T, ctx context.Context, conn *voucher_router.Conn) string {
	raw, err := conn.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, byte('F'), raw[0])
	var m struct {
		Text string `cbor:"text"`
	}
	require.NoError(t, cbor.Unmarshal(raw[1:], &m))
	return m.Text
}

// TestStatusBot runs the Rust status bot named by STATUS_BOT_BIN. It hands out no vouchers:
// the only way in is through the directory and a router.
func TestStatusBot(t *testing.T) {
	bin := os.Getenv("STATUS_BOT_BIN")
	if bin == "" {
		t.Skip("set STATUS_BOT_BIN to the status bot binary")
	}
	n := newNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	t.Cleanup(cancel)

	data := filepath.Join(t.TempDir(), "status")
	cmd := exec.CommandContext(ctx, bin, "--daemon", n.daemon, "--data-dir", data, "--poll-interval", fmt.Sprint(n.poll.Seconds()), "--check-interval", "5")
	cmd.Env = append(os.Environ(), "RUST_LOG=info")
	logFile, err := os.Create(filepath.Join(n.dir, "status-bot.log"))
	require.NoError(t, err)
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
	})
	var id common.ServiceID
	for {
		require.NoError(t, ctx.Err(), "the status bot never wrote its public key")
		if pub, err := pem.FromPublicPEMFile(filepath.Join(data, "status.public.pem"), common.DefaultNIKE); err == nil {
			id = common.IDFromPublicKey(pub.Bytes())
			break
		}
		time.Sleep(n.poll)
	}
	t.Logf("the status bot is %x", id[:8])
	require.NoDirExists(t, filepath.Join(data, "vouchers"), "the status bot hands out no vouchers")

	ph := n.pigeonhole()

	// Through the Go router: the Rust service registered with it and advertised itself in the
	// Go directory, and opens the voucher the client sealed.
	d := lookupLinked(t, ctx, n, ph, id)
	conn, err := ps.Dial(ctx, ph, d, "bob", n.poll)
	require.NoError(t, err)
	require.Contains(t, chatRecv(t, ctx, conn), "This is the status bot.")
	require.NoError(t, conn.Send(ctx, chatText(t, "status")))
	report := chatRecv(t, ctx, conn)
	require.Regexp(t, `^epoch \d+\n`, report)
	require.Contains(t, report, "pigeonhole services in the directory: ")
	require.Contains(t, report, "this bot: linked with ")
	t.Logf("report:\n%s", report)
	require.NoError(t, conn.Send(ctx, chatText(t, "you are kind")))
	require.Equal(t, "What makes you think I am kind?", chatRecv(t, ctx, conn))
	t.Log("the status bot reports, and Eliza still answers")
}
