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
	"regexp"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/nike/pem"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonservice/discovery"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
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

// The katzenqt chat framing: 'F' and a GroupChatMessage, written as the
// clients write it and read in either form.
func chatText(t *testing.T, text string) []byte {
	return wire.Frame(wire.TextContent(make([]byte, 32), text, wire.CurrentVersion))
}

var epochReport = regexp.MustCompile(`^epoch \d+\n`)

func chatRecv(t *testing.T, ctx context.Context, conn *voucher_router.Conn) string {
	raw, err := conn.Recv(ctx)
	require.NoError(t, err)
	require.Equal(t, byte('F'), raw[0])
	g := wire.DecodeGcm(raw[1:])
	require.NotNil(t, g)
	require.NotNil(t, g.Text)
	return *g.Text
}

// TestStatusBot runs the Rust status bot named by STATUS_BOT_BIN. It hands out no vouchers:
// the only way in is through the directory and a router.
func testStatusBot(t *testing.T) {
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
	require.Regexp(t, epochReport, report)
	require.Contains(t, report, "pigeonhole services in the directory: ")
	require.Contains(t, report, "this bot: linked with ")
	t.Logf("report:\n%s", report)
	require.NoError(t, conn.Send(ctx, chatText(t, "you are kind")))
	// The bot also sends the report on its own once its probes finish and on each new epoch, so
	// one can come before Eliza's answer: a status asked mid-probe gets "being probed" first.
	reply := chatRecv(t, ctx, conn)
	for epochReport.MatchString(reply) {
		reply = chatRecv(t, ctx, conn)
	}
	require.Equal(t, "What makes you think I am kind?", reply)
	t.Log("the status bot reports, and Eliza still answers")
}
