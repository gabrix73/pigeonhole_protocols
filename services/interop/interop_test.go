// Package interop runs the services against a real client daemon, real
// couriers and storage replicas, and the Go voucher router and service
// directory: all in one process with katzenpost's localnet, or on a running
// mixnet such as the docker testnet when THIN_CONFIG names its thin client
// config.
package interop

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/nike/pem"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonservice/discovery"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
	client "github.com/katzenpost/pigeonhole_protocols/clients/motd"
	ps "github.com/katzenpost/pigeonhole_protocols/pigeonservice"
	"github.com/katzenpost/pigeonhole_protocols/services/motd"
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

// TestEliza runs the Rust Eliza binary named by ELIZA_BIN.
func TestEliza(t *testing.T) {
	bin := os.Getenv("ELIZA_BIN")
	if bin == "" {
		t.Skip("set ELIZA_BIN to the eliza binary")
	}
	n := newNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	t.Cleanup(cancel)

	data := filepath.Join(t.TempDir(), "eliza")
	cmd := exec.CommandContext(ctx, bin, "--daemon", n.daemon, "--data-dir", data, "--vouchers", "1", "--poll-interval", fmt.Sprint(n.poll.Seconds()))
	cmd.Env = append(os.Environ(), "RUST_LOG=info")
	logFile, err := os.Create(filepath.Join(n.dir, "eliza.log"))
	require.NoError(t, err)
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
	})
	var id common.ServiceID
	for {
		require.NoError(t, ctx.Err(), "eliza never wrote its public key")
		if pub, err := pem.FromPublicPEMFile(filepath.Join(data, "eliza.public.pem"), common.DefaultNIKE); err == nil {
			id = common.IDFromPublicKey(pub.Bytes())
			break
		}
		time.Sleep(n.poll)
	}
	t.Logf("eliza is %x", id[:8])

	ph := n.pigeonhole()

	// As katzenqt does: take a voucher from the bot and induct it.
	var code string
	for code == "" {
		require.NoError(t, ctx.Err(), "eliza never wrote a voucher")
		files, _ := filepath.Glob(filepath.Join(data, "vouchers", "*.txt"))
		if len(files) > 0 {
			b, err := os.ReadFile(files[0])
			require.NoError(t, err)
			code = strings.TrimSpace(string(b))
		}
		time.Sleep(n.poll)
	}
	voucher, err := base64.StdEncoding.DecodeString(code)
	require.NoError(t, err)
	user, err := voucher_router.Induct(ctx, ph, voucher, "alice", n.poll)
	require.NoError(t, err)
	require.Equal(t, "How do you do. Please tell me your problem.", chatRecv(t, ctx, user))
	require.NoError(t, user.Send(ctx, chatText(t, "I am sad")))
	require.Equal(t, "I am sorry to hear that you are sad.", chatRecv(t, ctx, user))
	t.Log("chatted through an offered voucher")

	// Through the Go router: the Rust service registered with it and
	// advertised itself in the Go directory, both under MACs the Go
	// plugins check, and opens the voucher the client sealed.
	d := lookupLinked(t, ctx, n, ph, id)
	conn, err := ps.Dial(ctx, ph, d, "bob", n.poll)
	require.NoError(t, err)
	require.Equal(t, "How do you do. Please tell me your problem.", chatRecv(t, ctx, conn))
	require.NoError(t, conn.Send(ctx, chatText(t, "you are kind")))
	require.Equal(t, "What makes you think I am kind?", chatRecv(t, ctx, conn))
	t.Log("chatted through the router")
}
