package interop

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/client"
	"github.com/katzenpost/pigeonhole_protocols/go/transport/thinclient"
)

// zuliprc is the [api] section of a zuliprc file.
type zuliprc struct{ email, key, site string }

func readZuliprc(t *testing.T, path string) zuliprc {
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	var rc zuliprc
	for _, l := range strings.Split(string(b), "\n") {
		k, v, _ := strings.Cut(l, "=")
		switch strings.TrimSpace(k) {
		case "email":
			rc.email = strings.TrimSpace(v)
		case "key":
			rc.key = strings.TrimSpace(v)
		case "site":
			rc.site = strings.TrimRight(strings.TrimSpace(v), "/")
		}
	}
	return rc
}

func (rc zuliprc) call(t *testing.T, method, path string, form url.Values) map[string]any {
	var req *http.Request
	var err error
	if method == http.MethodGet {
		req, err = http.NewRequest(method, rc.site+"/api/v1/"+path+"?"+form.Encode(), nil)
	} else {
		req, err = http.NewRequest(method, rc.site+"/api/v1/"+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	require.NoError(t, err)
	req.SetBasicAuth(rc.email, rc.key)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var v map[string]any
	require.NoError(t, json.Unmarshal(body, &v), "%s", body)
	require.Equal(t, "success", v["result"], "%s", body)
	return v
}

// TestZulipBridge runs the Rust bridge named by ZULIP_BRIDGE_BIN between a group on the mixnet
// and the Zulip stream ZULIP_STREAM ("general" by default), as the bot whose zuliprc is ZULIPRC;
// ZULIPRC_USER is a member of the stream who reads and writes it. SSL_CERT_FILE names the
// Zulip's certificate when it is self-signed.
func TestZulipBridge(t *testing.T) {
	bin, botRC, userRC := os.Getenv("ZULIP_BRIDGE_BIN"), os.Getenv("ZULIPRC"), os.Getenv("ZULIPRC_USER")
	if bin == "" || botRC == "" || userRC == "" {
		t.Skip("set ZULIP_BRIDGE_BIN, ZULIPRC and ZULIPRC_USER")
	}
	stream := os.Getenv("ZULIP_STREAM")
	if stream == "" {
		stream = "general"
	}
	zulip := readZuliprc(t, userRC)
	topic := fmt.Sprintf("bridge-test-%d", time.Now().Unix())
	n := newNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	t.Cleanup(cancel)

	data := filepath.Join(t.TempDir(), "bridge")
	cmd := exec.CommandContext(ctx, bin, "--daemon", n.daemon, "--data-dir", data, "--zuliprc", botRC,
		"--stream", stream, "--topic", topic, "--group", "bridge-test", "--vouchers", "1",
		"--poll-interval", fmt.Sprint(n.poll.Seconds()))
	cmd.Env = append(os.Environ(), "RUST_LOG=info")
	logFile, err := os.Create(filepath.Join(n.dir, "zulip-bridge.log"))
	require.NoError(t, err)
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
	})

	// Alice asks to join the group with her own chat client.
	be, err := thinclient.Dial(n.daemon, filepath.Join(n.dir, "alice-thin.log"))
	require.NoError(t, err)
	t.Cleanup(func() { be.Close() })
	alice, err := client.Open(ctx, client.Config{StateDir: filepath.Join(t.TempDir(), "alice"), Name: "alice", Backend: be, EpochPoll: n.poll})
	require.NoError(t, err)
	t.Cleanup(func() { alice.Close() })
	ag, err := alice.Join("bridge-test")
	require.NoError(t, err)
	var code string
	for code == "" {
		require.NoError(t, ctx.Err(), "alice never minted her voucher")
		v, err := alice.Chat(ag)
		require.NoError(t, err)
		code = v.Code
		time.Sleep(n.poll)
	}

	// She pastes the bot's voucher into a new conversation and sends it her code.
	var svcCode string
	for svcCode == "" {
		require.NoError(t, ctx.Err(), "the bridge never wrote a voucher")
		files, _ := filepath.Glob(filepath.Join(data, "vouchers", "*.txt"))
		if len(files) > 0 {
			b, err := os.ReadFile(files[0])
			require.NoError(t, err)
			svcCode = strings.TrimSpace(string(b))
		}
		time.Sleep(n.poll)
	}
	voucher, err := base64.StdEncoding.DecodeString(svcCode)
	require.NoError(t, err)
	user, err := voucher_router.Induct(ctx, n.pigeonhole(), voucher, "alice", n.poll)
	require.NoError(t, err)
	require.Contains(t, chatRecv(t, ctx, user), `bridges the group "bridge-test"`)
	require.NoError(t, user.Send(ctx, chatText(t, code)))
	require.Contains(t, chatRecv(t, ctx, user), "Inviting you")
	for {
		require.NoError(t, ctx.Err(), "alice never joined")
		v, err := alice.Chat(ag)
		require.NoError(t, err)
		if v.Joined {
			break
		}
		time.Sleep(n.poll)
	}
	t.Log("alice joined through the bridge's voucher")

	// What she says in the group is posted in the stream's topic.
	require.NoError(t, alice.Send(ag, "hello from the mixnet"))
	narrow, _ := json.Marshal([]map[string]string{{"operator": "stream", "operand": stream}, {"operator": "topic", "operand": topic}})
	for {
		require.NoError(t, ctx.Err(), "zulip never got alice's message")
		v := zulip.call(t, http.MethodGet, "messages", url.Values{
			"anchor": {"newest"}, "num_before": {"20"}, "num_after": {"0"}, "narrow": {string(narrow)}, "apply_markdown": {"false"},
		})
		var found bool
		for _, m := range v["messages"].([]any) {
			found = found || m.(map[string]any)["content"] == "**alice**: hello from the mixnet"
		}
		if found {
			break
		}
		time.Sleep(time.Second)
	}
	t.Log("the group's message reached zulip")

	// What the stream says in the topic is said in the group.
	zulip.call(t, http.MethodPost, "messages", url.Values{"type": {"stream"}, "to": {stream}, "topic": {topic}, "content": {"hello from zulip"}})
	for {
		require.NoError(t, ctx.Err(), "the group never got zulip's message")
		lines, err := alice.Lines(ag, -1)
		require.NoError(t, err)
		var found bool
		for _, l := range lines {
			found = found || (l.From == "zulip" && l.Text == "Alice: hello from zulip")
		}
		if found {
			break
		}
		time.Sleep(n.poll)
	}
	t.Log("zulip's message reached the group")
}
