package interop

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// testKpFa broadcasts kp-fa's three second clip and tunes in to it, from the start and then
// at the frontier of the ended stream; both get the clip's bytes back.
func testKpFa(t *testing.T) {
	n := newNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	t.Cleanup(cancel)

	work := t.TempDir()
	bin := filepath.Join(work, "kp-fa")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "../../cmd/kp-fa")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "go build kp-fa: %s", out)
	clip, err := os.ReadFile("../../cmd/kp-fa/testdata/poacher-e03-3s.opus")
	require.NoError(t, err)
	config := thinConfig(t, n, work)

	run := func(in []byte, args ...string) (stdout, stderr string) {
		cmd := exec.CommandContext(ctx, bin, append([]string{"-c", config}, args...)...)
		cmd.Stdin = bytes.NewReader(in)
		var o, e bytes.Buffer
		cmd.Stdout, cmd.Stderr = &o, &e
		require.NoError(t, cmd.Run(), "kp-fa %s: %s", args[0], e.String())
		return o.String(), e.String()
	}

	readCapFile := filepath.Join(work, "readcap")
	_, status := run(clip, "broadcast", "--readcap-file", readCapFile)
	require.Contains(t, status, "end of broadcast sent, off the air")
	raw, err := os.ReadFile(readCapFile)
	require.NoError(t, err)
	readCap := strings.TrimSpace(string(raw))

	got, status := run(nil, "tune-in", "--from-start", readCap)
	require.Equal(t, clip, []byte(got))
	require.Contains(t, status, "broadcast ended, signing off")

	got, status = run(nil, "tune-in", readCap)
	require.Contains(t, status, "ended true, starting at box 1")
	require.Equal(t, clip, []byte(got))
	require.Contains(t, status, "broadcast ended, signing off")
}
