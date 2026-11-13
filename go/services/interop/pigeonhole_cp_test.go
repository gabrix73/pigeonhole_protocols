package interop

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// testPigeonholeCp round-trips a file through the Rust pigeonhole-cp named by
// PIGEONHOLE_CP_BIN, once through the courier's copy command and once a box at
// a time (--no-copy).
func testPigeonholeCp(t *testing.T) {
	bin := os.Getenv("PIGEONHOLE_CP_BIN")
	if bin == "" {
		t.Skip("set PIGEONHOLE_CP_BIN to the pigeonhole-cp binary")
	}
	n := newNetwork(t)
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	t.Cleanup(cancel)

	work := t.TempDir()
	config := thinConfig(t, n, work)

	run := func(args ...string) string {
		cmd := exec.CommandContext(ctx, bin, args...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		require.NoError(t, err, "pigeonhole-cp %s: %s", args[0], stderr.String())
		return string(out)
	}

	for _, mode := range []struct {
		label string
		flags []string
	}{{"copy", nil}, {"direct", []string{"--no-copy"}}} {
		// Three boxes at the mixnet's 1553-byte payload: the first carries the CBOR header too.
		input := make([]byte, 4096)
		_, err := rand.Read(input)
		require.NoError(t, err)
		inPath := filepath.Join(work, mode.label+"-input.bin")
		require.NoError(t, os.WriteFile(inPath, input, 0o600))

		lines := strings.Split(run("genkey", "-c", config), "\n")
		after := func(heading string) string {
			for i, l := range lines {
				if strings.HasPrefix(l, heading) && i+1 < len(lines) {
					return strings.TrimSpace(lines[i+1])
				}
			}
			t.Fatalf("genkey printed no %s", heading)
			return ""
		}
		readCap, writeCap, index := after("Read Capability"), after("Write Capability"), after("First Index")

		t.Logf("[%s] %s", mode.label, strings.TrimSpace(run(append([]string{"send", "-c", config, "-w", writeCap, "-i", index, "-f", inPath}, mode.flags...)...)))

		dest := filepath.Join(work, mode.label+"-dest")
		require.NoError(t, os.Mkdir(dest, 0o700))
		t.Logf("[%s] %s", mode.label, strings.TrimSpace(run("receive", "-c", config, "-r", readCap, "-i", index, "-d", dest)))

		entries, err := os.ReadDir(dest)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		require.Equal(t, mode.label+"-input.bin", entries[0].Name())
		got, err := os.ReadFile(filepath.Join(dest, entries[0].Name()))
		require.NoError(t, err)
		require.Equal(t, input, got, "[%s] the file came back changed", mode.label)
	}
}

// thinConfig writes a thin client config in dir that dials n's daemon, and returns its path.
func thinConfig(t *testing.T, n *network, dir string) string {
	config := filepath.Join(dir, "thinclient.toml")
	dial := fmt.Sprintf("[Dial]\n  [Dial.Tcp]\n    Address = %q\n    Network = \"tcp\"\n", n.daemon)
	if strings.HasPrefix(n.daemon, "/") || strings.HasPrefix(n.daemon, "@") {
		dial = fmt.Sprintf("[Dial]\n  [Dial.Unix]\n    Address = %q\n", n.daemon)
	}
	require.NoError(t, os.WriteFile(config, []byte(dial), 0o600))
	return config
}
