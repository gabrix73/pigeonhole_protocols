package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLive runs two clients over the client daemon at $DAEMON, on a real mixnet: one founds a
// group, the other joins it with a voucher, and each reads what the other sends, then sees its
// own message acknowledged.
func TestLive(t *testing.T) {
	daemon := os.Getenv("DAEMON")
	if daemon == "" {
		t.Skip("DAEMON not set")
	}
	goBin := filepath.Join(t.TempDir(), "bin")
	os.Mkdir(goBin, 0o700)
	build(t, goBin)
	for _, p := range clients(t, goBin) {
		if pairs := os.Getenv("LIVE_PAIRS"); pairs != "" && !strings.Contains(pairs, label(p[0])+"-"+label(p[1])) {
			continue
		}
		t.Run(label(p[0])+"-"+label(p[1]), func(t *testing.T) { live(t, daemon, p[0], p[1]) })
	}
}

// TestConversationOverSim runs the live test's conversation over a Pigeonhole in a process of
// its own, with each pair of clients.
func TestConversationOverSim(t *testing.T) {
	goBin := filepath.Join(t.TempDir(), "bin")
	os.Mkdir(goBin, 0o700)
	build(t, goBin)
	for _, p := range clients(t, goBin) {
		t.Run(label(p[0])+"-"+label(p[1]), func(t *testing.T) {
			sock := filepath.Join(t.TempDir(), "sim.sock")
			sim := exec.Command(filepath.Join(goBin, "pigeonhole-sim"), "-socket", sock)
			if err := sim.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { sim.Process.Kill(); sim.Wait() }()
			for i := 0; i < 500; i++ {
				if _, err := os.Stat(sock); err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			conversation(t, []string{"-sim", sock}, p[0], p[1], 2*time.Minute)
		})
	}
}

func live(t *testing.T, daemon, aliceBin, bobBin string) {
	conversation(t, []string{"-daemon", daemon}, aliceBin, bobBin, 30*time.Minute)
}

func conversation(t *testing.T, via []string, aliceBin, bobBin string, long time.Duration) {
	dir := t.TempDir()
	run := func(bin, name string) *proc {
		args := append(append([]string{}, via...), "-state", filepath.Join(dir, name), "-name", name, "-wait", long.String())
		if label(bin) == "go" && via[0] == "-daemon" {
			args = append(args, "-log", filepath.Join(dir, name+".log"))
		}
		return startWith(t, bin, args...)
	}
	alice, bob := run(aliceBin, "alice"), run(bobBin, "bob")
	defer alice.kill()
	defer bob.kill()
	step := func(what string) { t.Logf("%s %s", time.Now().Format("15:04:05"), what) }
	alice.send("create g")
	alice.waitLong(t, long, func(l string) bool { return l == "JOINED g" })
	step("alice founded g")
	bob.send("join g")
	code := strings.TrimPrefix(bob.waitLong(t, long, func(l string) bool { return strings.HasPrefix(l, "VOUCHER=") }), "VOUCHER=")
	step("bob minted a voucher")
	alice.send("invite g " + code)
	bob.waitLong(t, long, func(l string) bool { return l == "JOINED g" })
	step("bob joined")
	alice.send("send g hello bob")
	bob.send("send g hello alice")
	bob.waitLong(t, long, func(l string) bool { return l == "LINE g alice: hello bob" })
	alice.waitLong(t, long, func(l string) bool { return l == "LINE g bob: hello alice" })
	step("each read the other")
	alice.send("send g read you")
	bob.send("send g read you too")
	alice.waitLong(t, long, func(l string) bool { return l == "LINE g bob: read you too" })
	bob.waitLong(t, long, func(l string) bool { return l == "LINE g alice: read you" })
	for deadline := time.Now().Add(long); ; time.Sleep(2 * time.Second) {
		alice.send("show g")
		bob.send("show g")
		time.Sleep(time.Second)
		if alice.has("me ✓✓: hello bob") && bob.has("me ✓✓: hello alice") {
			break
		}
		if time.Now().After(deadline) {
			alice.mu.Lock()
			bob.mu.Lock()
			t.Fatalf("no acknowledgements: alice %v, bob %v\nalice: %s\nbob: %s", alice.has("me ✓✓: hello bob"), bob.has("me ✓✓: hello alice"),
				strings.Join(alice.lines[max(0, len(alice.lines)-12):], " | "), strings.Join(bob.lines[max(0, len(bob.lines)-12):], " | "))
		}
	}
	step("each saw its first message acknowledged")
}
