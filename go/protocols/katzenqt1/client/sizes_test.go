package client

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/transport"
	"github.com/katzenpost/pigeonhole_protocols/go/transport/sim"
)

// reads says whether c has text and the file called file holding data.
func reads(t *testing.T, c *Client, id engine.ChatID, text, file string, data []byte) bool {
	ls, err := c.Lines(id, -1)
	if err != nil {
		t.Fatal(err)
	}
	var said, got bool
	for _, l := range ls {
		said = said || l.Text == text
		if a := l.Attachment; a != nil && a.Name == file {
			if p, err := c.FilePath(a); err == nil {
				b, _ := os.ReadFile(p)
				got = bytes.Equal(b, data)
			}
		}
	}
	return said && got
}

// TestGroupAcrossBoxSizes: a member on a mesh writes boxes of the mesh size, one on the mixnet of
// the mixnet's, and each reads the other's long message and file: substreams cut to either size.
func TestGroupAcrossBoxSizes(t *testing.T) {
	w := sim.NewWorld()
	mesh, mixnet := transport.BoxSizes["mesh"], transport.BoxSizes["mixnet"]
	openSized := func(name string, size int) *Client {
		c, err := Open(context.Background(), Config{StateDir: t.TempDir(), Name: name, Backend: sim.Backend{World: w, Size: size}, EpochPoll: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	alice, bob := openSized("alice", mesh), openSized("bob", mixnet)
	defer alice.Close()
	defer bob.Close()
	g, err := alice.Create("g")
	if err != nil {
		t.Fatal(err)
	}
	bg, err := bob.Join("g")
	if err != nil {
		t.Fatal(err)
	}
	var code string
	waitFor(t, "a voucher code and alice's group", func() bool {
		v, _ := bob.Chat(bg)
		a, _ := alice.Chat(g)
		code = v.Code
		return code != "" && a.Joined
	})
	if err := alice.Invite(g, code); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bob to join", func() bool { v, _ := bob.Chat(bg); return v.Joined })
	before := len(w.Plaintexts())
	text := strings.Repeat("a long message ", 100)
	data := bytesOf(5000, 1)
	for _, s := range []struct {
		c  *Client
		id engine.ChatID
		f  string
	}{{alice, g, "alice.bin"}, {bob, bg, "bob.bin"}} {
		if err := s.c.Send(s.id, text); err != nil {
			t.Fatal(err)
		}
		if err := s.c.SendFile(s.id, s.f, data); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "each to read the other's text and file", func() bool {
		return reads(t, bob, bg, text, "alice.bin", data) && reads(t, alice, g, text, "bob.bin", data)
	})
	all := w.Plaintexts()
	atMesh, larger := 0, 0
	for _, p := range all {
		switch {
		case len(p) == mesh:
			atMesh++
		case len(p) > mesh:
			larger++
		}
	}
	if len(all)-before <= 20 || atMesh <= 15 || larger == 0 {
		t.Fatalf("%d boxes after joining, %d of the mesh size, %d larger", len(all)-before, atMesh, larger)
	}
}
