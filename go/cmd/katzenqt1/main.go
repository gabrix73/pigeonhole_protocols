// Command katzenqt1 is a katzenqt1 group chat client without a user interface: it takes
// commands one per line on its input and prints what happens, for scripts and interop tests.
//
//	create G | join G | invite G CODE | send G TEXT... | sendfile G PATH | scan G
//	remove G WHO | leave G | rename G TO | chats | show G | members G
//	wait G TEXT... (until a line says it, for up to -wait) | quit
//
// It prints READY once started, VOUCHER=code when a voucher to join with is minted, JOINED G
// when a group is joined, LINE G FROM: TEXT for each line that arrives, and OK and the command
// once a command is done: saved, so that it survives the process stopping.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/client"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
	"github.com/katzenpost/pigeonhole_protocols/go/transport"
	"github.com/katzenpost/pigeonhole_protocols/go/transport/remote"
	"github.com/katzenpost/pigeonhole_protocols/go/transport/thinclient"
)

var out sync.Mutex

func say(format string, a ...any) {
	out.Lock()
	defer out.Unlock()
	fmt.Printf(format+"\n", a...)
}

func main() {
	stateDir := flag.String("state", "katzenqt1-state", "the state directory")
	name := flag.String("name", os.Getenv("USER"), "our display name")
	daemon := flag.String("daemon", "@katzenpost", "the client daemon: @name, a socket path, or host:port")
	simSock := flag.String("sim", "", "a pigeonhole-sim socket to use instead of the daemon")
	logFile := flag.String("log", "", "the thin client's log file")
	wait := flag.Duration("wait", 30*time.Minute, "how long wait waits")
	wireVersion := flag.Uint64("wire-version", wire.CurrentVersion, "the wire version written and vouchers minted in: 3 for clients that read only maps, 4 for those that read only version 4, 5 packs messages")
	flag.Parse()

	var backend transport.Backend
	if *simSock != "" {
		r, err := remote.Dial("unix", *simSock)
		if err != nil {
			log.Fatal(err)
		}
		defer r.Close()
		backend = r
	} else {
		t, err := thinclient.Dial(*daemon, *logFile)
		if err != nil {
			log.Fatal(err)
		}
		defer t.Close()
		backend = t
	}
	c, err := client.Open(context.Background(), client.Config{StateDir: *stateDir, Name: *name, Backend: backend, WireVersion: *wireVersion})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	go watch(c)
	say("READY")

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 {
			continue
		}
		if f[0] == "quit" {
			return
		}
		if err := command(c, f, *wait); err != nil {
			say("ERROR %s: %v", f[0], err)
		} else {
			say("OK %s", strings.Join(f, " "))
		}
	}
}

func chatNamed(c *client.Client, name string) (engine.ChatID, error) {
	chats, err := c.Chats()
	if err != nil {
		return "", err
	}
	for _, ch := range chats {
		if ch.Name == name {
			return ch.ID, nil
		}
	}
	return "", client.ErrNoSuchChat
}

func command(c *client.Client, f []string, wait time.Duration) error {
	need := func(n int) error {
		if len(f) < n {
			return fmt.Errorf("needs %d arguments", n-1)
		}
		return nil
	}
	if f[0] == "chats" {
		chats, err := c.Chats()
		for _, ch := range chats {
			say("CHAT %s joined=%v members=%d unsent=%d", ch.Name, ch.Joined, len(ch.Members), ch.Unsent)
		}
		return err
	}
	if err := need(2); err != nil {
		return err
	}
	switch f[0] {
	case "create":
		_, err := c.Create(f[1])
		return err
	case "join":
		_, err := c.Join(f[1])
		return err
	}
	id, err := chatNamed(c, f[1])
	if err != nil {
		return err
	}
	switch f[0] {
	case "invite":
		if err := need(3); err != nil {
			return err
		}
		return c.Invite(id, f[2])
	case "send":
		return c.Send(id, strings.Join(f[2:], " "))
	case "sendfile":
		if err := need(3); err != nil {
			return err
		}
		b, err := os.ReadFile(f[2])
		if err != nil {
			return err
		}
		return c.SendFile(id, f[2], b)
	case "scan":
		return c.Scan(id)
	case "remove":
		if err := need(3); err != nil {
			return err
		}
		k, err := c.MemberNamed(id, f[2])
		if err != nil {
			return err
		}
		return c.Remove(id, k)
	case "leave":
		return c.Leave(id)
	case "rename":
		if err := need(3); err != nil {
			return err
		}
		return c.Rename(id, f[2])
	case "show":
		ls, err := c.Lines(id, -1)
		for _, l := range ls {
			say("%s", show(l))
		}
		return err
	case "members":
		v, err := c.Chat(id)
		var names []string
		for _, m := range v.Members {
			names = append(names, m.Name)
		}
		say("MEMBERS %s", strings.Join(names, " "))
		return err
	case "wait":
		text := strings.Join(f[2:], " ")
		for deadline := time.Now().Add(wait); time.Now().Before(deadline); time.Sleep(time.Second) {
			ls, err := c.Lines(id, -1)
			if err != nil {
				return err
			}
			for _, l := range ls {
				if l.Notice == nil && !l.Mine && l.Text == text {
					say("FOUND %s", text)
					return nil
				}
			}
		}
		say("TIMEOUT %s", text)
		return nil
	}
	return fmt.Errorf("unknown command")
}

func show(l client.LineView) string {
	if l.Notice != nil {
		return "— " + engine.Plain(l.Notice)
	}
	mark := ""
	switch {
	case l.Mine && l.Status == engine.Pending:
		mark = " …"
	case l.Mine && l.Acked:
		mark = " ✓✓"
	case l.Mine:
		mark = " ✓"
	}
	return l.From + mark + ": " + l.Text
}

// watch prints what arrives.
func watch(c *client.Client) {
	seen := map[engine.ChatID]int{}
	joined := map[engine.ChatID]bool{}
	code := map[engine.ChatID]string{}
	for e := range c.Subscribe() {
		if e.Err != nil {
			say("STOPPED %v", e.Err)
			return
		}
		if e.Removed {
			continue
		}
		v, err := c.Chat(e.Chat)
		if err != nil {
			continue
		}
		if v.Code != "" && code[e.Chat] != v.Code {
			code[e.Chat] = v.Code
			say("VOUCHER=%s", v.Code)
		}
		if v.Joined && !joined[e.Chat] {
			joined[e.Chat] = true
			say("JOINED %s", v.Name)
		}
		last, ok := seen[e.Chat]
		if !ok {
			last = -1
		}
		ls, _ := c.Lines(e.Chat, last)
		for _, l := range ls {
			seen[e.Chat] = l.ID
			if l.Notice == nil && !l.Mine {
				say("LINE %s %s: %s", v.Name, l.From, l.Text)
			}
		}
	}
}
