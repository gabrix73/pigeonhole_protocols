// Command chat is a minimal katzenqt1 group chat: one member, talking to a Katzenpost client
// daemon, or to pigeonhole-sim for trying it on one machine.
//
//	go run ./examples/go/chat -name alice -state alice
//	go run ./examples/go/chat -name alice -state alice -sim pigeonhole.sock
//
// Anything typed is said in the current group. Commands:
//
//	/create GROUP   found a group
//	/join GROUP     ask to join a group: prints a voucher code to give one of its members
//	/invite CODE    add the member whose voucher code this is to the current group
//	/file PATH      send a file to the current group
//	/to GROUP       make GROUP the current group
//	/groups         list the groups
//	/quit
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/client"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/transport"
	"github.com/katzenpost/pigeonhole_protocols/go/transport/remote"
	"github.com/katzenpost/pigeonhole_protocols/go/transport/thinclient"
)

func main() {
	name := flag.String("name", os.Getenv("USER"), "our name, as the group sees it")
	state := flag.String("state", "chat-state", "where our groups are kept")
	daemon := flag.String("daemon", "@katzenpost", "the client daemon: @name, a socket path, or host:port")
	sim := flag.String("sim", "", "a pigeonhole-sim socket to use instead of the daemon")
	flag.Parse()

	// The backend is Pigeonhole: the mixnet through the client daemon, or an imitation of it.
	var backend transport.Backend
	if *sim != "" {
		r, err := remote.Dial("unix", *sim)
		if err != nil {
			log.Fatal(err)
		}
		defer r.Close()
		backend = r
	} else {
		t, err := thinclient.Dial(*daemon, "")
		if err != nil {
			log.Fatal(err)
		}
		defer t.Close()
		backend = t
	}

	// Open loads what is in the state directory and carries on with anything left under way.
	c, err := client.Open(context.Background(), client.Config{StateDir: *state, Name: *name, Backend: backend})
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	// Subscribe before showing anything, so that no change falls between the two.
	events := c.Subscribe()
	v := newView(c)
	go v.follow(events)

	// The current group is the one last made, to begin with.
	var current engine.ChatID
	if chats, _ := c.Chats(); len(chats) > 0 {
		current = chats[len(chats)-1].ID
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			if current == "" {
				fmt.Println("no group yet: /create one, or /join one")
				continue
			}
			report(c.Send(current, line))
			continue
		}
		cmd, arg, _ := strings.Cut(line[1:], " ")
		switch cmd {
		case "create", "join":
			start := c.Create
			if cmd == "join" {
				start = c.Join
			}
			if id, err := start(arg); err == nil {
				current = id
			} else {
				report(err)
			}
		case "invite":
			report(c.Invite(current, arg))
		case "file":
			b, err := os.ReadFile(arg)
			if err == nil {
				err = c.SendFile(current, filepath.Base(arg), b)
			}
			report(err)
		case "to":
			if id, ok := groupNamed(c, arg); ok {
				current = id
			} else {
				fmt.Println("no group called", arg)
			}
		case "groups":
			chats, _ := c.Chats()
			for _, ch := range chats {
				var names []string
				for _, m := range ch.Members {
					names = append(names, m.Name)
				}
				fmt.Printf("%s: joined %v, with %s\n", ch.Name, ch.Joined, strings.Join(names, ", "))
			}
		case "quit":
			return
		default:
			fmt.Println("unknown command", cmd)
		}
	}
}

// report prints what went wrong with a command. A command that returns nil has been saved to
// disk; it goes out over the network after, in the background.
func report(err error) {
	if err != nil {
		fmt.Println("error:", err)
	}
}

func groupNamed(c *client.Client, name string) (engine.ChatID, bool) {
	chats, _ := c.Chats()
	for _, ch := range chats {
		if ch.Name == name {
			return ch.ID, true
		}
	}
	return "", false
}

// view prints each group's lines as they arrive.
type view struct {
	c *client.Client
	// shown is the last line printed, for each group.
	shown map[engine.ChatID]int
	// unread are our messages not yet acknowledged, for each group.
	unread map[engine.ChatID]map[int]bool
	// codes are the groups whose voucher code has been printed.
	codes map[engine.ChatID]bool
}

func newView(c *client.Client) *view {
	v := &view{c, map[engine.ChatID]int{}, map[engine.ChatID]map[int]bool{}, map[engine.ChatID]bool{}}
	chats, _ := c.Chats()
	for _, ch := range chats {
		v.update(ch.ID)
	}
	return v
}

func (v *view) follow(events <-chan client.Event) {
	for e := range events {
		if e.Err != nil {
			// The client stops rather than send anything it could not save first.
			log.Fatal("the client stopped: ", e.Err)
		}
		if !e.Removed {
			v.update(e.Chat)
		}
	}
}

// update prints a group's new lines, and which of our messages have come to be read.
func (v *view) update(id engine.ChatID) {
	ch, err := v.c.Chat(id)
	if err != nil {
		return
	}
	// While joining, the group's view holds the voucher code to hand to a member.
	if ch.Code != "" && !v.codes[id] {
		v.codes[id] = true
		fmt.Printf("[%s] give this voucher code to a member of %s: %s\n", ch.Name, ch.Name, ch.Code)
	}
	if _, ok := v.shown[id]; !ok {
		v.shown[id] = -1
		v.unread[id] = map[int]bool{}
	}
	// Read from the oldest line that can have changed: the first new one, or the first of ours
	// still unread. A member acknowledges what it read in the next message it sends.
	after := v.shown[id]
	for l := range v.unread[id] {
		after = min(after, l-1)
	}
	lines, err := v.c.Lines(id, after)
	if err != nil {
		return
	}
	for _, l := range lines {
		if l.ID > v.shown[id] {
			v.shown[id] = l.ID
			fmt.Printf("[%s] %s\n", ch.Name, show(v.c, l))
			if l.Mine && !l.Acked {
				v.unread[id][l.ID] = true
			}
		} else if v.unread[id][l.ID] && l.Acked {
			delete(v.unread[id], l.ID)
			fmt.Printf("[%s] ✓✓ read: %s\n", ch.Name, l.Text)
		}
	}
}

func show(c *client.Client, l client.LineView) string {
	if l.Notice != nil {
		return "— " + engine.Plain(l.Notice)
	}
	s := l.From + ": " + l.Text
	if l.Mine && l.Acked {
		s = l.From + " ✓✓: " + l.Text
	}
	if a := l.Attachment; a != nil && !l.Mine {
		if path, err := c.FilePath(a); err == nil {
			s += " → " + path
		}
	}
	return s
}
