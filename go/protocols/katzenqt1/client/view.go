package client

import (
	"encoding/base64"
	"slices"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
)

func decodeCode(code string) ([]byte, error) { return base64.StdEncoding.DecodeString(code) }

type MemberView struct {
	Key  member.Key
	Name string
}

// ChatView is a group as an app shows it.
type ChatView struct {
	ID   engine.ChatID
	Name string
	// Joined says the group is ours to read and write.
	Joined bool
	// Me is our key in the group, once joined.
	Me member.Key
	// Code is the voucher code to hand a member of the group, while joining.
	Code string
	// Minting says a voucher is being made to join with.
	Minting bool
	// Adding says a member is being added.
	Adding bool
	// Members are those we read.
	Members []MemberView
	// Unsent is how many boxes are still to be written.
	Unsent int
}

// LineView is a line as an app shows it.
type LineView struct {
	engine.Line
	// Mine says we sent it.
	Mine bool
	// Acked says a member acknowledged it.
	Acked bool
	// From is its sender's name.
	From string
}

func viewOf(c *engine.Chat) ChatView {
	v := ChatView{ID: c.ID, Name: c.Name, Joined: c.Group != nil, Adding: c.Inducting != nil, Unsent: len(c.Jobs)}
	if j := c.Joining; j != nil {
		v.Code, v.Minting = j.Code, j.Code == ""
	}
	if g := c.Group; g != nil {
		v.Me = g.Me()
		for _, k := range g.Readers.Keys() {
			v.Members = append(v.Members, MemberView{k, c.Names.GetOr(k, "?")})
		}
	}
	return v
}

func lineOf(c *engine.Chat, l *engine.Line) LineView {
	v := LineView{Line: *l, Acked: c.Acknowledged(l)}
	if c.Group != nil && l.Notice == nil {
		v.Mine = l.Sender == c.Group.Me()
		if v.Mine {
			v.From = "me"
		} else {
			v.From = c.Names.GetOr(l.Sender, "?")
		}
	}
	return v
}

// Chats are our groups, in the order made.
func (c *Client) Chats() ([]ChatView, error) {
	var out []ChatView
	err := c.query(func(s *engine.State) {
		for _, ch := range s.Chats {
			out = append(out, viewOf(ch))
		}
	})
	return out, err
}

func (c *Client) Chat(id engine.ChatID) (ChatView, error) {
	var out ChatView
	var found bool
	err := c.query(func(s *engine.State) {
		if ch := s.Chat(id); ch != nil {
			out, found = viewOf(ch), true
		}
	})
	if err == nil && !found {
		err = ErrNoSuchChat
	}
	return out, err
}

// Lines are a group's lines from the one after id after on, oldest first; after -1 gives them
// all.
func (c *Client) Lines(id engine.ChatID, after int) ([]LineView, error) {
	var out []LineView
	var found bool
	err := c.query(func(s *engine.State) {
		ch := s.Chat(id)
		if ch == nil {
			return
		}
		found = true
		i, _ := slices.BinarySearchFunc(ch.Log, after+1, func(l *engine.Line, id int) int { return l.ID - id })
		for _, l := range ch.Log[i:] {
			out = append(out, lineOf(ch, l))
		}
	})
	if err == nil && !found {
		err = ErrNoSuchChat
	}
	return out, err
}

// FilePath is where a line's attachment is kept.
func (c *Client) FilePath(a *engine.Attachment) (string, error) { return c.st.Path(a.File) }

// MemberNamed is the one member of a group whose name, or the start of whose key in hex, is
// who.
func (c *Client) MemberNamed(id engine.ChatID, who string) (member.Key, error) {
	v, err := c.Chat(id)
	if err != nil {
		return "", err
	}
	var found []member.Key
	for _, m := range v.Members {
		if m.Name == who || len(who) >= 4 && hexPrefix(m.Key, who) {
			found = append(found, m.Key)
		}
	}
	if len(found) != 1 {
		return "", ErrNoSuchMember
	}
	return found[0], nil
}

func hexPrefix(k member.Key, p string) bool {
	const digits = "0123456789abcdef"
	h := make([]byte, 0, 2*len(k))
	for _, b := range []byte(k) {
		h = append(h, digits[b>>4], digits[b&15])
	}
	return len(p) <= len(h) && string(h[:len(p)]) == p
}
