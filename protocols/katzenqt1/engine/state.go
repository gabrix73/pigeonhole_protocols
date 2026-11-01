// Package engine is a katzenqt1 group chat client without IO: Step takes the state and one
// input, from the user or from the network, and returns the network work it asks for and what
// changed. The caller saves what changed before it carries out any of the work.
//
// The member state machine is driven as katzenqt's adapter drives it: Compose for each message
// sent, Written once its box is written, Observe for each box read in order, Handle for a new
// epoch and for a user's scan, and for a new member BeginInduction, then once everything owed is
// written Reply, then IntroduceNow as soon as the reply is sealed, ahead of anything sent while
// it sealed, so that the Introduction is the box at the index the reply names.
package engine

import (
	"bytes"

	"github.com/katzenpost/pigeonhole_protocols/internal/ordmap"
	"github.com/katzenpost/pigeonhole_protocols/protocols/katzenqt1/member"
)

// ChatID names a conversation for good; its name may change.
type ChatID string

// Upload is a message too long for a box, being written to a substream of its own.
type Upload struct {
	// File holds the message under the state directory, until it is written.
	File string
	// BoxSize is the most plaintext a box holds, which its boxes were cut to.
	BoxSize int
	Total   int
	// WriteCap is the substream's, once made.
	WriteCap []byte
	// Sent is the boxes written so far, and Next the index of the next.
	Sent int
	Next member.Index
}

// Job is a box to write to our own stream, in order.
type Job struct {
	ID int
	// Token is the message's, to tell the member when it is written; nil for a rewrite.
	Token *int
	// Index is the box: chosen when the job is first sent, given for a rewrite.
	Index *member.Index
	// Box is what the box holds; empty for a tombstone.
	Box []byte
	// Line is the conversation line it shows as.
	Line *int
	// Upload is set for a message too long for a box: its substream is written first, and Box is
	// then the I box naming it.
	Upload *Upload
}

type Status int

const (
	Sent Status = iota
	Pending
)

// Attachment is a file a line carries.
type Attachment struct {
	// Name is made safe.
	Name     string
	Filetype string
	Size     int
	// File holds it under the state directory.
	File string
}

// Line is a line of a conversation: a message, or a notice of our own.
type Line struct {
	ID     int
	Sender member.Key
	// Index is the box it came in, so that it can expire.
	Index  member.Index
	Text   string
	Notice *Notice
	Status Status
	// Idx64 is that of our own message's box, once written.
	Idx64 *uint64
	// Time is when it was said here, or read, in milliseconds since the Unix epoch.
	Time       int64
	Attachment *Attachment
}

// Joining is joining a group through a contact voucher we minted: minting until Code is set.
type Joining struct {
	Code           string
	SecretKey      []byte
	VoucherReadCap []byte
	Box1           member.Index
}

// Inducting is inducting a member whose voucher we were given: reading the voucher until
// Payload is set.
type Inducting struct {
	Voucher         []byte
	Payload         []byte
	VoucherWriteCap []byte
	Box1            member.Index
	// Sealing says the reply is being sealed.
	Sealing bool
	// Sealed is the reply once sealed, kept until it is in box 1, with whom it adds.
	Sealed *Sealed
}

type Sealed struct {
	Name           string
	MutatedReadCap []byte
	Reply          []byte
}

// Download is a message a member's I box announced, being read from its substream. Their stream
// is read no further until it is.
type Download struct {
	Stream member.Key
	// Index is the I box, and Next the one after it.
	Index   member.Index
	Next    member.Index
	ReadCap []byte
	// Total is how many boxes the substream holds, when the writer said.
	Total *int
}

type Chat struct {
	ID        ChatID
	Name      string
	WriteCap  []byte
	NextWrite member.Index
	Group     *member.Group
	// Cursors is where we read each member's stream next.
	Cursors   ordmap.Map[member.Key, member.Index]
	Names     ordmap.Map[member.Key, string]
	Jobs      []*Job
	Log       []*Line
	Joining   *Joining
	Inducting *Inducting
	NextID    int
	Downloads []Download
}

type State struct {
	// Me is our display name.
	Me    string
	Chats []*Chat
}

// MaxLog is the lines a conversation keeps; older ones are dropped.
const MaxLog = 10000

func (s *State) Chat(id ChatID) *Chat {
	for _, c := range s.Chats {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (s *State) ChatNamed(name string) *Chat {
	for _, c := range s.Chats {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// Wanted says whether an action tried again is still of use: its chat is still here and, for a
// voucher's box, still waiting for it.
func (s *State) Wanted(a Action) bool {
	var id ChatID
	switch a := a.(type) {
	case DoAwaitReply:
		c := s.Chat(a.Chat)
		return c != nil && c.Joining != nil && bytes.Equal(c.Joining.SecretKey, a.SecretKey)
	case DoReadVoucher:
		c := s.Chat(a.Chat)
		return c != nil && c.Inducting != nil && c.Inducting.Payload == nil && bytes.Equal(c.Inducting.Voucher, a.Voucher)
	case DoWrite:
		id = a.Chat
	case DoRead:
		id = a.Chat
	case DoScanRead:
		id = a.Chat
	case DoWalk:
		id = a.Chat
	case DoDerive:
		id = a.Chat
	case DoSubstream:
		id = a.Chat
	case DoWriteChunk:
		id = a.Chat
	case DoChunkIndexes:
		id = a.Chat
	case DoReadChunk:
		id = a.Chat
	default:
		return true
	}
	return s.Chat(id) != nil
}

func (c *Chat) fresh() int {
	id := c.NextID
	c.NextID++
	return id
}

// Files are the files a conversation's lines and jobs hold.
func (c *Chat) Files() []string {
	var fs []string
	for _, l := range c.Log {
		if l.Attachment != nil {
			fs = append(fs, l.Attachment.File)
		}
	}
	for _, j := range c.Jobs {
		if j.Upload != nil {
			fs = append(fs, j.Upload.File)
		}
	}
	return fs
}

func (c *Chat) job(id int) *Job {
	for _, j := range c.Jobs {
		if j.ID == id {
			return j
		}
	}
	return nil
}

// Acknowledged says whether any member has acknowledged our line l.
func (c *Chat) Acknowledged(l *Line) bool {
	if c.Group == nil || l.Idx64 == nil {
		return false
	}
	for _, n := range c.Group.Ledger.AckedBy.Values() {
		if *l.Idx64 <= n {
			return true
		}
	}
	return false
}

func slug(group string) string {
	b := []rune(group)
	for i, r := range b {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			b[i] = '_'
		}
	}
	return string(b)
}
