package engine

import (
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/transport"
)

// Input is one thing that happened: a user's command, or what came of an Action.
type Input interface{ input() }

// What a user asks.
type (
	Create struct {
		Chat ChatID
		Name string
	}
	// Join mints a voucher to join a group we will call Name.
	Join struct {
		Chat ChatID
		Name string
	}
	// Induct adds the member whose voucher code is Code.
	Induct struct {
		Chat ChatID
		Code string
	}
	Send struct {
		Chat ChatID
		Text string
	}
	// Ping asks the group's members to play their ping sound.
	Ping     struct{ Chat ChatID }
	SendFile struct {
		Chat  ChatID
		Name  string
		Bytes []byte
	}
	Scan struct{ Chat ChatID }
	// Leave forgets a group: stops reading and writing it, and deletes it.
	Leave struct{ Chat ChatID }
	// RemoveMember stops reading a member.
	RemoveMember struct {
		Chat ChatID
		Who  member.Key
	}
	// Clear deletes a conversation's lines here.
	Clear  struct{ Chat ChatID }
	Rename struct {
		Chat ChatID
		To   string
	}
)

// Outcome is what reading a box found, with the index after it for data or a tombstone.
type Outcome struct {
	Kind      transport.ReadKind
	Plaintext []byte
	Next      member.Index
}

// What came of an Action.
type (
	Created struct {
		Chat    ChatID
		Joining bool
		Keypair transport.Keypair
	}
	Wrote struct {
		Chat  ChatID
		Job   int
		Index member.Index
		Next  member.Index
	}
	// Refused says a write found its box holding other bytes.
	Refused struct {
		Chat ChatID
		Job  int
	}
	Read struct {
		Chat    ChatID
		Stream  member.Key
		Index   member.Index
		Outcome Outcome
	}
	Wake struct {
		Chat   ChatID
		Stream member.Key
	}
	ScanRead struct {
		Chat    ChatID
		Stream  member.Key
		Index   member.Index
		Outcome Outcome
	}
	Walked struct {
		Chat    ChatID
		Stream  member.Key
		Target  *member.Index
		Skipped []member.Index
		Steps   int
	}
	Derived struct {
		Chat    ChatID
		Stream  member.Key
		Indexes []member.Index
	}
	Minted struct {
		Chat   ChatID
		Minted transport.Minted
		Box1   member.Index
	}
	Opened struct {
		Chat   ChatID
		Opened transport.Opened
	}
	JoinerPayload struct {
		Chat            ChatID
		Voucher         []byte
		VoucherWriteCap []byte
		Payload         []byte
		Box1            member.Index
	}
	SealedReply struct {
		Chat     ChatID
		Inducted transport.Inducted
	}
	// Published says the sealed reply is in box 1.
	Published struct{ Chat ChatID }
	Epoch     struct{ N int }
	Failed    struct {
		Chat ChatID
		What string
	}
	Loaded struct {
		Chat  ChatID
		Job   int
		Bytes []byte
		Lost  bool
	}
	Substream struct {
		Chat    ChatID
		Job     int
		Keypair transport.Keypair
	}
	WroteChunk struct {
		Chat ChatID
		Job  int
		N    int
		Next member.Index
	}
	ChunkIndexes struct {
		Chat    ChatID
		Job     int
		Start   member.Index
		Indexes []member.Index
	}
	ReadChunk struct {
		Chat    ChatID
		Stream  member.Key
		Index   member.Index
		Outcome Outcome
	}
)

func (Create) input()        {}
func (Join) input()          {}
func (Induct) input()        {}
func (Send) input()          {}
func (SendFile) input()      {}
func (Ping) input()          {}
func (Scan) input()          {}
func (Leave) input()         {}
func (RemoveMember) input()  {}
func (Clear) input()         {}
func (Rename) input()        {}
func (Created) input()       {}
func (Wrote) input()         {}
func (Refused) input()       {}
func (Read) input()          {}
func (Wake) input()          {}
func (ScanRead) input()      {}
func (Walked) input()        {}
func (Derived) input()       {}
func (Minted) input()        {}
func (Opened) input()        {}
func (JoinerPayload) input() {}
func (SealedReply) input()   {}
func (Published) input()     {}
func (Epoch) input()         {}
func (Failed) input()        {}
func (Loaded) input()        {}
func (Substream) input()     {}
func (WroteChunk) input()    {}
func (ChunkIndexes) input()  {}
func (ReadChunk) input()     {}

// Action is network or disk work. Each comes back as the Input named.
type Action interface{ action() }

type (
	// DoCreate makes a new stream: Created.
	DoCreate struct {
		Chat    ChatID
		Joining bool
	}
	// DoWrite writes a box, retrying until it is written: Wrote, or Refused.
	DoWrite struct {
		Chat     ChatID
		Job      int
		WriteCap []byte
		Index    member.Index
		Box      []byte
	}
	// DoRead reads a box once: Read.
	DoRead struct {
		Chat    ChatID
		Stream  member.Key
		ReadCap []byte
		Index   member.Index
	}
	// DoWake sends Wake after Ms milliseconds.
	DoWake struct {
		Chat   ChatID
		Stream member.Key
		Ms     int
	}
	// DoScanRead reads a box once for a scan: ScanRead.
	DoScanRead struct {
		Chat    ChatID
		Stream  member.Key
		ReadCap []byte
		Index   member.Index
	}
	// DoWalk: Walked.
	DoWalk struct {
		Chat    ChatID
		Stream  member.Key
		Start   member.Index
		Targets []uint64
		Keep    int
	}
	// DoDerive: Derived.
	DoDerive struct {
		Chat   ChatID
		Stream member.Key
		Start  member.Index
		Count  int
	}
	// DoMint mints a voucher and publishes its box 0: Minted.
	DoMint struct {
		Chat     ChatID
		WriteCap []byte
		Name     string
		// Form is the payload's form: 2 the compact array, 1 the signed map.
		Form int
	}
	// DoAwaitReply waits for the reply in box 1 and opens it: Opened.
	DoAwaitReply struct {
		Chat           ChatID
		SecretKey      []byte
		VoucherReadCap []byte
		Box1           member.Index
		WriteCap       []byte
		// Version 2 is framed over boxes 1 on, C pieces then an F piece; 1 is box 1 alone.
		Version int
	}
	// DoReadVoucher reads a voucher's box 0: JoinerPayload.
	DoReadVoucher struct {
		Chat    ChatID
		Voucher []byte
	}
	// DoSeal seals the reply to a voucher: SealedReply.
	DoSeal struct {
		Chat     ChatID
		Voucher  []byte
		Payload  []byte
		WhoReply []byte
	}
	// DoPublish writes the sealed reply to box 1, retrying until it is written: Published.
	DoPublish struct {
		Chat            ChatID
		VoucherWriteCap []byte
		Box1            member.Index
		Reply           []byte
		// Version 2 is written framed in pieces of a box less one byte; 1 to box 1 alone.
		Version int
	}
	// DoDelete deletes a file under the state directory.
	DoDelete struct{ File string }
	// DoLoad reads back the file holding an upload's message: Loaded.
	DoLoad struct {
		Chat ChatID
		Job  int
		File string
	}
	// DoSubstream makes a new stream for an upload: Substream.
	DoSubstream struct {
		Chat ChatID
		Job  int
	}
	// DoWriteChunk writes the Nth box of an upload, retrying until it is written: WroteChunk.
	DoWriteChunk struct {
		Chat     ChatID
		Job      int
		N        int
		WriteCap []byte
		Index    member.Index
		Box      []byte
	}
	// DoChunkIndexes derives the indexes of Count boxes after Start of an upload's substream:
	// ChunkIndexes.
	DoChunkIndexes struct {
		Chat  ChatID
		Job   int
		Start member.Index
		Count int
	}
	// DoReadChunk reads a box of the substream an I box named: ReadChunk.
	DoReadChunk struct {
		Chat    ChatID
		Stream  member.Key
		ReadCap []byte
		Index   member.Index
	}
)

func (DoCreate) action()       {}
func (DoWrite) action()        {}
func (DoRead) action()         {}
func (DoWake) action()         {}
func (DoScanRead) action()     {}
func (DoWalk) action()         {}
func (DoDerive) action()       {}
func (DoMint) action()         {}
func (DoAwaitReply) action()   {}
func (DoReadVoucher) action()  {}
func (DoSeal) action()         {}
func (DoPublish) action()      {}
func (DoDelete) action()       {}
func (DoLoad) action()         {}
func (DoSubstream) action()    {}
func (DoWriteChunk) action()   {}
func (DoChunkIndexes) action() {}
func (DoReadChunk) action()    {}

// FileWrite is a file to keep under the state directory. It must be on disk before the state
// that names it is saved.
type FileWrite struct {
	File  string
	Bytes []byte
}

// Changes say what a step changed, so that only that is saved.
type Changes struct {
	// Chats are the conversations whose record changed, apart from their lines.
	Chats map[ChatID]bool
	// Lines are the lines added or changed, by conversation.
	Lines map[ChatID]map[int]bool
	// Dropped are the lines deleted, by conversation.
	Dropped map[ChatID]map[int]bool
	// Removed are the conversations deleted.
	Removed map[ChatID]bool
}

func (c *Changes) Empty() bool {
	return len(c.Chats) == 0 && len(c.Lines) == 0 && len(c.Dropped) == 0 && len(c.Removed) == 0
}

// Result is what a step asks for: files to keep, then the state to save, then work to start.
type Result struct {
	Files   []FileWrite
	Changes Changes
	Actions []Action
}
