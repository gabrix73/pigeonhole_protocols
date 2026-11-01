package engine

import "fmt"

// A Notice is what the client tells the user of a conversation, as a kind and its arguments;
// an app words it.
type Notice struct {
	Kind NoticeKind
	Args []string
}

type NoticeKind int

const (
	NameTaken NoticeKind = iota
	NameTakenJoining
	Minting
	NewGroup
	// VoucherMinted's arguments are the code, the group's name and the file holding the code.
	VoucherMinted
	ReplyUnreadable
	Joined
	NotJoinedYet
	AlreadyAdding
	NotAVoucher
	ReadingVoucher
	// Added's argument is whom it added.
	Added
	NotJoined
	FileTooLarge
	SendLost
	FileTooLargeToFetch
	Scanning
	NoLongerMember
	StoppedReading
	Renamed
	// ActionFailed's argument says what failed.
	ActionFailed
	TooLong
	NotWritten
	// MemberAdded's arguments are who added whom.
	MemberAdded
	Unreadable
	NotFetched
	// Desync says a box of our stream holds other bytes than we meant to write there: another
	// client writes our stream, or this state is older than one that wrote it.
	Desync
)

// Plain words a notice as group_chat_client's plain presentation does, with names as they are.
func Plain(n *Notice) string {
	a := func(i int) string {
		if i < len(n.Args) {
			return n.Args[i]
		}
		return ""
	}
	switch n.Kind {
	case NameTaken:
		return "you already have a group called " + a(0)
	case NameTakenJoining:
		return "you already have a group called " + a(0) + ": to join someone else's group, give it a name of its own"
	case Minting:
		return "minting a voucher"
	case NewGroup:
		return "a new group: adding a member's voucher code adds them"
	case VoucherMinted:
		return "give the voucher code to a member of the group (it is also in " + a(2) + ")"
	case ReplyUnreadable:
		return "the reply to our voucher cannot be read"
	case Joined:
		return "joined the group"
	case NotJoinedYet:
		return "join or create the group first"
	case AlreadyAdding:
		return "already adding a member"
	case NotAVoucher:
		return "that is not a voucher code"
	case ReadingVoucher:
		return "reading the voucher"
	case Added:
		return "added ~" + a(0) + ": they now read everything said in this group"
	case NotJoined:
		return "this conversation has not been joined yet"
	case FileTooLarge:
		return "that file is too large to send: at most " + a(0)
	case SendLost:
		return "a message could not be sent: what it held was lost"
	case FileTooLargeToFetch:
		return a(0) + " sent a file too large to fetch"
	case Scanning:
		return "scanning for missed messages"
	case NoLongerMember:
		return "that member is no longer in this group"
	case StoppedReading:
		return "stopped reading " + a(0) + " and deleted what they sent; they can still read this group"
	case Renamed:
		return "renamed from " + a(0)
	case ActionFailed:
		return a(0)
	case TooLong:
		return "that message is too long to send"
	case NotWritten:
		return "a message could not be written"
	case MemberAdded:
		return a(0) + " added ~" + a(1)
	case Unreadable:
		return a(0) + " sent a message that cannot be read"
	case NotFetched:
		return a(0) + " sent a message that could not be fetched"
	case Desync:
		return "a box of our stream holds something else: is this group used from another client?"
	}
	return fmt.Sprintf("notice %d %v", n.Kind, n.Args)
}

// SizeText is a size as people read it.
func SizeText(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d bytes", n)
	case n < 1024*1024:
		return fmt.Sprintf("%d KB", (n+512)/1024)
	}
	return fmt.Sprintf("%d.%d MB", n/(1024*1024), n%(1024*1024)*10/(1024*1024))
}
