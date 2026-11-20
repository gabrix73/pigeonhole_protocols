package wire

// A tally message's body, msg_type 5 to 9: the map katzenqt's GroupChatTally writes,
// {survey_id, version, choice, crdt} in that order, absent fields left out. A create or a sync
// response carries a CRDT update in crdt, a sync request a state vector there; a vote carries the
// sender's choice, slot id to availability; a close neither. What the CRDT holds is the app's:
// this client only carries it.

const (
	MsgTallyCreate   = 5
	MsgTallyVote     = 6
	MsgTallyClose    = 7
	MsgTallySyncReq  = 8
	MsgTallySyncResp = 9
)

// Choice is a vote's availability for one slot.
type Choice struct {
	Slot, Availability string
}

// Tally is a tally message. A nil Choice or Crdt is absent; a non-nil empty one is present and
// empty.
type Tally struct {
	// Kind is the message's type, MsgTallyCreate to MsgTallySyncResp.
	Kind     uint64
	SurveyID []byte
	Version  uint64
	// Choice is a vote's, in the order sent.
	Choice []Choice
	Crdt   []byte
}

// Body is the body's CBOR.
func (t *Tally) Body() []byte {
	n := uint64(2)
	if t.Choice != nil {
		n++
	}
	if t.Crdt != nil {
		n++
	}
	out := appendHeader(nil, 5, n)
	out = appendBytes(appendText(out, "survey_id"), t.SurveyID)
	out = appendUint(appendText(out, "version"), t.Version)
	if t.Choice != nil {
		out = appendHeader(appendText(out, "choice"), 5, uint64(len(t.Choice)))
		for _, c := range t.Choice {
			out = appendText(appendText(out, c.Slot), c.Availability)
		}
	}
	if t.Crdt != nil {
		out = appendBytes(appendText(out, "crdt"), t.Crdt)
	}
	return out
}

// TallyOfBody is a body of type kind, which must have a survey id; null is taken as absent and
// keys katzenqt does not write are passed over.
func TallyOfBody(kind uint64, b []byte) (*Tally, bool) {
	if kind < MsgTallyCreate || kind > MsgTallySyncResp {
		return nil, false
	}
	major, n, l, ok := readHeader(b)
	if !ok || major != 5 {
		return nil, false
	}
	t := &Tally{Kind: kind}
	for ; n > 0; n-- {
		var k string
		if k, l, ok = readText(l); !ok {
			return nil, false
		}
		switch {
		case k == "survey_id":
			t.SurveyID, l, ok = readBytes(l)
		case k == "version":
			t.Version, l, ok = readUint(l)
		case (k == "choice" || k == "crdt") && isNull(l):
			l = l[1:]
		case k == "crdt":
			t.Crdt, l, ok = readBytes(l)
		case k == "choice":
			t.Choice, l, ok = readChoice(l)
		default:
			l, ok = skipItems(len(l)+1, 1, l)
		}
		if !ok {
			return nil, false
		}
	}
	if len(t.SurveyID) == 0 {
		return nil, false
	}
	return t, true
}

func readChoice(l []byte) ([]Choice, []byte, bool) {
	major, m, l, ok := readHeader(l)
	if !ok || major != 5 || m > uint64(len(l)) {
		return nil, nil, false
	}
	c := make([]Choice, 0, m)
	for ; m > 0; m-- {
		var s, a string
		if s, l, ok = readText(l); !ok {
			return nil, nil, false
		}
		if a, l, ok = readText(l); !ok {
			return nil, nil, false
		}
		c = append(c, Choice{s, a})
	}
	return c, l, true
}

// TallyOf is the tally a message carries, if it is one.
func TallyOf(g *Gcm) (*Tally, bool) {
	i, ok := g.other("tally")
	if !ok {
		return nil, false
	}
	return TallyOfBody(g.MsgType, g.Other[i].Raw)
}

// TallyContent is t in version, as a member's content.
func TallyContent(membershipHash []byte, t *Tally, version uint64) []byte {
	g := Gcm{Version: version, MembershipHash: membershipHash, MsgType: t.Kind,
		Other: []RawField{{"tally", t.Body()}}}
	return g.Encode()
}
