// Package tally is katzenqt's polls without IO: a survey is a Yjs document that tally messages
// (wire.Tally) carry and change, read as a poll with its votes counted.
//
// The document has three roots: the map meta {survey_id (hex), topic, mode, n_slots, status
// "open" or "closed", creator (hex voter id)}, the array slots of maps {id, text}, fixed when the
// survey is made, and the map votes of voter id (hex) to a map of slot id to availability with
// the vote's version under _version. Counts are not kept; they are read from the votes.
//
// A create or sync response carries an update, merged in. A vote carries the sender's choice,
// recorded under the voter id of the member who sent it, never one it names; a newer version
// replaces an older one whatever the order they come in. A close counts from the survey's
// creator only. A sync request carries a state vector and is answered with what it lacks.
package tally

import (
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/Deln0r/ygo"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

// Mode is how a poll is answered.
type Mode string

const (
	// Approval is yes or no to each option.
	Approval Mode = "approval"
	// Availability adds maybe.
	Availability Mode = "availability"
)

// Domain is the availabilities a vote may give in m.
func (m Mode) Domain() []string {
	if m == Availability {
		return []string{"yes", "maybe", "no"}
	}
	return []string{"yes", "no"}
}

// Limits on what is taken from a member, as katzenqt's.
const (
	MaxSurveyID = 64
	MaxCrdt     = 512 * 1024
)

const versionKey = "_version"

// VoterID is a member's voter id: BLAKE2b-128 of its key, the first 32 bytes of its read cap.
type VoterID [16]byte

func VoterOf(key member.Key) VoterID {
	h, _ := blake2b.New(16, nil)
	h.Write([]byte(wire.KeyOf([]byte(key))))
	return VoterID(h.Sum(nil))
}

func (v VoterID) String() string { return hex.EncodeToString(v[:]) }

// SlotID is the id of the option at i.
func SlotID(i int) string { return fmt.Sprintf("s%d", i) }

// Survey is one survey's document.
type Survey struct{ doc *ygo.Doc }

// New is a survey asking topic, with an option for each of options, made by creator.
func New(id []byte, topic string, mode Mode, options []string, creator VoterID) (*Survey, error) {
	if len(options) == 0 {
		return nil, errors.New("a survey needs at least one option")
	}
	if len(id) == 0 || len(id) > MaxSurveyID {
		return nil, errors.New("a survey id is 1 to 64 bytes")
	}
	d := ygo.NewDoc()
	txn := d.WriteTxn()
	meta, slots := ygo.MapIn(txn, "meta"), ygo.ArrayIn(txn, "slots")
	ygo.MapIn(txn, "votes")
	meta.Set(txn, "survey_id", hex.EncodeToString(id))
	meta.Set(txn, "topic", topic)
	meta.Set(txn, "mode", string(mode))
	meta.Set(txn, "n_slots", float64(len(options)))
	meta.Set(txn, "status", "open")
	meta.Set(txn, "creator", creator.String())
	for i, o := range options {
		m := slots.InsertMap(txn, uint64(i))
		m.Set(txn, "id", SlotID(i))
		m.Set(txn, "text", o)
	}
	txn.Commit()
	return &Survey{d}, nil
}

// Load is the survey an update holds.
func Load(update []byte) (*Survey, error) {
	s := &Survey{ygo.NewDoc()}
	return s, s.Apply(update)
}

// Apply merges an update in. The update is a member's, so a panic in the decoder is an error.
func (s *Survey) Apply(update []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("undecodable update: %v", r)
		}
	}()
	return ygo.ApplyUpdate(s.doc, update)
}

// Update is the whole survey, as one update.
func (s *Survey) Update() []byte { return ygo.EncodeStateAsUpdate(s.doc) }

// StateVector says what the survey holds, for a sync request.
func (s *Survey) StateVector() []byte { return ygo.EncodeStateVector(s.doc) }

// Diff is what the survey holds that a state vector sv lacks.
func (s *Survey) Diff(sv []byte) (diff []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("undecodable state vector: %v", r)
		}
	}()
	return ygo.EncodeDiff(s.doc, sv)
}

func (s *Survey) meta(k string) string {
	v, _ := ygo.NewMap(s.doc, "meta").Get(k).(string)
	return v
}

func (s *Survey) Mode() Mode    { return Mode(s.meta("mode")) }
func (s *Survey) Closed() bool  { return s.meta("status") == "closed" }
func (s *Survey) Topic() string { return s.meta("topic") }
func (s *Survey) ID() []byte    { b, _ := hex.DecodeString(s.meta("survey_id")); return b }

// Creator is who made the survey; ok is false for one made before that was kept.
func (s *Survey) Creator() (v VoterID, ok bool) {
	b, err := hex.DecodeString(s.meta("creator"))
	if err != nil || len(b) != len(v) {
		return v, false
	}
	return VoterID(b), true
}

// MayClose says whether voter may close the survey.
func (s *Survey) MayClose(voter VoterID) bool {
	c, ok := s.Creator()
	return !ok || c == voter
}

// Option is one of a poll's options with its count.
type Option struct {
	ID, Text       string
	Yes, Maybe, No int
}

func (s *Survey) options() []Option {
	var out []Option
	for _, v := range ygo.NewArray(s.doc, "slots").ToSlice() {
		if m, ok := v.(*ygo.Map); ok {
			id, _ := m.Get("id").(string)
			text, _ := m.Get("text").(string)
			out = append(out, Option{ID: id, Text: text})
		}
	}
	return out
}

// Ballot is a member's vote: its availability for each option it marked, by slot id.
type Ballot struct {
	Voter   VoterID
	Version uint64
	Choice  []wire.Choice
}

// number is a Yjs number as Go reads it back.
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}

func ballotOf(m *ygo.Map) (version uint64, choice []wire.Choice) {
	choice = []wire.Choice{}
	m.Range(func(k string, v any) bool {
		if k == versionKey {
			// shortcut: a non-numeric or negative version reads as 0, as katzenqt's; a fraction is cut.
			if n, ok := number(v); ok && n > 0 && n < 1<<63 {
				version = uint64(n)
			}
		} else if a, ok := v.(string); ok {
			choice = append(choice, wire.Choice{Slot: k, Availability: a})
		}
		return true
	})
	slices.SortFunc(choice, func(a, b wire.Choice) int { return strings.Compare(a.Slot, b.Slot) })
	return version, choice
}

// Ballots are the votes, by voter id.
func (s *Survey) Ballots() []Ballot {
	votes := ygo.NewMap(s.doc, "votes")
	var out []Ballot
	for _, k := range slices.Sorted(maps.Keys(entries(votes))) {
		m, ok := votes.Get(k).(*ygo.Map)
		b, err := hex.DecodeString(k)
		if !ok || err != nil || len(b) != 16 {
			continue
		}
		version, choice := ballotOf(m)
		out = append(out, Ballot{VoterID(b), version, choice})
	}
	return out
}

func entries(m *ygo.Map) map[string]any {
	out := map[string]any{}
	m.Range(func(k string, v any) bool { out[k] = v; return true })
	return out
}

// Ballot is voter's vote, if any.
func (s *Survey) Ballot(voter VoterID) (Ballot, bool) {
	for _, b := range s.Ballots() {
		if b.Voter == voter {
			return b, true
		}
	}
	return Ballot{}, false
}

// NextVersion is the version voter's next vote is sent in, to replace the one recorded.
func (s *Survey) NextVersion(voter VoterID) uint64 {
	if b, ok := s.Ballot(voter); ok {
		return b.Version + 1
	}
	return 0
}

// Options are the options with their counts; an option a voter did not mark counts as no.
func (s *Survey) Options() []Option {
	opts, ballots := s.options(), s.Ballots()
	for i := range opts {
		for _, b := range ballots {
			a := ""
			for _, c := range b.Choice {
				if c.Slot == opts[i].ID {
					a = c.Availability
				}
			}
			switch a {
			case "yes":
				opts[i].Yes++
			case "maybe":
				opts[i].Maybe++
			default:
				opts[i].No++
			}
		}
	}
	return opts
}

// Winners are the options with the most yes, several for a tie and none when no option has a yes.
func Winners(opts []Option) []Option {
	top := 0
	for _, o := range opts {
		top = max(top, o.Yes)
	}
	var out []Option
	for _, o := range opts {
		if top > 0 && o.Yes == top {
			out = append(out, o)
		}
	}
	return out
}

// Vote records voter's choice in version: its slots must be the survey's and its availabilities
// the mode's. An older version than the one recorded changes nothing.
func (s *Survey) Vote(voter VoterID, choice []wire.Choice, version uint64) error {
	domain := s.Mode().Domain()
	opts := s.options()
	for _, c := range choice {
		if !slices.ContainsFunc(opts, func(o Option) bool { return o.ID == c.Slot }) {
			return fmt.Errorf("unknown slot id %q", c.Slot)
		}
		if !slices.Contains(domain, c.Availability) {
			return fmt.Errorf("availability %q not allowed in %s mode", c.Availability, s.Mode())
		}
	}
	if b, ok := s.Ballot(voter); ok && version < b.Version {
		return nil
	}
	txn := s.doc.WriteTxn()
	m := ygo.MapIn(txn, "votes").SetMap(txn, voter.String())
	for _, c := range choice {
		m.Set(txn, c.Slot, c.Availability)
	}
	m.Set(txn, versionKey, float64(version))
	txn.Commit()
	return nil
}

// Close marks the survey closed.
func (s *Survey) Close() {
	txn := s.doc.WriteTxn()
	ygo.MapIn(txn, "meta").Set(txn, "status", "closed")
	txn.Commit()
}

// The messages a member sends.

func (s *Survey) CreateMessage() wire.Tally {
	return wire.Tally{Kind: wire.MsgTallyCreate, SurveyID: s.ID(), Crdt: s.Update()}
}

func VoteMessage(id []byte, choice []wire.Choice, version uint64) wire.Tally {
	if choice == nil {
		choice = []wire.Choice{}
	}
	return wire.Tally{Kind: wire.MsgTallyVote, SurveyID: id, Choice: choice, Version: version}
}

func CloseMessage(id []byte) wire.Tally { return wire.Tally{Kind: wire.MsgTallyClose, SurveyID: id} }

func (s *Survey) SyncRequest() wire.Tally {
	return wire.Tally{Kind: wire.MsgTallySyncReq, SurveyID: s.ID(), Crdt: s.StateVector()}
}

// Polls are the surveys of one conversation, from the tally messages read in it.
type Polls struct {
	surveys map[string]*Survey
	// lines is the line each survey was first made known at.
	lines   map[int]*Survey
	pending map[string][]pending
}

// pending is a vote or close read before its survey.
type pending struct {
	voter VoterID
	t     wire.Tally
}

func NewPolls() *Polls {
	return &Polls{surveys: map[string]*Survey{}, lines: map[int]*Survey{}, pending: map[string][]pending{}}
}

// Survey is the survey id names, if known.
func (p *Polls) Survey(id []byte) *Survey { return p.surveys[string(id)] }

// At is the survey made known at line.
func (p *Polls) At(line int) *Survey { return p.lines[line] }

// Receive takes in a tally message from sender, read at line, and returns the answer to send, if
// any. An error says why the message was refused.
func (p *Polls) Receive(sender member.Key, t *wire.Tally, line int) (*wire.Tally, error) {
	id := string(t.SurveyID)
	if len(t.SurveyID) > MaxSurveyID {
		return nil, fmt.Errorf("survey id of %d bytes is over %d", len(t.SurveyID), MaxSurveyID)
	}
	if len(t.Crdt) > MaxCrdt {
		return nil, fmt.Errorf("update of %d bytes is over %d", len(t.Crdt), MaxCrdt)
	}
	s, voter := p.surveys[id], VoterOf(sender)
	switch t.Kind {
	case wire.MsgTallyCreate, wire.MsgTallySyncResp:
		if t.Crdt == nil {
			return nil, nil
		}
		if s != nil {
			return nil, s.Apply(t.Crdt)
		}
		s, err := Load(t.Crdt)
		if err != nil {
			return nil, err
		}
		p.surveys[id], p.lines[line] = s, s
		for _, w := range p.pending[id] {
			p.replay(s, w)
		}
		delete(p.pending, id)
	case wire.MsgTallyVote, wire.MsgTallyClose:
		if s == nil {
			p.pending[id] = append(p.pending[id], pending{voter, *t})
			return nil, nil
		}
		if t.Kind == wire.MsgTallyVote {
			return nil, s.Vote(voter, t.Choice, t.Version)
		}
		if !s.MayClose(voter) {
			return nil, errors.New("close ignored: not the creator")
		}
		s.Close()
	case wire.MsgTallySyncReq:
		if s == nil {
			return nil, nil
		}
		diff, err := s.Diff(t.Crdt)
		if err != nil {
			return nil, err
		}
		return &wire.Tally{Kind: wire.MsgTallySyncResp, SurveyID: t.SurveyID, Crdt: diff}, nil
	}
	return nil, nil
}

// replay applies a vote or close read before its survey, as katzenqt's controller drains them.
func (p *Polls) replay(s *Survey, w pending) {
	if w.t.Kind == wire.MsgTallyClose {
		if s.MayClose(w.voter) {
			s.Close()
		}
		return
	}
	if b, ok := s.Ballot(w.voter); ok && (w.t.Version < b.Version || w.t.Version == b.Version && sameChoice(b.Choice, w.t.Choice)) {
		return
	}
	_ = s.Vote(w.voter, w.t.Choice, w.t.Version) // shortcut: an invalid early vote is dropped unreported, as katzenqt's
}

func sameChoice(a, b []wire.Choice) bool {
	b = slices.Clone(b)
	slices.SortFunc(b, func(x, y wire.Choice) int { return strings.Compare(x.Slot, y.Slot) })
	return slices.Equal(a, b)
}

// FromLines are the polls a conversation's lines make, read in order; sync requests among them
// are not answered.
func FromLines(lines []*engine.Line) *Polls {
	p := NewPolls()
	for _, l := range lines {
		if l.Tally != nil {
			_, _ = p.Receive(l.Sender, l.Tally, l.ID)
		}
	}
	return p
}

// Shows says whether a line is shown: a line that is no tally message, or the one that made a
// poll known.
func (p *Polls) Shows(l *engine.Line) bool { return l.Tally == nil || p.lines[l.ID] != nil }
