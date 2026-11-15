package tally

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/wire"
)

type vTally struct {
	SurveyID string      `json:"survey_id"`
	Version  uint64      `json:"version"`
	Choice   [][2]string `json:"choice"`
	Crdt     *string     `json:"crdt"`
}

type vectors struct {
	VoterIDs  [][2]string `json:"voter_ids"`
	Scenarios []struct {
		Name  string `json:"name"`
		Steps []struct {
			Sender   string `json:"sender"`
			MsgType  uint64 `json:"msg_type"`
			Tally    vTally `json:"tally"`
			Refused  bool   `json:"refused"`
			Answered bool   `json:"answered"`
			Answer   any    `json:"answer_reads_as"`
		} `json:"steps"`
		Polls []any `json:"polls"`
	} `json:"scenarios"`
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (v vTally) wire(t *testing.T, kind uint64) *wire.Tally {
	w := &wire.Tally{Kind: kind, SurveyID: unhex(t, v.SurveyID), Version: v.Version}
	if v.Choice != nil {
		w.Choice = []wire.Choice{}
		for _, c := range v.Choice {
			w.Choice = append(w.Choice, wire.Choice{Slot: c[0], Availability: c[1]})
		}
	}
	if v.Crdt != nil {
		w.Crdt = unhex(t, *v.Crdt)
	}
	return w
}

// pollJSON is a survey as the vectors write it.
func pollJSON(s *Survey) any {
	var creator any
	if c, ok := s.Creator(); ok {
		creator = c.String()
	}
	opts := s.Options()
	options := []any{}
	for _, o := range opts {
		options = append(options, []any{o.ID, o.Text, o.Yes, o.Maybe, o.No})
	}
	ballots := []any{}
	for _, b := range s.Ballots() {
		choice := []any{}
		for _, c := range b.Choice {
			choice = append(choice, []any{c.Slot, c.Availability})
		}
		ballots = append(ballots, []any{b.Voter.String(), b.Version, choice})
	}
	winners := []any{}
	for _, w := range Winners(opts) {
		winners = append(winners, w.ID)
	}
	j, _ := json.Marshal(map[string]any{
		"survey_id": hex.EncodeToString(s.ID()), "topic": s.Topic(), "mode": string(s.Mode()), "closed": s.Closed(),
		"creator": creator, "options": options, "ballots": ballots, "winners": winners,
	})
	var out any
	json.Unmarshal(j, &out)
	return out
}

func load(t *testing.T) vectors {
	b, err := os.ReadFile("../../../../testdata/katzenqt1/tally_poll_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestPollVectors: polls kept as katzenqt keeps them, from pycrdt's updates.
func TestPollVectors(t *testing.T) {
	v := load(t)
	if len(v.VoterIDs) != 4 || len(v.Scenarios) != 6 {
		t.Fatalf("%d voter ids, %d scenarios", len(v.VoterIDs), len(v.Scenarios))
	}
	for _, k := range v.VoterIDs {
		if got := VoterOf(member.Key(unhex(t, k[0]))).String(); got != k[1] {
			t.Errorf("voter id of %s: %s", k[0], got)
		}
	}
	for _, sc := range v.Scenarios {
		p := NewPolls()
		var lines []*engine.Line
		for i, st := range sc.Steps {
			w := st.Tally.wire(t, st.MsgType)
			sender := member.Key(unhex(t, st.Sender))
			answer, err := p.Receive(sender, w, i)
			if (err != nil) != st.Refused || (answer != nil) != st.Answered {
				t.Errorf("%s step %d: refused %v, answer %v", sc.Name, i, err, answer != nil)
			}
			if answer != nil {
				fresh, err := Load(sc.Steps[0].Tally.wire(t, wire.MsgTallyCreate).Crdt)
				if err == nil {
					err = fresh.Apply(answer.Crdt)
				}
				if got := pollJSON(fresh); err != nil || !reflect.DeepEqual(got, st.Answer) {
					t.Errorf("%s step %d: answer reads as %v, %v", sc.Name, i, got, err)
				}
			}
			lines = append(lines, &engine.Line{ID: i, Sender: sender, Tally: w})
		}
		var ids []string
		for id := range p.surveys {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		var got []any
		for _, id := range ids {
			got = append(got, pollJSON(p.surveys[id]))
		}
		if !reflect.DeepEqual(got, sc.Polls) {
			t.Errorf("%s:\n got  %v\n want %v", sc.Name, got, sc.Polls)
		}
		// The same lines replayed read the same, and show a poll at the line that made it known.
		q := FromLines(lines)
		for _, id := range ids {
			if !reflect.DeepEqual(pollJSON(q.surveys[id]), pollJSON(p.surveys[id])) {
				t.Errorf("%s: replayed lines read otherwise", sc.Name)
			}
		}
		for _, l := range lines {
			if q.Shows(l) != (q.At(l.ID) != nil) {
				t.Errorf("%s: line %d shown %v", sc.Name, l.ID, q.Shows(l))
			}
		}
	}
}

// TestMadeHere: a survey made, voted in and closed here reads back the same once sent, and a sync
// request brings a member up to date.
func TestMadeHere(t *testing.T) {
	alice, bob := member.Key(make([]byte, 32)), member.Key(append(make([]byte, 31), 1))
	s, err := New([]byte("survey-1"), "Lunch?", Availability, []string{"Mon", "Tue"}, VoterOf(alice))
	if err != nil {
		t.Fatal(err)
	}
	here, there := NewPolls(), NewPolls()
	create := s.CreateMessage()
	for _, p := range []*Polls{here, there} {
		if _, err := p.Receive(alice, &create, 1); err != nil {
			t.Fatal(err)
		}
	}
	if v := here.Survey(create.SurveyID).NextVersion(VoterOf(bob)); v != 0 {
		t.Fatalf("first vote in version %d", v)
	}
	vote := VoteMessage(create.SurveyID, []wire.Choice{{Slot: "s1", Availability: "maybe"}}, 0)
	closing := CloseMessage(create.SurveyID)
	for _, m := range []*wire.Tally{&vote} {
		if _, err := here.Receive(bob, m, 2); err != nil {
			t.Fatal(err)
		}
	}
	if v := here.Survey(create.SurveyID).NextVersion(VoterOf(bob)); v != 1 {
		t.Fatalf("second vote in version %d", v)
	}
	if _, err := here.Receive(bob, &closing, 3); err == nil {
		t.Fatal("bob closed alice's poll")
	}
	if _, err := here.Receive(alice, &closing, 4); err != nil {
		t.Fatal(err)
	}
	req := there.Survey(create.SurveyID).SyncRequest()
	answer, err := here.Receive(bob, &req, 5)
	if err != nil || answer == nil {
		t.Fatalf("no answer: %v", err)
	}
	if _, err := there.Receive(alice, answer, 6); err != nil {
		t.Fatal(err)
	}
	a, b := here.Survey(create.SurveyID), there.Survey(create.SurveyID)
	if !reflect.DeepEqual(pollJSON(a), pollJSON(b)) || !b.Closed() || b.Options()[1].Maybe != 1 {
		t.Fatalf("here %v\nthere %v", pollJSON(a), pollJSON(b))
	}
	if w := Winners(b.Options()); len(w) != 0 {
		t.Fatalf("winners %v", w)
	}
	big := wire.Tally{Kind: wire.MsgTallySyncResp, SurveyID: create.SurveyID, Crdt: make([]byte, MaxCrdt+1)}
	if _, err := there.Receive(alice, &big, 7); err == nil {
		t.Fatal("took an update over the cap")
	}
	if _, err := there.Receive(alice, &wire.Tally{Kind: wire.MsgTallySyncResp, SurveyID: create.SurveyID, Crdt: []byte{0xff, 0xff, 0xff}}, 8); err == nil {
		t.Fatal("took an undecodable update")
	}
}
