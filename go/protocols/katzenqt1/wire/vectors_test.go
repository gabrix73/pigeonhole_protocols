package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"
)

const testdata = "../../../../testdata/katzenqt1/"

func load(t *testing.T, name string) map[string]any {
	t.Helper()
	f, err := os.Open(testdata + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.UseNumber()
	var v map[string]any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, v any) []byte {
	t.Helper()
	b, err := hex.DecodeString(v.(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func num(v any) json.Number { return v.(json.Number) }

func intOf(t *testing.T, v any) int {
	n, err := num(v).Int64()
	if err != nil {
		t.Fatal(err)
	}
	return int(n)
}

func hexOrNull(b []byte, present bool) any {
	if !present {
		return nil
	}
	return hex.EncodeToString(b)
}

func numOf(n uint64) json.Number { return json.Number(new(json.Number).String() + itoa(n)) }

func itoa(n uint64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// messageJSON writes m in the vectors' shape.
func messageJSON(m *Message) any {
	if m == nil {
		return nil
	}
	numbers := []any{}
	for _, n := range m.Numbers {
		numbers = append(numbers, []any{numOf(uint64(n.Index)), hexOrNull(n.Prefix, n.Prefix != nil)})
	}
	acks := []any{}
	for _, a := range m.Acks {
		acks = append(acks, []any{numOf(uint64(a.Member)), numOf(a.Idx64)})
	}
	var intro, at any
	if m.Introduction != nil {
		intro = map[string]any{"name": m.Introduction.Name, "read_cap": hex.EncodeToString(m.Introduction.ReadCap)}
	}
	if m.IntroducedAt != nil {
		at = map[string]any{"introducer": numOf(uint64(m.IntroducedAt.Introducer)), "index": hex.EncodeToString(m.IntroducedAt.Index)}
	}
	return map[string]any{"content": hexOrNull(m.Content, m.Content != nil), "introduction": intro,
		"numbers": numbers, "introduced_at": at, "acks": acks,
		"membership_hash": hexOrNull(m.MembershipHash, m.MembershipHash != nil)}
}

func joinReplyJSON(r *JoinReply) any {
	if r == nil {
		return nil
	}
	members := []any{}
	for _, m := range r.Members {
		if m == nil {
			members = append(members, nil)
		} else {
			members = append(members, []any{hex.EncodeToString(m.ReadCap), hex.EncodeToString(m.Start)})
		}
	}
	rosters := []any{}
	for _, ro := range r.Rosters {
		if ro == nil {
			rosters = append(rosters, nil)
			continue
		}
		es := []any{}
		for _, e := range ro.Entries {
			var slot any
			if e.Place != nil {
				slot = numOf(uint64(*e.Place))
			}
			es = append(es, []any{numOf(uint64(e.Index)), slot})
		}
		rosters = append(rosters, es)
	}
	intros := []any{}
	for _, i := range r.Introductions {
		intros = append(intros, []any{numOf(uint64(i.By)), hex.EncodeToString(i.Index), numOf(uint64(i.Member))})
	}
	return map[string]any{"members": members, "rosters": rosters, "introductions": intros,
		"introducer": numOf(uint64(r.Introducer)), "newcomer": numOf(uint64(r.Newcomer))}
}

func readMessage(t *testing.T, v any) *Message {
	j := v.(map[string]any)
	m := &Message{}
	if c := j["content"]; c != nil {
		m.Content = unhex(t, c)
	}
	if i := j["introduction"]; i != nil {
		i := i.(map[string]any)
		m.Introduction = &Introduction{Name: i["name"].(string), ReadCap: unhex(t, i["read_cap"])}
	}
	for _, n := range j["numbers"].([]any) {
		p := n.([]any)
		num := Number{Index: intOf(t, p[0])}
		if p[1] != nil {
			num.Prefix = unhex(t, p[1])
		}
		m.Numbers = append(m.Numbers, num)
	}
	if a := j["introduced_at"]; a != nil {
		a := a.(map[string]any)
		m.IntroducedAt = &IntroRef{Introducer: intOf(t, a["introducer"]), Index: unhex(t, a["index"])}
	}
	for _, a := range j["acks"].([]any) {
		p := a.([]any)
		idx, err := strconvU(num(p[1]))
		if err != nil {
			t.Fatal(err)
		}
		m.Acks = append(m.Acks, Ack{Member: intOf(t, p[0]), Idx64: idx})
	}
	if h := j["membership_hash"]; h != nil {
		m.MembershipHash = unhex(t, h)
	}
	return m
}

func strconvU(n json.Number) (uint64, error) {
	var u uint64
	err := json.Unmarshal([]byte(n), &u)
	return u, err
}

// mapForm is g written in the map form, as these vectors were, like Python's box_of(m, hash,
// MAP_VERSION).
func mapForm(g *Gcm) []byte {
	g.Version = min(g.Version, MapVersion)
	return g.Encode()
}

func TestWireVectors(t *testing.T) {
	v := load(t, "groupchat_wire_vectors.json")
	count := 0
	for _, e := range v["messages"].([]any) {
		e := e.(map[string]any)
		name := e["name"].(string)
		cbor := unhex(t, e["cbor"])
		got := ToMessage(cbor)
		if !reflect.DeepEqual(messageJSON(got), e["message"]) {
			t.Errorf("%s: read as %v, want %v", name, messageJSON(got), e["message"])
		}
		rw, hasRw := e["rewritten"], e["rewritten"] != nil
		switch {
		case got != nil && hasRw:
			want := unhex(t, rw)
			if g := OfMessage(got); g == nil || !bytes.Equal(mapForm(g), want) {
				t.Errorf("%s: written back differently", name)
			}
			if bytes.Equal(want, cbor) {
				if g := DecodeGcm(cbor); g == nil || !bytes.Equal(g.Encode(), cbor) {
					t.Errorf("%s: does not decode and encode to itself", name)
				}
			}
		case got == nil && !hasRw:
		default:
			t.Errorf("%s: inconsistent with the vector", name)
		}
		count++
	}
	for _, e := range v["written"].([]any) {
		e := e.(map[string]any)
		if g := OfMessage(readMessage(t, e["message"])); !bytes.Equal(Frame(mapForm(g)), unhex(t, e["box"])) {
			t.Errorf("%s: written as another box", e["name"])
		}
		count++
	}
	for _, e := range v["membership"].([]any) {
		e := e.(map[string]any)
		var caps [][]byte
		for _, c := range e["read_caps"].([]any) {
			caps = append(caps, unhex(t, c))
		}
		if !bytes.Equal(MembershipHash(caps), unhex(t, e["hash"])) {
			t.Errorf("membership of %d: a different hash", len(caps))
		}
		count++
	}
	for _, e := range v["replies"].([]any) {
		e := e.(map[string]any)
		name := e["name"].(string)
		cbor := unhex(t, e["cbor"])
		w := DecodeReplyWho(cbor)
		if w == nil {
			t.Errorf("%s: does not decode", name)
			continue
		}
		if !bytes.Equal(w.EncodeMap(), cbor) {
			t.Errorf("%s: encodes differently", name)
		}
		if got := joinReplyJSON(w.ToJoinReply()); !reflect.DeepEqual(got, e["join_reply"]) {
			t.Errorf("%s: carries %v, want %v", name, got, e["join_reply"])
		}
		count++
	}
	if count != 19+6+6+5 {
		t.Errorf("%d vectors", count)
	}
}

func readAcks(t *testing.T, v any) []Ack {
	var acks []Ack
	for _, a := range v.([]any) {
		p := a.([]any)
		idx, err := strconvU(num(p[1]))
		if err != nil {
			t.Fatal(err)
		}
		acks = append(acks, Ack{Member: intOf(t, p[0]), Idx64: idx})
	}
	// The vectors list a set of acknowledgements; the field holds them by roster index.
	slices.SortStableFunc(acks, func(a, b Ack) int { return a.Member - b.Member })
	return acks
}

func TestAcksVectors(t *testing.T) {
	v := load(t, "acks_vectors.json")
	for _, e := range v["valid"].([]any) {
		e := e.(map[string]any)
		acks, field := readAcks(t, e["acks"]), unhex(t, e["field"])
		if !bytes.Equal(EncodeAcks(acks), field) {
			t.Errorf("%s: encodes to %x", e["name"], EncodeAcks(acks))
		}
		got, err := DecodeAcks(field)
		if err != nil || !reflect.DeepEqual(got, acks) {
			t.Errorf("%s: decodes to %v %v", e["name"], got, err)
		}
	}
	for _, e := range v["lenient"].([]any) {
		e := e.(map[string]any)
		got, err := DecodeAcks(unhex(t, e["field"]))
		if err != nil || !reflect.DeepEqual(got, readAcks(t, e["acks"])) {
			t.Errorf("%s: decodes to %v %v", e["name"], got, err)
		}
	}
	for _, e := range v["malformed"].([]any) {
		e := e.(map[string]any)
		if got, err := DecodeAcks(unhex(t, e["field"])); err == nil {
			t.Errorf("%s: accepted as %v", e["name"], got)
		}
	}
}
