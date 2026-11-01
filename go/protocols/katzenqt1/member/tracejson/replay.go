package tracejson

import (
	"bufio"
	"fmt"
	"io"
	"slices"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
)

// A trace line is one call on a member. Replay makes the same call on a Group and requires the
// same result and state, and checks the trace's BACAP steps against hpqc's BACAP.

type walkAsked struct {
	stream  member.Key
	start   member.Index
	targets []uint64
	keep    int
}

type deriveAsked struct {
	start member.Index
	count int
}

// asked is what a member has asked BACAP for and not yet been told.
type asked struct {
	derives []deriveAsked
	walks   []walkAsked
}

func checkBACAP(a *asked, line map[string]any, effects []member.Effect) int {
	args := field(line, "args")
	checks := 0
	switch str(field(line, "call")) {
	case "handle":
		switch e := readEvent(field(args, "event")).(type) {
		case member.BoxRead:
			if e.Next != nil {
				checks++
				if n, err := member.NextIndex(e.Index); err != nil || n != *e.Next {
					fail("the index after a box read is not BACAP's")
				}
			}
		case member.IndexesDerived:
			if len(a.derives) == 0 {
				fail("indexes derived that were not asked for")
			}
			d := a.derives[0]
			a.derives = a.derives[1:]
			checks++
			got, err := member.DeriveWith(member.NextIndex, d.start, d.count)
			if err != nil || !slices.Equal(got, e.Indexes) {
				fail("the indexes derived are not BACAP's")
			}
		case member.Walked:
			i := slices.IndexFunc(a.walks, func(w walkAsked) bool { return w.stream == e.Stream })
			if i < 0 {
				fail("a walk that was not asked for")
			}
			w := a.walks[i]
			a.walks = slices.Delete(a.walks, i, i+1)
			checks++
			if len(w.start) != 104 {
				fail("the walk's result is not BACAP's")
			}
			target, skipped, steps, err := member.WalkWith(member.NextIndex, w.start, w.targets, w.keep)
			if err != nil || steps != e.Steps || !slices.Equal(skipped, e.Skipped) ||
				(target == nil) != (e.Target == nil) || target != nil && *target != *e.Target {
				fail("the walk's result is not BACAP's")
			}
		}
	case "observe":
		checks++
		if n, err := member.NextIndex(index(field(args, "index"))); err != nil || n != index(field(args, "next")) {
			fail("the index after an observed box is not BACAP's")
		}
	}
	for _, e := range effects {
		switch e := e.(type) {
		case member.DeriveIndexes:
			a.derives = append(a.derives, deriveAsked{e.Start, e.Count})
		case member.Walk:
			a.walks = append(a.walks, walkAsked{e.Stream, e.Start, e.Targets, e.Keep})
		}
	}
	return checks
}

// Call makes one recorded call on g (nil before the member starts), returning what it returned,
// the effects it asked for, and the member after.
func Call(g *member.Group, line map[string]any) (any, []member.Effect, *member.Group, error) {
	type out struct {
		result  any
		effects []member.Effect
		g       *member.Group
	}
	o, err := get(func() out {
		args := field(line, "args")
		policy := readRetention(field(args, "policy"))
		recheck := natural(field(args, "recheck"))
		name := str(field(line, "call"))
		// A client may change its policy between calls; each call says which was in force.
		if g != nil {
			g.Policy = policy
		}
		switch name {
		case "found":
			var founders [][]byte
			for _, f := range items(field(args, "founders")) {
				founders = append(founders, bytesOf(f))
			}
			return out{nil, nil, member.Found(bytesOf(field(args, "read_cap")), founders, policy, recheck)}
		case "joined":
			return out{nil, nil, member.Joined(bytesOf(field(args, "read_cap")), readJoinReply(field(args, "reply")), policy, recheck)}
		}
		if g == nil {
			fail("%s before the member started", name)
		}
		switch name {
		case "handle":
			es := g.Handle(readEvent(field(args, "event")))
			return out{Effects(es), es, g}
		case "observe":
			es := g.Observe(key(field(args, "stream")), index(field(args, "index")),
				optMessage(field(args, "message")), index(field(args, "next")))
			return out{Effects(es), es, g}
		case "compose":
			var content []byte
			if c := field(args, "content"); c != nil {
				content = bytesOf(c)
			}
			return out{Outgoings(g.Compose(content)), nil, g}
		case "written":
			var p *member.Payload
			if j := field(args, "payload"); j != nil {
				v := readPayload(j)
				p = &v
			}
			g.Written(natural(field(args, "token")), index(field(args, "index")), p)
			return out{nil, nil, g}
		case "abandoned":
			g.Abandoned(natural(field(args, "token")))
			return out{nil, nil, g}
		case "begin_induction":
			return out{Outgoings(g.BeginInduction()), nil, g}
		case "introduce_now":
			return out{Outgoing(g.IntroduceNow(str(field(args, "name")), bytesOf(field(args, "read_cap")))), nil, g}
		case "cancel_induction":
			g.CancelInduction()
			return out{nil, nil, g}
		case "reply":
			return out{JoinReply(g.Reply(index(field(args, "own_start")))), nil, g}
		case "remove":
			g.Remove(key(field(args, "member")))
			return out{nil, nil, g}
		}
		fail("unknown call %s", name)
		return out{}
	})
	return o.result, o.effects, o.g, err
}

// Replay replays one trace, returning the number of calls replayed and BACAP checks made.
func Replay(r io.Reader) (calls, checks int, err error) {
	type state struct {
		g *member.Group
		a asked
	}
	members := map[string]*state{}
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 64<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		calls++
		line, err := Parse(sc.Bytes())
		if err != nil {
			return calls, checks, fmt.Errorf("line %d: not JSON: %w", calls, err)
		}
		me, _ := line["me"].(string)
		who, _ := line["member"].(string)
		if who == "" {
			who = me
		}
		callName, _ := line["call"].(string)
		st := members[me]
		if st == nil {
			st = &state{}
		}
		result, effects, g, err := Call(st.g, line)
		if err != nil {
			return calls, checks, fmt.Errorf("line %d: %s %s: %w", calls, who, callName, err)
		}
		if d, ok := Diff("result", result, line["result"]); ok {
			return calls, checks, fmt.Errorf("line %d: %s %s: %s", calls, who, callName, d)
		}
		if d, ok := Diff("state", Group(g), line["state"]); ok {
			return calls, checks, fmt.Errorf("line %d: %s %s: %s", calls, who, callName, d)
		}
		c, err := get(func() int { return checkBACAP(&st.a, line, effects) })
		if err != nil {
			return calls, checks, fmt.Errorf("line %d: %s %s: %w", calls, who, callName, err)
		}
		checks += c
		st.g = g
		members[me] = st
	}
	return calls, checks, sc.Err()
}
