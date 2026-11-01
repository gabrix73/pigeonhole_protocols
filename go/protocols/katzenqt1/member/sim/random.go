package sim

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
)

// RandomScript makes a scenario of steps random commands, each followed by what it printed, for
// differential tests against katzenqt's simulator and Lean's model. The commands are chosen
// from what the world allows as it runs.
func RandomScript(seed uint64, steps int, record Recorder) (script string, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(simError); ok {
				err = errors.New(e.msg)
				return
			}
			panic(r)
		}
	}()
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	w := &world{record: record}
	var out []string
	emit := func(cmd string) {
		var words []string
		for _, f := range strings.Split(cmd, " ") {
			if f != "" {
				words = append(words, f)
			}
		}
		printed := w.command(words)
		out = append(out, cmd, "----")
		out = append(out, printed...)
		out = append(out, "")
	}
	pick := func(l []string) string { return l[rng.IntN(len(l))] }
	if rng.IntN(3) == 0 {
		emit("option passive on")
	}
	if rng.IntN(3) == 0 {
		emit("option delay-writes on")
	}
	for _, o := range []string{"window", "keep-sent", "keep-received"} {
		if rng.IntN(4) == 0 {
			emit(fmt.Sprintf("option %s %d", o, 1+rng.IntN(3)))
		}
	}
	if rng.IntN(4) == 0 {
		emit("option discard-acked off")
	}
	if rng.IntN(4) == 0 {
		emit(fmt.Sprintf("option recheck %d", 1+rng.IntN(4)))
	}
	names := []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"}
	founders := 1 + rng.IntN(3)
	emit("new-group " + strings.Join(names[:founders], " "))
	for range steps {
		joined := w.joinedNames()
		var fresh []string
		for _, n := range names {
			if !slices.Contains(joined, n) {
				fresh = append(fresh, n)
			}
		}
		actor := pick(joined)
		other := pick(joined)
		n := rng.IntN(5)
		switch r := rng.IntN(100); {
		case r < 25:
			emit(fmt.Sprintf("send %s m%d", actor, rng.IntN(1000)))
		case r < 30 && len(fresh) > 0:
			emit(fmt.Sprintf("invite %s %s", actor, pick(fresh)))
		case r < 37 && len(fresh) > 0:
			emit(fmt.Sprintf("introduce %s %s", actor, pick(fresh)))
		case r < 42:
			emit("land " + actor)
		case r < 44:
			emit("abandon " + actor)
		case r < 46 && actor != other:
			emit(fmt.Sprintf("remove %s %s", actor, other))
		case r < 62:
			emit(fmt.Sprintf("read %s %s", actor, other))
		case r < 68:
			emit(fmt.Sprintf("scan %s %s", actor, other))
		case r < 71:
			emit("epoch")
		case r < 74:
			emit("tick")
		case r < 77:
			emit("backfill " + actor)
		case r < 82:
			emit(fmt.Sprintf("roster %s %s", actor, other))
		case r < 87:
			emit(fmt.Sprintf("acks %s %s %d", actor, other, n))
		case r < 91:
			emit("acked " + actor)
		case r < 95:
			emit("inbox " + actor)
		default:
			emit(fmt.Sprintf("peek %s %d", other, n))
		}
	}
	return strings.Join(out, "\n") + "\n", nil
}
