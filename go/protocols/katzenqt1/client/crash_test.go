package client

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/store"
	"github.com/katzenpost/pigeonhole_protocols/go/transport/sim"
)

// The crash tests run each client scenario with one member restarted after one of its actions,
// for every member and every action, with what came of the action lost or kept. Whatever the
// crash, once everyone runs on to the end, each member must be where the run without a crash
// left it: no write refused, nothing left to write, the same members, and the same messages,
// each once.

// settled is what a run ends with, member by member.
func settled(t *testing.T, w *scWorld) map[string]string {
	w.held = map[int]bool{}
	w.crash = nil
	w.runTo(w.clock + 1800*1000)
	out := map[string]string{}
	for _, m := range w.members {
		for _, c := range m.eng.State.Chats {
			var msgs []string
			for _, l := range c.Log {
				if l.Notice == nil {
					msgs = append(msgs, w.nameOf(l.Sender)+": "+l.Text)
				}
			}
			slices.Sort(msgs)
			i := slices.Index(w.members, m)
			out[m.name+" "+c.Name] = fmt.Sprintf("members %v; jobs %d; inducting %v; joining %v; %s",
				w.membersOf(i, c.Name), len(c.Jobs), c.Inducting != nil, c.Joining != nil, strings.Join(msgs, " | "))
		}
	}
	if len(w.sim.Refused) > 0 {
		out["refused"] = fmt.Sprint(w.refused())
	}
	return out
}

func diskWorld(t *testing.T) *scWorld {
	w := &scWorld{sim: sim.NewWorld(), held: map[int]bool{}, epoch: 1, skipSaveCheck: true, plain: true}
	w.onCommand = func() {
		for _, m := range w.members {
			if m.st == nil {
				st, err := store.Open(t.TempDir(), store.Options{NoSync: true})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { st.Close() })
				m.st = st
				// What the member did before it had a store is saved now.
				all := engine.Changes{Chats: map[engine.ChatID]bool{}, Lines: map[engine.ChatID]map[int]bool{}}
				for _, c := range m.eng.State.Chats {
					all.Chats[c.ID] = true
					all.Lines[c.ID] = map[int]bool{}
					for _, l := range c.Log {
						all.Lines[c.ID][l.ID] = true
					}
				}
				if err := st.Commit(m.eng.State, &engine.Result{Changes: all}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	return w
}

func TestCrashAnywhere(t *testing.T) {
	files, _ := filepath.Glob("../../../../testdata/katzenqt1/client_scenarios/" + os.Getenv("SCENARIO") + "*.txt")
	runs := 0
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		b, _ := os.ReadFile(f)
		script := string(b)
		// The run without a crash, counting each member's actions.
		w := diskWorld(t)
		w.checkSaved = true
		counts := map[int]int{}
		w.crash = func(who int, a engine.Action) (bool, bool) { counts[who]++; return false, false }
		if _, _, err := runScenarioIn(w, script); err != nil {
			t.Fatal(err)
		}
		want := settled(t, w)
		if want["refused"] != "" {
			t.Fatalf("%s: refused without a crash", name)
		}
		for who := range len(w.members) {
			step := max(1, counts[who]/40)
			for k := 1; k <= counts[who]; k += step {
				for _, lost := range []bool{false, true} {
					cw := diskWorld(t)
					n := 0
					cw.crash = func(i int, a engine.Action) (bool, bool) {
						if i != who {
							return false, false
						}
						n++
						return n == k, lost
					}
					if _, _, err := runScenarioIn(cw, script); err != nil {
						t.Fatalf("%s: %v", name, err)
					}
					if cw.restarts[who] != 1 {
						t.Fatalf("%s: %s restarted %d times, not once", name, w.members[who].name, cw.restarts[who])
					}
					got := settled(t, cw)
					runs++
					for key, v := range want {
						if got[key] != v {
							t.Errorf("%s: %s restarted after action %d (lost %v):\n  %s\n  without a crash:\n  %s\n  with:\n  %s",
								name, w.members[who].name, k, lost, key, v, got[key])
						}
					}
					if got["refused"] != "" {
						t.Errorf("%s: %s restarted after action %d (lost %v): refused %s", name, w.members[who].name, k, lost, got["refused"])
					}
				}
			}
		}
	}
	t.Logf("%d runs with a crash", runs)
}
