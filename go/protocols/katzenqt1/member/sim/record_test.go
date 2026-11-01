package sim

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member/tracejson"
)

// recordScenario runs a scenario, returning the trace of every call made on its members.
func recordScenario(t *testing.T, script string) []map[string]any {
	var lines []map[string]any
	rec := func(call string, me member.Key, name string, args map[string]any, result any, g *member.Group) {
		// Round trip through JSON so the line is in the form a trace file is read in.
		b, err := json.Marshal(tracejson.Line(call, me, name, args, result, g))
		if err != nil {
			t.Fatal(err)
		}
		l, err := tracejson.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, l)
	}
	if _, err := Run(script, rec); err != nil {
		t.Fatal(err)
	}
	return lines
}

// TestTracesMatchKatzenqt checks that each scenario makes the calls katzenqt's simulator made,
// with the same arguments, results and states, as its recorded trace says.
func TestTracesMatchKatzenqt(t *testing.T) {
	files, _ := filepath.Glob("../../../../../testdata/katzenqt1/groupchat_scenarios/*.txt")
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".txt")
		script, _ := os.ReadFile(f)
		ours := recordScenario(t, string(script))
		theirs := readTrace(t, "../../../../../testdata/katzenqt1/groupchat_traces/scenario-"+name+".jsonl")
		if len(ours) != len(theirs) {
			t.Errorf("%s: %d calls, katzenqt made %d", name, len(ours), len(theirs))
		}
		for i := range min(len(ours), len(theirs)) {
			if d, ok := tracejson.Diff(fmt.Sprintf("%s:%d", name, i+1), ours[i], theirs[i]); ok {
				t.Errorf("%s", d)
				break
			}
		}
	}
}

func readTrace(t *testing.T, path string) []map[string]any {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(nil, 64<<20)
	for sc.Scan() {
		if l, err := tracejson.Parse(sc.Bytes()); err == nil {
			out = append(out, l)
		} else {
			t.Fatal(err)
		}
	}
	return out
}

// TestWriteTraces writes each scenario's trace to $TRACE_OUT, for replay by Lean's model.
func TestWriteTraces(t *testing.T) {
	dir := os.Getenv("TRACE_OUT")
	if dir == "" {
		t.Skip("TRACE_OUT not set")
	}
	files, _ := filepath.Glob("../../../../../testdata/katzenqt1/groupchat_scenarios/*.txt")
	for _, f := range files {
		script, _ := os.ReadFile(f)
		var buf bytes.Buffer
		for _, l := range recordScenario(t, string(script)) {
			b, _ := json.Marshal(l)
			buf.Write(append(b, '\n'))
		}
		out := filepath.Join(dir, "go-"+strings.TrimSuffix(filepath.Base(f), ".txt")+".jsonl")
		if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
