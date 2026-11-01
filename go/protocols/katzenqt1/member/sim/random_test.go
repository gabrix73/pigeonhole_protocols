package sim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/member/tracejson"
)

func randomRuns() int {
	if n, err := strconv.Atoi(os.Getenv("RANDOM_RUNS")); err == nil {
		return n
	}
	return 50
}

// TestRandomScripts runs random scripts, checks each rereads as written, and with RANDOM_OUT set
// writes each script and its trace there, for katzenqt's simulator and Lean's replay.
func TestRandomScripts(t *testing.T) {
	dir := os.Getenv("RANDOM_OUT")
	for seed := range uint64(randomRuns()) {
		var trace bytes.Buffer
		rec := func(call string, me member.Key, name string, args map[string]any, result any, g *member.Group) {
			b, err := json.Marshal(tracejson.Line(call, me, name, args, result, g))
			if err != nil {
				t.Fatal(err)
			}
			trace.Write(append(b, '\n'))
		}
		script, err := RandomScript(seed, 60, rec)
		if err != nil {
			t.Errorf("seed %d: %v", seed, err)
			continue
		}
		again, err := Run(script, nil)
		if err != nil || again != script {
			t.Errorf("seed %d: does not run as written: %v", seed, err)
		}
		if _, _, err := tracejson.Replay(bytes.NewReader(trace.Bytes())); err != nil {
			t.Errorf("seed %d: own trace does not replay: %v", seed, err)
		}
		if dir != "" {
			name := filepath.Join(dir, fmt.Sprintf("random-%04d", seed))
			os.WriteFile(name+".txt", []byte(script), 0o644)
			os.WriteFile(name+".jsonl", trace.Bytes(), 0o644)
		}
	}
}
