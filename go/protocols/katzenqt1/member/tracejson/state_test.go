package tracejson

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestStateRoundTrip reads back every state in the traces and checks it writes as it was.
func TestStateRoundTrip(t *testing.T) {
	files, _ := filepath.Glob("../../../../../testdata/katzenqt1/groupchat_traces/*.jsonl")
	if d := os.Getenv("TRACES"); d != "" {
		more, _ := filepath.Glob(filepath.Join(d, "*.jsonl"))
		files = append(files, more...)
	}
	n := 0
	for _, f := range files {
		r, _ := os.Open(f)
		sc := bufio.NewScanner(r)
		sc.Buffer(nil, 64<<20)
		for sc.Scan() {
			line, err := Parse(sc.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			g, err := ReadGroup(line["state"])
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			// Write through JSON as a saved state would be.
			b, _ := json.Marshal(Group(g))
			back, _ := Parse(append(append([]byte(`{"s":`), b...), '}'))
			if d, ok := Diff("state", back["s"], line["state"]); ok {
				t.Fatalf("%s: %s", f, d)
			}
			n++
		}
		r.Close()
	}
	t.Logf("%d states", n)
}
