package tracejson

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplayKatzenqtTraces(t *testing.T) {
	files, _ := filepath.Glob("../../../../../testdata/katzenqt1/groupchat_traces/*.jsonl")
	if len(files) != 20 {
		t.Fatalf("%d traces", len(files))
	}
	replayAll(t, files)
}

// TestReplayMoreTraces replays the traces in $TRACES, such as fresh random runs from katzenqt's
// tools/groupchat_traces.py.
func TestReplayMoreTraces(t *testing.T) {
	dir := os.Getenv("TRACES")
	if dir == "" {
		t.Skip("TRACES not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if len(files) == 0 {
		t.Fatalf("no traces in %s", dir)
	}
	replayAll(t, files)
}

func replayAll(t *testing.T, files []string) {
	calls, checks := 0, 0
	for _, f := range files {
		r, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		n, c, err := Replay(r)
		r.Close()
		calls += n
		checks += c
		if err != nil {
			t.Errorf("%s:%v", filepath.Base(f), err)
		}
	}
	t.Logf("%d traces, %d calls, %d BACAP checks", len(files), calls, checks)
}
