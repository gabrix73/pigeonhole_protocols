package sim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKatzenqtScenarios(t *testing.T) {
	files, _ := filepath.Glob("../../../../../testdata/katzenqt1/groupchat_scenarios/*.txt")
	if len(files) != 14 {
		t.Fatalf("%d scenarios", len(files))
	}
	for _, f := range files {
		script, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Run(string(script), nil)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		if got != string(script) {
			a, e := strings.Split(got, "\n"), strings.Split(string(script), "\n")
			for i := range min(len(a), len(e)) {
				if a[i] != e[i] {
					t.Errorf("%s: line %d: expected %q, got %q", filepath.Base(f), i+1, e[i], a[i])
					break
				}
			}
			if len(a) != len(e) {
				t.Errorf("%s: %d lines, expected %d", filepath.Base(f), len(a), len(e))
			}
		}
	}
}
