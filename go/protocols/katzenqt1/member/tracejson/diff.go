package tracejson

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

func bytesReader(b []byte) *strings.Reader { return strings.NewReader(string(b)) }

func compact(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Diff says where two values first differ, if they do. An object's missing field counts as
// null, as Lean's replay reads it.
func Diff(path string, ours, theirs any) (string, bool) {
	switch a := ours.(type) {
	case map[string]any:
		if b, ok := theirs.(map[string]any); ok {
			keys := make([]string, 0, len(a)+len(b))
			for k := range a {
				keys = append(keys, k)
			}
			for k := range b {
				if _, ok := a[k]; !ok {
					keys = append(keys, k)
				}
			}
			slices.Sort(keys)
			for _, k := range keys {
				if d, ok := Diff(path+"."+k, a[k], b[k]); ok {
					return d, true
				}
			}
			return "", false
		}
	case []any:
		if b, ok := theirs.([]any); ok {
			if len(a) != len(b) {
				return fmt.Sprintf("%s: %d items here, %d in the trace\n  here  %s\n  trace %s",
					path, len(a), len(b), compact(a), compact(b)), true
			}
			for i := range a {
				if d, ok := Diff(fmt.Sprintf("%s[%d]", path, i), a[i], b[i]); ok {
					return d, true
				}
			}
			return "", false
		}
	}
	switch ours.(type) {
	case map[string]any, []any:
	default:
		switch theirs.(type) {
		case map[string]any, []any:
		default:
			if ours == theirs {
				return "", false
			}
		}
	}
	return fmt.Sprintf("%s: here %s, in the trace %s", path, compact(ours), compact(theirs)), true
}
