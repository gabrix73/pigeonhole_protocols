// SPDX-License-Identifier: AGPL-3.0-only

package nntp

import (
	"sort"
	"strings"

	svc "github.com/katzenpost/pigeonhole_protocols/go/services/nntp"
)

// ThreadNode represents one article inside a RFC 5536 References thread tree.
type ThreadNode struct {
	Entry      svc.OverviewEntry
	Hidden     bool
	HideReason string
	Children   []*ThreadNode
	parent     *ThreadNode
	Depth      int
}

// BuildThreads builds a forest of ThreadNodes from overview entries using the
// References header (attaching each entry to the nearest present ancestor) with
// cycle protection and deterministic numeric ordering.
func BuildThreads(entries []svc.OverviewEntry, kf *Killfile) []*ThreadNode {
	if len(entries) == 0 {
		return nil
	}
	sorted := make([]svc.OverviewEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Number < sorted[j].Number
	})

	counts := AuthorCounts(sorted)
	nodes := make([]*ThreadNode, len(sorted))
	byID := make(map[string]*ThreadNode, len(sorted))

	for i, e := range sorted {
		hidden, reason := kf.EvaluateOverview(e, counts)
		n := &ThreadNode{
			Entry:      e,
			Hidden:     hidden,
			HideReason: reason,
		}
		nodes[i] = n
		mid := strings.TrimSpace(e.MessageID)
		if mid != "" {
			byID[mid] = n
		}
	}

	var roots []*ThreadNode
	for _, n := range nodes {
		parent := findNearestParent(n, byID)
		if parent != nil && !wouldCycle(n, parent) {
			n.parent = parent
			parent.Children = append(parent.Children, n)
		} else {
			roots = append(roots, n)
		}
	}

	var assignDepth func(list []*ThreadNode, depth int)
	assignDepth = func(list []*ThreadNode, depth int) {
		for _, n := range list {
			n.Depth = depth
			assignDepth(n.Children, depth+1)
		}
	}
	assignDepth(roots, 0)
	return roots
}

func findNearestParent(n *ThreadNode, byID map[string]*ThreadNode) *ThreadNode {
	refs := strings.Fields(n.Entry.References)
	for i := len(refs) - 1; i >= 0; i-- {
		ref := strings.TrimSpace(refs[i])
		if ref == "" || ref == strings.TrimSpace(n.Entry.MessageID) {
			continue
		}
		if p, ok := byID[ref]; ok && p != n {
			return p
		}
	}
	return nil
}

func wouldCycle(child, candidateParent *ThreadNode) bool {
	for cur := candidateParent; cur != nil; cur = cur.parent {
		if cur == child {
			return true
		}
	}
	return false
}
