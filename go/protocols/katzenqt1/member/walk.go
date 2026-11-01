package member

// WalkLimit is how far ahead a walk reaches.
const WalkLimit = 256

// WalkWith answers a Walk effect, given how to step from one box's index to the next: the box at
// the furthest of targets fewer than WalkLimit boxes ahead of start, the last keep indexes before
// it (all for keep = 0), and the step count.
func WalkWith(next func(Index) (Index, error), start Index, targets []uint64, keep int) (*Index, []Index, int, error) {
	here := counter(start)
	var target uint64
	found := false
	for _, t := range targets {
		if t >= here && t-here < WalkLimit && (!found || t > target) {
			target, found = t, true
		}
	}
	if !found {
		return nil, nil, 0, nil
	}
	first := here
	if keep != 0 && target-here > uint64(keep) {
		first = target - uint64(keep)
	}
	index := start
	var err error
	for range first - here {
		if index, err = next(index); err != nil {
			return nil, nil, 0, err
		}
	}
	var skipped []Index
	for range target - first {
		skipped = append(skipped, index)
		if index, err = next(index); err != nil {
			return nil, nil, 0, err
		}
	}
	return &index, skipped, int(target - here), nil
}

// DeriveWith answers a DeriveIndexes effect: count indexes after start.
func DeriveWith(next func(Index) (Index, error), start Index, count int) ([]Index, error) {
	out := make([]Index, 0, count)
	for range count {
		var err error
		if start, err = next(start); err != nil {
			return nil, err
		}
		out = append(out, start)
	}
	return out, nil
}
