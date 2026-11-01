package member

import "github.com/katzenpost/hpqc/bacap"

// NextIndex is the index of the box after i, by BACAP.
func NextIndex(i Index) (Index, error) {
	m, err := bacap.NewEmptyMessageBoxIndexFromBytes([]byte(i))
	if err != nil {
		return "", err
	}
	n, err := m.NextIndex()
	if err != nil {
		return "", err
	}
	b, err := n.MarshalBinary()
	return Index(b), err
}
