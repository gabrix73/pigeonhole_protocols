package wire

import (
	"bytes"
	"crypto/sha256"
	"slices"
)

var membershipDomain = []byte("KP:membership:v1")

// MembershipHash is what a message's membership_hash says of its sender's view of the group, as
// katzenqt's canonical_membership_hash computes it: SHA-256, under a domain, of the members'
// keys, each once, in byte order. A member counts itself as write_cap[32:].
func MembershipHash(readCaps [][]byte) []byte {
	keys := make([][]byte, 0, len(readCaps))
	for _, c := range readCaps {
		keys = append(keys, KeyOf(c))
	}
	slices.SortFunc(keys, bytes.Compare)
	keys = slices.CompactFunc(keys, bytes.Equal)
	h := sha256.New()
	h.Write(membershipDomain)
	for _, k := range keys {
		h.Write(k)
	}
	return h.Sum(nil)
}
