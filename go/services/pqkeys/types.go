// Package pqkeys implements an asynchronous, blind post-quantum public key directory
// and distribution service over Pigeonhole and Katzenpost mixnet framing.
package pqkeys

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Actions supported by the PQKeys protocol.
const (
	ActionPublish uint8 = 1
	ActionLookup  uint8 = 2
	ActionRevoke  uint8 = 3
	ActionList    uint8 = 4
)

// Standard error messages.
var (
	ErrNotFound         = errors.New("pqkeys: key record not found")
	ErrAlreadyExists    = errors.New("pqkeys: fingerprint already registered")
	ErrInvalidSignature = errors.New("pqkeys: self-signature verification failed")
	ErrKeyRevoked       = errors.New("pqkeys: key has been revoked")
	ErrBadRequest       = errors.New("pqkeys: malformed request payload")
)

// Conn represents an abstract bidirectional connection over Pigeonhole/Sphinx framing.
type Conn interface {
	Recv(ctx context.Context) ([]byte, error)
	Send(ctx context.Context, msg []byte) error
}

// Request is the envelope sent by the client.
type Request struct {
	Action  uint8           `cbor:"1,keyasint"`
	Publish *PublishPayload `cbor:"2,keyasint,omitempty"`
	Lookup  *LookupPayload  `cbor:"3,keyasint,omitempty"`
	Revoke  *RevokePayload  `cbor:"4,keyasint,omitempty"`
	List    *ListPayload    `cbor:"5,keyasint,omitempty"`
}

// Reply is the envelope returned by the service.
type Reply struct {
	Action    uint8               `cbor:"1,keyasint"`
	Success   bool                `cbor:"2,keyasint"`
	Error     string              `cbor:"3,keyasint,omitempty"`
	KeyRecord *KeyRecord          `cbor:"4,keyasint,omitempty"`
	Keys      []*KeyRecordSummary `cbor:"5,keyasint,omitempty"`
}

// PublishPayload contains the data required to register or update a post-quantum public key.
type PublishPayload struct {
	UserID           string `cbor:"1,keyasint,omitempty"`
	ArmoredPublicKey string `cbor:"2,keyasint"`
	Signature        []byte `cbor:"3,keyasint"` // Ed25519 signature over SignedPayload()
	Timestamp        int64  `cbor:"4,keyasint"` // Unix epoch seconds
}

// LookupPayload is used to retrieve a public key by fingerprint or user ID.
type LookupPayload struct {
	Query string `cbor:"1,keyasint"` // Fingerprint (hex) or UserID
}

// RevokePayload is used to mark a key as permanently revoked.
type RevokePayload struct {
	Fingerprint string `cbor:"1,keyasint"`
	Reason      string `cbor:"2,keyasint"`
	Signature   []byte `cbor:"3,keyasint"` // Ed25519 signature over RevocationPayload()
	Timestamp   int64  `cbor:"4,keyasint"`
}

// ListPayload requests paginated summaries of stored keys.
type ListPayload struct {
	Limit  int `cbor:"1,keyasint,omitempty"`
	Offset int `cbor:"2,keyasint,omitempty"`
}

// KeyRecord represents a stored post-quantum public key entry.
type KeyRecord struct {
	Fingerprint      string `cbor:"1,keyasint"`
	UserID           string `cbor:"2,keyasint,omitempty"`
	ArmoredPublicKey string `cbor:"3,keyasint"`
	Signature        []byte `cbor:"4,keyasint"`
	Timestamp        int64  `cbor:"5,keyasint"`
	Revoked          bool   `cbor:"6,keyasint"`
	RevocationReason string `cbor:"7,keyasint,omitempty"`
}

// KeyRecordSummary provides a compact view for directory listings without full armored keys.
type KeyRecordSummary struct {
	Fingerprint string `cbor:"1,keyasint"`
	UserID      string `cbor:"2,keyasint,omitempty"`
	Timestamp   int64  `cbor:"3,keyasint"`
	Revoked     bool   `cbor:"4,keyasint"`
}

// ComputeFingerprint returns the SHA-256 hex digest of the normalized armored public key.
func ComputeFingerprint(armoredKey string) string {
	h := sha256.Sum256([]byte(armoredKey))
	return hex.EncodeToString(h[:])
}

// SignedPayload formats the canonical byte representation that must be self-signed by the key owner.
func SignedPayload(userID, armoredKey string, timestamp int64) []byte {
	return []byte(fmt.Sprintf("PQKEYS-PUBLISH-V1|%s|%s|%d", userID, armoredKey, timestamp))
}

// RevocationSignedPayload formats the canonical byte representation for revoking a key.
func RevocationSignedPayload(fingerprint, reason string, timestamp int64) []byte {
	return []byte(fmt.Sprintf("PQKEYS-REVOKE-V1|%s|%s|%d", fingerprint, reason, timestamp))
}
