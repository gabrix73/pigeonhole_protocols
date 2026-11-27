package pqkeys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"

	"github.com/awnumar/memguard"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

// Store defines persistent or memory storage for public key records.
type Store interface {
	Put(record *KeyRecord) error
	GetByFingerprint(fp string) (*KeyRecord, error)
	GetByUserID(uid string) (*KeyRecord, error)
	Revoke(fp string, reason string, sig []byte, ts int64) error
	List(limit, offset int) ([]*KeyRecordSummary, error)
}

// MemoryStore is an in-memory thread-safe implementation of Store.
type MemoryStore struct {
	mu           sync.RWMutex
	byFP         map[string]*KeyRecord
	byUID        map[string]string // userID -> fingerprint
	orderedKeys  []string
}

// NewMemoryStore creates an initialized MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byFP:  make(map[string]*KeyRecord),
		byUID: make(map[string]string),
	}
}

func (m *MemoryStore) Put(record *KeyRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.byFP[record.Fingerprint]; exists {
		return ErrAlreadyExists
	}

	// Copy record
	recCopy := *record
	m.byFP[record.Fingerprint] = &recCopy
	m.orderedKeys = append(m.orderedKeys, record.Fingerprint)

	if record.UserID != "" {
		m.byUID[strings.ToLower(record.UserID)] = record.Fingerprint
	}
	return nil
}

func (m *MemoryStore) GetByFingerprint(fp string) (*KeyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	rec, exists := m.byFP[fp]
	if !exists {
		return nil, ErrNotFound
	}
	recCopy := *rec
	return &recCopy, nil
}

func (m *MemoryStore) GetByUserID(uid string) (*KeyRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	fp, exists := m.byUID[strings.ToLower(uid)]
	if !exists {
		return nil, ErrNotFound
	}
	rec, exists := m.byFP[fp]
	if !exists {
		return nil, ErrNotFound
	}
	recCopy := *rec
	return &recCopy, nil
}

func (m *MemoryStore) Revoke(fp string, reason string, sig []byte, ts int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rec, exists := m.byFP[fp]
	if !exists {
		return ErrNotFound
	}

	rec.Revoked = true
	rec.RevocationReason = reason
	return nil
}

func (m *MemoryStore) List(limit, offset int) ([]*KeyRecordSummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := len(m.orderedKeys)
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []*KeyRecordSummary{}, nil
	}

	if limit <= 0 || limit > 100 {
		limit = 50
	}

	end := offset + limit
	if end > total {
		end = total
	}

	res := make([]*KeyRecordSummary, 0, end-offset)
	for i := offset; i < end; i++ {
		fp := m.orderedKeys[i]
		rec := m.byFP[fp]
		res = append(res, &KeyRecordSummary{
			Fingerprint: rec.Fingerprint,
			UserID:      rec.UserID,
			Timestamp:   rec.Timestamp,
			Revoked:     rec.Revoked,
		})
	}
	return res, nil
}

// ExtractEd25519PublicKey decodes a PQPG armored public key and returns its Ed25519 signing component.
// Format: 5 bytes header ("PQPK\x01") + 32 bytes Ed25519 + 32 bytes X25519 + 1184 bytes ML-KEM-768. Total: 1253 bytes.
func ExtractEd25519PublicKey(armored string) (ed25519.PublicKey, error) {
	lines := strings.Split(armored, "\n")
	var b64Builder strings.Builder
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "-----") || l == "" {
			continue
		}
		b64Builder.WriteString(l)
	}

	raw, err := base64.StdEncoding.DecodeString(b64Builder.String())
	if err != nil {
		return nil, fmt.Errorf("pqkeys: invalid base64 armored key: %w", err)
	}

	const expectedLen = 5 + 32 + 32 + 1184 // 1253
	if len(raw) != expectedLen {
		return nil, fmt.Errorf("pqkeys: unexpected raw key length %d (expected %d)", len(raw), expectedLen)
	}

	if !bytes.HasPrefix(raw, []byte("PQPK\x01")) {
		return nil, fmt.Errorf("pqkeys: missing PQPK magic prefix in public key")
	}

	ed25519Bytes := raw[5 : 5+32]
	return ed25519.PublicKey(ed25519Bytes), nil
}

// ExtractEd25519PrivateKey decodes a PQPG armored private key and returns its Ed25519 signing component.
// Format: 5 bytes header ("PQSK\x01") + 32 bytes Ed25519 seed + 32 bytes X25519 + 2400 bytes ML-KEM-768. Total: 2469 bytes.
func ExtractEd25519PrivateKey(armored string) (ed25519.PrivateKey, error) {
	lines := strings.Split(armored, "\n")
	var b64Builder strings.Builder
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "-----") || l == "" {
			continue
		}
		b64Builder.WriteString(l)
	}

	raw, err := base64.StdEncoding.DecodeString(b64Builder.String())
	if err != nil {
		return nil, fmt.Errorf("pqkeys: invalid base64 armored private key: %w", err)
	}
	defer memguard.WipeBytes(raw)

	const expectedLen = 5 + 32 + 32 + 2400 // 2469
	if len(raw) != expectedLen {
		return nil, fmt.Errorf("pqkeys: unexpected raw key length %d (expected %d)", len(raw), expectedLen)
	}

	if !bytes.HasPrefix(raw, []byte("PQSK\x01")) {
		return nil, fmt.Errorf("pqkeys: missing PQSK magic prefix in private key")
	}

	seed := raw[5 : 5+32]
	seedBuf := memguard.NewBufferFromBytes(seed)
	defer seedBuf.Destroy()

	return ed25519.NewKeyFromSeed(seedBuf.Bytes()), nil
}

// VerifySelfSignature verifies that the publisher holds the private key matching the public key.
func VerifySelfSignature(userID, armoredKey string, timestamp int64, signature []byte) error {
	pub, err := ExtractEd25519PublicKey(armoredKey)
	if err != nil {
		return err
	}

	expectedPayload := SignedPayload(userID, armoredKey, timestamp)
	if !ed25519.Verify(pub, expectedPayload, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// VerifyRevocationSignature verifies that the revocation request is signed by the registered key owner.
func VerifyRevocationSignature(armoredKey, fingerprint, reason string, timestamp int64, signature []byte) error {
	pub, err := ExtractEd25519PublicKey(armoredKey)
	if err != nil {
		return err
	}

	payload := RevocationSignedPayload(fingerprint, reason, timestamp)
	if !ed25519.Verify(pub, payload, signature) {
		return ErrInvalidSignature
	}
	return nil
}

// Serve handles incoming client requests over a bidirectional connection.
func Serve(ctx context.Context, s Conn, store Store) error {
	for {
		raw, err := s.Recv(ctx)
		if err != nil {
			return err
		}

		var req Request
		if err := common.Unmarshal(raw, &req); err != nil {
			reply, _ := common.Marshal(&Reply{
				Success: false,
				Error:   "bad request: unmarshal error",
			})
			_ = s.Send(ctx, reply)
			continue
		}

		reply := handleRequest(store, &req)
		replyBytes, err := common.Marshal(reply)
		if err != nil {
			return err
		}

		if err := s.Send(ctx, replyBytes); err != nil {
			return err
		}
	}
}

func handleRequest(store Store, req *Request) *Reply {
	reply := &Reply{
		Action: req.Action,
	}

	switch req.Action {
	case ActionPublish:
		if req.Publish == nil || req.Publish.ArmoredPublicKey == "" {
			reply.Error = ErrBadRequest.Error()
			return reply
		}

		// Verify signature
		if err := VerifySelfSignature(req.Publish.UserID, req.Publish.ArmoredPublicKey, req.Publish.Timestamp, req.Publish.Signature); err != nil {
			reply.Error = err.Error()
			return reply
		}

		fp := ComputeFingerprint(req.Publish.ArmoredPublicKey)
		rec := &KeyRecord{
			Fingerprint:      fp,
			UserID:           req.Publish.UserID,
			ArmoredPublicKey: req.Publish.ArmoredPublicKey,
			Signature:        req.Publish.Signature,
			Timestamp:        req.Publish.Timestamp,
			Revoked:          false,
		}

		if err := store.Put(rec); err != nil {
			reply.Error = err.Error()
			return reply
		}

		reply.Success = true
		reply.KeyRecord = rec

	case ActionLookup:
		if req.Lookup == nil || req.Lookup.Query == "" {
			reply.Error = ErrBadRequest.Error()
			return reply
		}

		query := req.Lookup.Query
		rec, err := store.GetByFingerprint(query)
		if err != nil {
			// Try lookup by user ID
			rec, err = store.GetByUserID(query)
		}

		if err != nil {
			reply.Error = ErrNotFound.Error()
			return reply
		}

		reply.Success = true
		reply.KeyRecord = rec

	case ActionRevoke:
		if req.Revoke == nil || req.Revoke.Fingerprint == "" {
			reply.Error = ErrBadRequest.Error()
			return reply
		}

		existing, err := store.GetByFingerprint(req.Revoke.Fingerprint)
		if err != nil {
			reply.Error = ErrNotFound.Error()
			return reply
		}

		if err := VerifyRevocationSignature(existing.ArmoredPublicKey, req.Revoke.Fingerprint, req.Revoke.Reason, req.Revoke.Timestamp, req.Revoke.Signature); err != nil {
			reply.Error = err.Error()
			return reply
		}

		if err := store.Revoke(req.Revoke.Fingerprint, req.Revoke.Reason, req.Revoke.Signature, req.Revoke.Timestamp); err != nil {
			reply.Error = err.Error()
			return reply
		}

		existing.Revoked = true
		existing.RevocationReason = req.Revoke.Reason
		reply.Success = true
		reply.KeyRecord = existing

	case ActionList:
		limit := 50
		offset := 0
		if req.List != nil {
			if req.List.Limit > 0 {
				limit = req.List.Limit
			}
			offset = req.List.Offset
		}

		summaries, err := store.List(limit, offset)
		if err != nil {
			reply.Error = err.Error()
			return reply
		}

		reply.Success = true
		reply.Keys = summaries

	default:
		reply.Error = fmt.Sprintf("unsupported action %d", req.Action)
	}

	return reply
}
