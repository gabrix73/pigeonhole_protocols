package pqkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/stretchr/testify/require"
)

// pipeConn implements a simple in-memory duplex Conn for unit testing.
type pipeConn struct {
	in       chan []byte
	out      chan []byte
	done     chan struct{}
	closeOnce *sync.Once
}

func newPipePair() (*pipeConn, *pipeConn) {
	c1 := make(chan []byte, 10)
	c2 := make(chan []byte, 10)
	done := make(chan struct{})
	once := &sync.Once{}

	return &pipeConn{in: c1, out: c2, done: done, closeOnce: once},
		&pipeConn{in: c2, out: c1, done: done, closeOnce: once}
}

func (p *pipeConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, context.Canceled
	case msg, ok := <-p.in:
		if !ok {
			return nil, context.Canceled
		}
		return msg, nil
	}
}

func (p *pipeConn) Send(ctx context.Context, msg []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return context.Canceled
	case p.out <- msg:
		return nil
	}
}

func (p *pipeConn) Close() {
	p.closeOnce.Do(func() {
		close(p.done)
	})
}

// generateDummyArmoredKey creates a synthetic 1253-byte PQPG armored public key with valid Ed25519 pubkey.
func generateDummyArmoredKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	raw := make([]byte, 1253)
	copy(raw[:5], []byte("PQPK\x01"))
	copy(raw[5:37], edPub)
	// Fill dummy X25519 and KEM bytes
	_, err = rand.Read(raw[37:])
	require.NoError(t, err)

	b64 := base64.StdEncoding.EncodeToString(raw)
	var sb string
	sb += "-----BEGIN PQPG PUBLIC KEY-----\n\n"
	for i := 0; i < len(b64); i += 64 {
		end := i + 64
		if end > len(b64) {
			end = len(b64)
		}
		sb += b64[i:end] + "\n"
	}
	sb += "-----END PQPG PUBLIC KEY-----\n"
	return sb, edPriv
}

func TestPQKeysService(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := NewMemoryStore()
	serverConn, clientConn := newPipePair()
	defer serverConn.Close()
	defer clientConn.Close()

	// Start server in background
	go func() {
		_ = Serve(ctx, serverConn, store)
	}()

	sendAndRecv := func(req *Request) *Reply {
		raw, err := common.Marshal(req)
		require.NoError(t, err)
		err = clientConn.Send(ctx, raw)
		require.NoError(t, err)

		replyRaw, err := clientConn.Recv(ctx)
		require.NoError(t, err)
		var reply Reply
		err = common.Unmarshal(replyRaw, &reply)
		require.NoError(t, err)
		return &reply
	}

	// 1. Generate key and sign
	armoredKey, edPriv := generateDummyArmoredKey(t)
	userID := "alice@katzenpost.mix"
	ts := time.Now().Unix()

	signedBytes := SignedPayload(userID, armoredKey, ts)
	sig := ed25519.Sign(edPriv, signedBytes)

	// 2. Test Publish with Invalid Signature
	badReq := &Request{
		Action: ActionPublish,
		Publish: &PublishPayload{
			UserID:           userID,
			ArmoredPublicKey: armoredKey,
			Signature:        []byte("invalid-signature-bytes"),
			Timestamp:        ts,
		},
	}
	badReply := sendAndRecv(badReq)
	require.False(t, badReply.Success)
	require.Contains(t, badReply.Error, "signature")

	// 3. Test Publish with Valid Signature
	pubReq := &Request{
		Action: ActionPublish,
		Publish: &PublishPayload{
			UserID:           userID,
			ArmoredPublicKey: armoredKey,
			Signature:        sig,
			Timestamp:        ts,
		},
	}
	pubReply := sendAndRecv(pubReq)
	require.True(t, pubReply.Success, "Publish should succeed")
	require.Empty(t, pubReply.Error)
	require.NotNil(t, pubReply.KeyRecord)
	fp := pubReply.KeyRecord.Fingerprint
	require.Equal(t, ComputeFingerprint(armoredKey), fp)

	// 4. Test Duplicate Publish
	dupReply := sendAndRecv(pubReq)
	require.False(t, dupReply.Success)
	require.Contains(t, dupReply.Error, "already registered")

	// 5. Test Lookup by Fingerprint
	lookupFpReq := &Request{
		Action: ActionLookup,
		Lookup: &LookupPayload{
			Query: fp,
		},
	}
	lookupFpReply := sendAndRecv(lookupFpReq)
	require.True(t, lookupFpReply.Success)
	require.Equal(t, fp, lookupFpReply.KeyRecord.Fingerprint)
	require.Equal(t, userID, lookupFpReply.KeyRecord.UserID)
	require.Equal(t, armoredKey, lookupFpReply.KeyRecord.ArmoredPublicKey)

	// 6. Test Lookup by UserID
	lookupUidReq := &Request{
		Action: ActionLookup,
		Lookup: &LookupPayload{
			Query: "Alice@Katzenpost.Mix", // test case insensitivity
		},
	}
	lookupUidReply := sendAndRecv(lookupUidReq)
	require.True(t, lookupUidReply.Success)
	require.Equal(t, fp, lookupUidReply.KeyRecord.Fingerprint)

	// 7. Test Lookup Not Found
	notFoundReq := &Request{
		Action: ActionLookup,
		Lookup: &LookupPayload{
			Query: "non-existent-user",
		},
	}
	notFoundReply := sendAndRecv(notFoundReq)
	require.False(t, notFoundReply.Success)
	require.Contains(t, notFoundReply.Error, "not found")

	// 8. Test Revoke with Bad Signature
	revokeBadReq := &Request{
		Action: ActionRevoke,
		Revoke: &RevokePayload{
			Fingerprint: fp,
			Reason:      "Compromised laptop",
			Signature:   []byte("bad-sig"),
			Timestamp:   time.Now().Unix(),
		},
	}
	revokeBadReply := sendAndRecv(revokeBadReq)
	require.False(t, revokeBadReply.Success)

	// 9. Test Revoke with Valid Signature
	revokeTs := time.Now().Unix()
	revReason := "Key rotation"
	revSig := ed25519.Sign(edPriv, RevocationSignedPayload(fp, revReason, revokeTs))

	revokeReq := &Request{
		Action: ActionRevoke,
		Revoke: &RevokePayload{
			Fingerprint: fp,
			Reason:      revReason,
			Signature:   revSig,
			Timestamp:   revokeTs,
		},
	}
	revokeReply := sendAndRecv(revokeReq)
	require.True(t, revokeReply.Success)
	require.True(t, revokeReply.KeyRecord.Revoked)
	require.Equal(t, revReason, revokeReply.KeyRecord.RevocationReason)

	// 10. Test Lookup after Revocation
	afterRevLookup := sendAndRecv(lookupFpReq)
	require.True(t, afterRevLookup.Success)
	require.True(t, afterRevLookup.KeyRecord.Revoked)

	// 11. Test List
	listReq := &Request{
		Action: ActionList,
		List: &ListPayload{
			Limit:  10,
			Offset: 0,
		},
	}
	listReply := sendAndRecv(listReq)
	require.True(t, listReply.Success)
	require.Len(t, listReply.Keys, 1)
	require.Equal(t, fp, listReply.Keys[0].Fingerprint)
	require.True(t, listReply.Keys[0].Revoked)
}
