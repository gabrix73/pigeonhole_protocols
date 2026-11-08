package pqkeys

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"sync"
	"testing"

	"github.com/katzenpost/pigeonhole_protocols/go/services/pqkeys"
	"github.com/stretchr/testify/require"
)

type pipeConn struct {
	in        chan []byte
	out       chan []byte
	done      chan struct{}
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

func generateDummyArmoredKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	raw := make([]byte, 1253)
	copy(raw[:5], []byte("PQPK\x01"))
	copy(raw[5:37], edPub)
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

func TestPQKeysClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store := pqkeys.NewMemoryStore()
	serverConn, clientConn := newPipePair()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		_ = pqkeys.Serve(ctx, serverConn, store)
	}()

	client := NewClient(clientConn)

	armoredKey, edPriv := generateDummyArmoredKey(t)
	userID := "charlie@katzenpost.mix"

	// 1. Client Publish
	pubRec, err := client.Publish(ctx, userID, armoredKey, edPriv)
	require.NoError(t, err)
	require.NotEmpty(t, pubRec.Fingerprint)
	require.Equal(t, userID, pubRec.UserID)

	// 2. Client Lookup by Fingerprint
	lookupRec, err := client.Lookup(ctx, pubRec.Fingerprint)
	require.NoError(t, err)
	require.Equal(t, pubRec.Fingerprint, lookupRec.Fingerprint)
	require.Equal(t, armoredKey, lookupRec.ArmoredPublicKey)
	require.False(t, lookupRec.Revoked)

	// 3. Client Lookup by UserID
	lookupUidRec, err := client.Lookup(ctx, "charlie@katzenpost.mix")
	require.NoError(t, err)
	require.Equal(t, pubRec.Fingerprint, lookupUidRec.Fingerprint)

	// 4. Client List
	list, err := client.List(ctx, 10, 0)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, pubRec.Fingerprint, list[0].Fingerprint)

	// 5. Client Revoke
	revRec, err := client.Revoke(ctx, pubRec.Fingerprint, "Key compromise", edPriv)
	require.NoError(t, err)
	require.True(t, revRec.Revoked)
	require.Equal(t, "Key compromise", revRec.RevocationReason)

	// 6. Verify Lookup reflects revocation
	lookupRevRec, err := client.Lookup(ctx, pubRec.Fingerprint)
	require.NoError(t, err)
	require.True(t, lookupRevRec.Revoked)
}
