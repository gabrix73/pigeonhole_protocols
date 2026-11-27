package pqkeys

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBoltStore(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "pqkeys.db")

	store, err := NewBoltStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	rec := &KeyRecord{
		Fingerprint:      "deadbeef1234",
		UserID:           "bob@katzenpost.mix",
		ArmoredPublicKey: "dummy-key-content",
		Signature:        []byte("sig"),
		Timestamp:        time.Now().Unix(),
		Revoked:          false,
	}

	// 1. Put
	err = store.Put(rec)
	require.NoError(t, err)

	// 2. Duplicate Put
	err = store.Put(rec)
	require.ErrorIs(t, err, ErrAlreadyExists)

	// 3. GetByFingerprint
	got, err := store.GetByFingerprint("deadbeef1234")
	require.NoError(t, err)
	require.Equal(t, rec.UserID, got.UserID)
	require.Equal(t, rec.ArmoredPublicKey, got.ArmoredPublicKey)
	require.False(t, got.Revoked)

	// 4. GetByUserID (case insensitive)
	gotUID, err := store.GetByUserID("Bob@Katzenpost.Mix")
	require.NoError(t, err)
	require.Equal(t, "deadbeef1234", gotUID.Fingerprint)

	// 5. Revoke
	err = store.Revoke("deadbeef1234", "Stolen device", nil, time.Now().Unix())
	require.NoError(t, err)

	gotRev, err := store.GetByFingerprint("deadbeef1234")
	require.NoError(t, err)
	require.True(t, gotRev.Revoked)
	require.Equal(t, "Stolen device", gotRev.RevocationReason)

	// 6. List
	list, err := store.List(10, 0)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, "deadbeef1234", list[0].Fingerprint)
	require.True(t, list[0].Revoked)
}
