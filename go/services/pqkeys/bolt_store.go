package pqkeys

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketKeys  = []byte("keys")
	bucketUsers = []byte("users")
	bucketIndex = []byte("index")
)

// BoltStore is a persistent BoltDB-backed implementation of Store.
type BoltStore struct {
	db *bolt.DB
}

// NewBoltStore opens or creates a BoltDB store at the specified path.
func NewBoltStore(path string) (*BoltStore, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("pqkeys: failed to open bolt db: %w", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketKeys); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(bucketUsers); err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(bucketIndex); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("pqkeys: failed to initialize buckets: %w", err)
	}

	return &BoltStore{db: db}, nil
}

// Close closes the underlying BoltDB database.
func (b *BoltStore) Close() error {
	return b.db.Close()
}

func (b *BoltStore) Put(record *KeyRecord) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bKeys := tx.Bucket(bucketKeys)
		if existing := bKeys.Get([]byte(record.Fingerprint)); existing != nil {
			return ErrAlreadyExists
		}

		raw, err := common.Marshal(record)
		if err != nil {
			return err
		}

		if err := bKeys.Put([]byte(record.Fingerprint), raw); err != nil {
			return err
		}

		if record.UserID != "" {
			bUsers := tx.Bucket(bucketUsers)
			normUID := strings.ToLower(record.UserID)
			if err := bUsers.Put([]byte(normUID), []byte(record.Fingerprint)); err != nil {
				return err
			}
		}

		bIndex := tx.Bucket(bucketIndex)
		seq, err := bIndex.NextSequence()
		if err != nil {
			return err
		}
		seqKey := make([]byte, 8)
		binary.BigEndian.PutUint64(seqKey, seq)
		return bIndex.Put(seqKey, []byte(record.Fingerprint))
	})
}

func (b *BoltStore) GetByFingerprint(fp string) (*KeyRecord, error) {
	var record KeyRecord
	err := b.db.View(func(tx *bolt.Tx) error {
		bKeys := tx.Bucket(bucketKeys)
		raw := bKeys.Get([]byte(fp))
		if raw == nil {
			return ErrNotFound
		}
		return common.Unmarshal(raw, &record)
	})
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (b *BoltStore) GetByUserID(uid string) (*KeyRecord, error) {
	var fp []byte
	err := b.db.View(func(tx *bolt.Tx) error {
		bUsers := tx.Bucket(bucketUsers)
		normUID := strings.ToLower(uid)
		val := bUsers.Get([]byte(normUID))
		if val == nil {
			return ErrNotFound
		}
		fp = make([]byte, len(val))
		copy(fp, val)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return b.GetByFingerprint(string(fp))
}

func (b *BoltStore) Revoke(fp string, reason string, sig []byte, ts int64) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bKeys := tx.Bucket(bucketKeys)
		raw := bKeys.Get([]byte(fp))
		if raw == nil {
			return ErrNotFound
		}

		var record KeyRecord
		if err := common.Unmarshal(raw, &record); err != nil {
			return err
		}

		record.Revoked = true
		record.RevocationReason = reason

		updatedRaw, err := common.Marshal(&record)
		if err != nil {
			return err
		}

		return bKeys.Put([]byte(fp), updatedRaw)
	})
}

func (b *BoltStore) List(limit, offset int) ([]*KeyRecordSummary, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var results []*KeyRecordSummary
	err := b.db.View(func(tx *bolt.Tx) error {
		bIndex := tx.Bucket(bucketIndex)
		bKeys := tx.Bucket(bucketKeys)

		cursor := bIndex.Cursor()
		count := 0
		skipped := 0

		for k, v := cursor.First(); k != nil && count < limit; k, v = cursor.Next() {
			if skipped < offset {
				skipped++
				continue
			}

			raw := bKeys.Get(v)
			if raw == nil {
				continue
			}

			var rec KeyRecord
			if err := common.Unmarshal(raw, &rec); err != nil {
				continue
			}

			results = append(results, &KeyRecordSummary{
				Fingerprint: rec.Fingerprint,
				UserID:      rec.UserID,
				Timestamp:   rec.Timestamp,
				Revoked:     rec.Revoked,
			})
			count++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}
