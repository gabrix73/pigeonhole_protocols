// Package store keeps a katzenqt1 client's state on disk: one bbolt file, with a record per
// conversation and its lines kept one by one, and the files lines and uploads carry beside it.
// A step's changes are saved in one transaction, synced to disk before Commit returns.
package store

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/pigeonhole_protocols/go/protocols/katzenqt1/engine"
)

const version = 1

var (
	metaBucket  = []byte("meta")
	chatsBucket = []byte("chats")
	recordKey   = []byte("record")
	linesBucket = []byte("lines")
)

type Store struct {
	dir    string
	db     *bolt.DB
	noSync bool
	// saved is each conversation's record as last saved, so that one unchanged is not written.
	saved map[engine.ChatID]string
}

type Options struct {
	// NoSync leaves syncing to the system: for tests only, since a crash may then lose what was
	// committed.
	NoSync bool
}

// Open opens the state in dir, making it if need be.
func Open(dir string, opts Options) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(dir, "state.db"), 0o600, &bolt.Options{NoSync: opts.NoSync, NoFreelistSync: opts.NoSync})
	if err != nil {
		return nil, err
	}
	s := &Store{dir: dir, db: db, noSync: opts.NoSync, saved: map[engine.ChatID]string{}}
	err = db.Update(func(tx *bolt.Tx) error {
		m, err := tx.CreateBucketIfNotExists(metaBucket)
		if err != nil {
			return err
		}
		if _, err := tx.CreateBucketIfNotExists(chatsBucket); err != nil {
			return err
		}
		switch v := m.Get([]byte("version")); {
		case v == nil:
			return m.Put([]byte("version"), []byte{version})
		case len(v) != 1 || v[0] != version:
			return fmt.Errorf("store: state of version %v", v)
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func lineKey(id int) []byte { return binary.BigEndian.AppendUint64(nil, uint64(id)) }

// Load reads the whole state; me is our name when none is saved.
func (s *Store) Load(me string) (*engine.State, error) {
	st := &engine.State{Me: me}
	err := s.db.View(func(tx *bolt.Tx) error {
		if n := tx.Bucket(metaBucket).Get([]byte("me")); n != nil {
			st.Me = string(n)
		}
		var order []string
		if o := tx.Bucket(metaBucket).Get([]byte("order")); o != nil {
			if err := json.Unmarshal(o, &order); err != nil {
				return err
			}
		}
		chats := tx.Bucket(chatsBucket)
		for _, id := range order {
			b := chats.Bucket([]byte(id))
			if b == nil {
				return fmt.Errorf("store: no conversation %s", id)
			}
			rec := b.Get(recordKey)
			c, err := decodeChat(rec)
			if err != nil {
				return err
			}
			s.saved[c.ID] = string(rec)
			err = b.Bucket(linesBucket).ForEach(func(_, v []byte) error {
				l, err := decodeLine(v)
				c.Log = append(c.Log, l)
				return err
			})
			if err != nil {
				return err
			}
			st.Chats = append(st.Chats, c)
		}
		return nil
	})
	return st, err
}

// Path is where a file under the state directory is, refusing names that leave it.
func (s *Store) Path(name string) (string, error) {
	p := filepath.Join(s.dir, filepath.FromSlash(name))
	if rel, err := filepath.Rel(s.dir, p); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("store: %q is outside the state directory", name)
	}
	return p, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// keep writes a file and syncs it and its directory, so that it is on disk before any state
// that names it.
func (s *Store) keep(f engine.FileWrite) error {
	p, err := s.Path(f.File)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(f.Bytes)
	if err == nil && !s.noSync {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), p)
	}
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if s.noSync {
		return nil
	}
	return syncDir(dir)
}

// Commit saves what a step changed: first the files it keeps, then its changes to the state, in
// one transaction. Nothing the step asks for may be done before Commit returns without error.
func (s *Store) Commit(st *engine.State, r *engine.Result) error {
	for _, f := range r.Files {
		if err := s.keep(f); err != nil {
			return err
		}
	}
	ch := &r.Changes
	records := map[engine.ChatID][]byte{}
	for id := range ch.Chats {
		c := st.Chat(id)
		if c == nil {
			continue
		}
		rec, err := encodeChat(c)
		if err != nil {
			return err
		}
		if s.saved[id] != string(rec) {
			records[id] = rec
		}
	}
	if len(records) == 0 && len(ch.Lines) == 0 && len(ch.Dropped) == 0 && len(ch.Removed) == 0 {
		return nil
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		chats := tx.Bucket(chatsBucket)
		for id := range ch.Removed {
			if err := chats.DeleteBucket([]byte(id)); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
				return err
			}
		}
		bucket := func(id engine.ChatID) (*bolt.Bucket, error) {
			b, err := chats.CreateBucketIfNotExists([]byte(id))
			if err != nil {
				return nil, err
			}
			_, err = b.CreateBucketIfNotExists(linesBucket)
			return b, err
		}
		for id, rec := range records {
			b, err := bucket(id)
			if err != nil {
				return err
			}
			if err := b.Put(recordKey, rec); err != nil {
				return err
			}
		}
		for id, lines := range ch.Lines {
			c := st.Chat(id)
			if c == nil {
				continue
			}
			b, err := bucket(id)
			if err != nil {
				return err
			}
			lb := b.Bucket(linesBucket)
			for _, l := range c.Log {
				if !lines[l.ID] {
					continue
				}
				v, err := encodeLine(l)
				if err != nil {
					return err
				}
				if err := lb.Put(lineKey(l.ID), v); err != nil {
					return err
				}
			}
		}
		for id, lines := range ch.Dropped {
			b := chats.Bucket([]byte(id))
			if b == nil {
				continue
			}
			lb := b.Bucket(linesBucket)
			for n := range lines {
				if err := lb.Delete(lineKey(n)); err != nil {
					return err
				}
			}
		}
		order := make([]string, len(st.Chats))
		for i, c := range st.Chats {
			order[i] = string(c.ID)
		}
		o, err := json.Marshal(order)
		if err != nil {
			return err
		}
		m := tx.Bucket(metaBucket)
		if err := m.Put([]byte("order"), o); err != nil {
			return err
		}
		return m.Put([]byte("me"), []byte(st.Me))
	})
	if err != nil {
		return err
	}
	for id, rec := range records {
		s.saved[id] = string(rec)
	}
	for id := range ch.Removed {
		delete(s.saved, id)
	}
	return nil
}

// Files are the files under the state directory, for an Executor.
type Files struct{ S *Store }

func (f Files) Read(name string) ([]byte, error) {
	p, err := f.S.Path(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

func (f Files) Remove(name string) error {
	p, err := f.S.Path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Unsaved is the conversations whose record or lines differ from what was last saved: a step
// that changed them without saying so. For tests.
func (s *Store) Unsaved(st *engine.State) ([]engine.ChatID, error) {
	var out []engine.ChatID
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, c := range st.Chats {
			rec, err := encodeChat(c)
			if err != nil {
				return err
			}
			b := tx.Bucket(chatsBucket).Bucket([]byte(c.ID))
			if b == nil || string(b.Get(recordKey)) != string(rec) {
				out = append(out, c.ID)
				continue
			}
			lb := b.Bucket(linesBucket)
			if lb.Stats().KeyN != len(c.Log) {
				out = append(out, c.ID)
				continue
			}
			for _, l := range c.Log {
				v, err := encodeLine(l)
				if err != nil {
					return err
				}
				if string(lb.Get(lineKey(l.ID))) != string(v) {
					out = append(out, c.ID)
					break
				}
			}
		}
		return nil
	})
	return out, err
}
