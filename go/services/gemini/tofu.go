package gemini

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// TOFUStore remembers the first TLS certificate seen for each Gemini host and
// port. The first connection is unauthenticated; later connections must use
// the same certificate. Keep the file in a private directory.
type TOFUStore struct {
	mu   sync.Mutex
	path string
	pins map[string]string
}

// OpenTOFUStore loads a persistent certificate pin store. A missing file is
// created when the first certificate is accepted.
func OpenTOFUStore(path string) (*TOFUStore, error) {
	if path == "" {
		return nil, errors.New("gemini: empty TOFU store path")
	}
	s := &TOFUStore{path: path, pins: make(map[string]string)}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("gemini: TOFU store must be a private regular file: %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &s.pins); err != nil {
		return nil, fmt.Errorf("gemini: invalid TOFU store: %w", err)
	}
	if s.pins == nil {
		return nil, errors.New("gemini: invalid TOFU store: null pins")
	}
	for host, fingerprint := range s.pins {
		decoded, err := hex.DecodeString(fingerprint)
		if host == "" || err != nil || len(decoded) != sha256.Size {
			return nil, errors.New("gemini: invalid TOFU store entry")
		}
	}
	return s, nil
}

// Verify accepts the first certificate for hostPort and rejects any later
// certificate with a different SHA-256 fingerprint. A new pin is persisted
// before the connection is accepted.
func (s *TOFUStore) Verify(hostPort string, certDER []byte) error {
	if s == nil || hostPort == "" || len(certDER) == 0 {
		return errors.New("gemini: missing TOFU store, host or certificate")
	}
	sum := sha256.Sum256(certDER)
	fingerprint := hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.pins[hostPort]; ok {
		if subtle.ConstantTimeCompare([]byte(old), []byte(fingerprint)) != 1 {
			return fmt.Errorf("gemini: TLS certificate changed for %s", hostPort)
		}
		return nil
	}
	next := make(map[string]string, len(s.pins)+1)
	for host, pin := range s.pins {
		next[host] = pin
	}
	next[hostPort] = fingerprint
	if err := writePins(s.path, next); err != nil {
		return fmt.Errorf("gemini: failed to persist TOFU pin: %w", err)
	}
	s.pins = next
	return nil
}

func writePins(path string, pins map[string]string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".gemini-pins-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if err := json.NewEncoder(f).Encode(pins); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
