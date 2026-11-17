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
	"strings"
	"sync"
)

// TOFUStore remembers the first TLS SubjectPublicKeyInfo (SPKI) seen for each
// Gemini host and port (keyed by host:port as typed, so name and IP get
// separate pins). TOFU trust belongs to the service: whoever answers on the
// service's first fetch is pinned for all clients. Certificate renewals that
// keep the same public key remain valid. Keep the file in a private directory.
type TOFUStore struct {
	mu   sync.Mutex
	path string
	pins map[string]string
}

func loadPins(path string) (map[string]string, error) {
	pins := make(map[string]string)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return pins, nil
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
	if err := json.Unmarshal(data, &pins); err != nil {
		return nil, fmt.Errorf("gemini: invalid TOFU store: %w", err)
	}
	if pins == nil {
		return nil, errors.New("gemini: invalid TOFU store: null pins")
	}
	for host, fingerprint := range pins {
		decoded, err := hex.DecodeString(fingerprint)
		if host == "" || err != nil || len(decoded) != sha256.Size {
			return nil, errors.New("gemini: invalid TOFU store entry")
		}
	}
	return pins, nil
}

// OpenTOFUStore loads a persistent certificate pin store. A missing file is
// created when the first certificate is accepted.
func OpenTOFUStore(path string) (*TOFUStore, error) {
	if path == "" {
		return nil, errors.New("gemini: empty TOFU store path")
	}
	pins, err := loadPins(path)
	if err != nil {
		return nil, err
	}
	return &TOFUStore{path: path, pins: pins}, nil
}

// Verify accepts the first certificate for hostPort and rejects any later
// certificate with a different SHA-256 fingerprint. A new pin is persisted
// before the connection is accepted, reloading from disk so external edits
// while the service is running are preserved rather than overwritten.
func (s *TOFUStore) Verify(hostPort string, spkiDER []byte) error {
	hostPort = strings.ToLower(strings.TrimSpace(hostPort))
	if s == nil || hostPort == "" || len(spkiDER) == 0 {
		return errors.New("gemini: missing TOFU store, host or public key")
	}
	sum := sha256.Sum256(spkiDER)
	fingerprint := hex.EncodeToString(sum[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	pins, err := loadPins(s.path)
	if err != nil {
		return err
	}
	s.pins = pins
	if old, ok := s.pins[hostPort]; ok {
		if subtle.ConstantTimeCompare([]byte(old), []byte(fingerprint)) != 1 {
			return fmt.Errorf("gemini: TLS public key changed for %s", hostPort)
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
