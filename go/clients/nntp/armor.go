// SPDX-License-Identifier: AGPL-3.0-only

package nntp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/protocols/sealedbox"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

const (
	hpqcMsgBegin    = "-----BEGIN KATZENPOST HPQC MESSAGE-----"
	hpqcMsgEnd      = "-----END KATZENPOST HPQC MESSAGE-----"
	hpqcPubBegin    = "-----BEGIN KATZENPOST HPQC PUBLIC KEY-----"
	hpqcPubEnd      = "-----END KATZENPOST HPQC PUBLIC KEY-----"
	hpqcPrivBegin   = "-----BEGIN KATZENPOST HPQC PRIVATE KEY-----"
	hpqcPrivEnd     = "-----END KATZENPOST HPQC PRIVATE KEY-----"
	armorLineWidth  = 64
	armorVersionTag = "1"
)

// CipherKind identifies encrypted ASCII-armored content inside a Usenet article.
type CipherKind string

const (
	CipherNone CipherKind = ""
	CipherHPQC CipherKind = "hpqc"
	CipherPGP  CipherKind = "pgp"
	CipherPQPG CipherKind = "pqpg"
	CipherAge  CipherKind = "age"
)

var (
	// ErrNoHPQCBlock reports that no HPQC armored block was found in the text.
	ErrNoHPQCBlock = errors.New("nntp armor: no HPQC message block found")
	// ErrInvalidArmor reports malformed armor framing or headers.
	ErrInvalidArmor = errors.New("nntp armor: invalid ASCII armor")
	// ErrUnknownScheme reports an unrecognized HPQC NIKE scheme name.
	ErrUnknownScheme = errors.New("nntp armor: unknown HPQC NIKE scheme")
	// ErrDecryptFailed reports that sealedbox opening failed (wrong key or tampered ciphertext).
	ErrDecryptFailed = errors.New("nntp armor: decryption failed")
)

// Keypair holds a local HPQC NIKE keypair used for optional anonymous
// public-key encryption (hpqc/protocols/sealedbox) over Usenet.
type Keypair struct {
	Scheme  nike.Scheme
	Public  nike.PublicKey
	Private nike.PrivateKey
}

// GenerateKeypair creates a fresh HPQC NIKE keypair. When schemeName is empty,
// common.DefaultNIKE (X25519-CTIDH1024) is used.
func GenerateKeypair(schemeName string) (*Keypair, error) {
	sch, err := resolveNIKEScheme(schemeName)
	if err != nil {
		return nil, err
	}
	pub, priv, err := sch.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("nntp armor: generate keypair: %w", err)
	}
	return &Keypair{Scheme: sch, Public: pub, Private: priv}, nil
}

// Fingerprint returns a short human-readable SHA-256 fingerprint of the public key.
func (k *Keypair) Fingerprint() string {
	if k == nil || k.Public == nil {
		return ""
	}
	sum := sha256.Sum256(k.Public.Bytes())
	return strings.ToUpper(hex.EncodeToString(sum[:8]))
}

// ArmorPublicKey encodes the public key in Usenet-safe ASCII armor.
func (k *Keypair) ArmorPublicKey() string {
	return formatArmor(hpqcPubBegin, hpqcPubEnd, k.Scheme.Name(), k.Public.Bytes())
}

// SaveKeypair writes public.asc (0644) and private.asc (0600) into dir atomically.
func SaveKeypair(dir string, kp *Keypair) error {
	if kp == nil || kp.Scheme == nil || kp.Public == nil || kp.Private == nil {
		return errors.New("nntp armor: incomplete keypair")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	pubText := kp.ArmorPublicKey()
	privText := formatArmor(hpqcPrivBegin, hpqcPrivEnd, kp.Scheme.Name(), kp.Private.Bytes())
	if err := writeAtomicFile(filepath.Join(dir, "public.asc"), []byte(pubText), 0o644); err != nil {
		return err
	}
	return writeAtomicFile(filepath.Join(dir, "private.asc"), []byte(privText), 0o600)
}

// LoadKeypair loads public.asc and private.asc from dir.
func LoadKeypair(dir string) (*Keypair, error) {
	pubRaw, err := os.ReadFile(filepath.Join(dir, "public.asc"))
	if err != nil {
		return nil, err
	}
	privRaw, err := os.ReadFile(filepath.Join(dir, "private.asc"))
	if err != nil {
		return nil, err
	}
	sch, pub, err := ParseArmoredPublicKey(string(pubRaw))
	if err != nil {
		return nil, err
	}
	privScheme, privBytes, err := parseArmorBlock(string(privRaw), hpqcPrivBegin, hpqcPrivEnd)
	if err != nil {
		return nil, err
	}
	if privScheme != sch.Name() {
		return nil, fmt.Errorf("%w: public/private scheme mismatch", ErrInvalidArmor)
	}
	priv, err := sch.UnmarshalBinaryPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArmor, err)
	}
	return &Keypair{Scheme: sch, Public: pub, Private: priv}, nil
}

// ParseArmoredPublicKey parses an ASCII-armored HPQC public key.
func ParseArmoredPublicKey(armored string) (nike.Scheme, nike.PublicKey, error) {
	schemeName, raw, err := parseArmorBlock(armored, hpqcPubBegin, hpqcPubEnd)
	if err != nil {
		return nil, nil, err
	}
	sch, err := resolveNIKEScheme(schemeName)
	if err != nil {
		return nil, nil, err
	}
	pub, err := sch.UnmarshalBinaryPublicKey(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidArmor, err)
	}
	return sch, pub, nil
}

// SealArmored anonymously encrypts plaintext to recipientPub using
// hpqc/protocols/sealedbox and returns a Cleanfeed-friendly ASCII-armored block.
func SealArmored(sch nike.Scheme, recipientPub nike.PublicKey, plaintext []byte) (string, error) {
	if sch == nil || recipientPub == nil {
		return "", errors.New("nntp armor: scheme and recipient public key are required")
	}
	sb := sealedbox.NewScheme(sch)
	ct, err := sb.Seal(recipientPub, plaintext)
	if err != nil {
		return "", fmt.Errorf("nntp armor: seal failed: %w", err)
	}
	return formatArmor(hpqcMsgBegin, hpqcMsgEnd, sch.Name(), ct), nil
}

// OpenArmored locates an HPQC ASCII-armored block inside text and decrypts it
// with kp.
func OpenArmored(kp *Keypair, text string) ([]byte, error) {
	if kp == nil || kp.Scheme == nil || kp.Private == nil || kp.Public == nil {
		return nil, ErrDecryptFailed
	}
	schemeName, ct, err := parseArmorBlock(text, hpqcMsgBegin, hpqcMsgEnd)
	if err != nil {
		if errors.Is(err, ErrNoHPQCBlock) {
			return nil, ErrNoHPQCBlock
		}
		return nil, err
	}
	if schemeName != kp.Scheme.Name() {
		return nil, ErrDecryptFailed
	}
	sb := sealedbox.NewScheme(kp.Scheme)
	pt, err := sb.Open(kp.Private, kp.Public, ct)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return pt, nil
}

// DetectCiphertextKind detects integrated HPQC armor as well as free-form
// encrypted blocks (PGP, pqpg, age) inside an article body.
func DetectCiphertextKind(body string) CipherKind {
	switch {
	case strings.Contains(body, hpqcMsgBegin) && strings.Contains(body, hpqcMsgEnd):
		return CipherHPQC
	case strings.Contains(body, "-----BEGIN PGP MESSAGE-----") && strings.Contains(body, "-----END PGP MESSAGE-----"):
		return CipherPGP
	case strings.Contains(body, "-----BEGIN PQPG MESSAGE-----") && strings.Contains(body, "-----END PQPG MESSAGE-----"):
		return CipherPQPG
	case strings.Contains(body, "-----BEGIN AGE ENCRYPTED FILE-----") && strings.Contains(body, "-----END AGE ENCRYPTED FILE-----"):
		return CipherAge
	default:
		return CipherNone
	}
}

// DecryptOutcome summarizes automatic inspection and optional HPQC decryption
// of an article body.
type DecryptOutcome struct {
	CipherKind    CipherKind
	Decrypted     bool
	Undecryptable bool
	Plaintext     string
}

// InspectBody classifies an article body and attempts local HPQC decryption
// when kp is configured. Free-form encrypted payloads (PGP/pqpg/age) or HPQC
// messages for other recipients are flagged Undecryptable so the killfile can
// hide them automatically while still allowing manual inspection.
func InspectBody(body string, kp *Keypair) DecryptOutcome {
	kind := DetectCiphertextKind(body)
	if kind == CipherNone {
		return DecryptOutcome{CipherKind: CipherNone}
	}
	if kind == CipherHPQC && kp != nil {
		if pt, err := OpenArmored(kp, body); err == nil {
			return DecryptOutcome{
				CipherKind: CipherHPQC,
				Decrypted:  true,
				Plaintext:  string(pt),
			}
		}
	}
	return DecryptOutcome{
		CipherKind:    kind,
		Decrypted:     false,
		Undecryptable: true,
	}
}

func resolveNIKEScheme(name string) (nike.Scheme, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return common.DefaultNIKE, nil
	}
	if strings.EqualFold(name, common.DefaultNIKE.Name()) {
		return common.DefaultNIKE, nil
	}
	sch := schemes.ByName(name)
	if sch == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownScheme, name)
	}
	return sch, nil
}

func formatArmor(begin, end, schemeName string, raw []byte) string {
	b64 := base64.StdEncoding.EncodeToString(raw)
	var b strings.Builder
	b.WriteString(begin + "\n")
	b.WriteString("Version: " + armorVersionTag + "\n")
	b.WriteString("Scheme: " + schemeName + "\n")
	b.WriteString("\n")
	for i := 0; i < len(b64); i += armorLineWidth {
		hi := i + armorLineWidth
		if hi > len(b64) {
			hi = len(b64)
		}
		b.WriteString(b64[i:hi] + "\n")
	}
	b.WriteString(end + "\n")
	return b.String()
}

func parseArmorBlock(text, begin, end string) (string, []byte, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	start := strings.Index(text, begin)
	if start < 0 {
		if begin == hpqcMsgBegin {
			return "", nil, ErrNoHPQCBlock
		}
		return "", nil, ErrInvalidArmor
	}
	rest := text[start+len(begin):]
	stop := strings.Index(rest, end)
	if stop < 0 {
		return "", nil, ErrInvalidArmor
	}
	inner := strings.TrimPrefix(rest[:stop], "\n")
	sep := strings.Index(inner, "\n\n")
	if sep < 0 {
		return "", nil, ErrInvalidArmor
	}
	hdrBlock := inner[:sep]
	b64Block := inner[sep+2:]

	var schemeName, version string
	for _, line := range strings.Split(hdrBlock, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return "", nil, ErrInvalidArmor
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "version":
			version = strings.TrimSpace(v)
		case "scheme":
			schemeName = strings.TrimSpace(v)
		}
	}
	if version != armorVersionTag || schemeName == "" {
		return "", nil, ErrInvalidArmor
	}

	cleaned := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(b64Block)
	if cleaned == "" {
		return "", nil, ErrInvalidArmor
	}
	raw, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return "", nil, fmt.Errorf("%w: base64 decode: %v", ErrInvalidArmor, err)
	}
	return schemeName, raw, nil
}

func writeAtomicFile(dst string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	cleanup = false
	return nil
}
