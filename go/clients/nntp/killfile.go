// SPDX-License-Identifier: AGPL-3.0-only

package nntp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	svc "github.com/katzenpost/pigeonhole_protocols/go/services/nntp"
)

// Killfile stores local anti-troll, anti-flood, and ciphertext-hiding rules.
// It is persisted as JSON (0600) and editable both on disk and in the Web UI.
type Killfile struct {
	// HideUndecryptable automatically hides encrypted articles (HPQC for other
	// recipients, PGP, pqpg, age) that cannot be decrypted with local keys.
	HideUndecryptable bool `json:"hide_undecryptable"`
	// MaxCrossposts hides articles crossposted to more than N groups (0 disables).
	MaxCrossposts int `json:"max_crossposts"`
	// MaxLines hides oversized flood/dump articles above N lines (0 disables).
	MaxLines uint64 `json:"max_lines"`
	// MaxPostsPerAuthor hides bursts where one From header posts > N times in one overview window (0 disables).
	MaxPostsPerAuthor int `json:"max_posts_per_author"`
	// BlockedFrom hides entries matching any case-insensitive substring or /regex/.
	BlockedFrom []string `json:"blocked_from"`
	// BlockedSubjects hides entries matching any case-insensitive substring or /regex/.
	BlockedSubjects []string `json:"blocked_subjects"`
	// BlockedMessageIDs hides specific Message-IDs.
	BlockedMessageIDs []string `json:"blocked_message_ids"`
	// BlockedThreads hides any article whose Message-ID or References contains a listed ID.
	BlockedThreads []string `json:"blocked_threads"`
}

// DefaultKillfile returns strong anti-troll and anti-flood defaults.
func DefaultKillfile() *Killfile {
	return &Killfile{
		HideUndecryptable: true,
		MaxCrossposts:     4,
		MaxLines:          2000,
		MaxPostsPerAuthor: 15,
		BlockedFrom:       []string{},
		BlockedSubjects: []string{
			"/^(MAKE MONEY FAST|FREE CRYPTO|BUY NOW)/",
		},
		BlockedMessageIDs: []string{},
		BlockedThreads:    []string{},
	}
}

// LoadKillfile reads a killfile from path, returning DefaultKillfile when the
// file does not yet exist.
func LoadKillfile(path string) (*Killfile, error) {
	if strings.TrimSpace(path) == "" {
		return DefaultKillfile(), nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return DefaultKillfile(), nil
	}
	if err != nil {
		return nil, err
	}
	kf := DefaultKillfile()
	if err := json.Unmarshal(raw, kf); err != nil {
		return nil, err
	}
	return kf, nil
}

// SaveKillfile atomically saves kf to path with 0600 permissions.
func SaveKillfile(path string, kf *Killfile) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("killfile: empty path")
	}
	if kf == nil {
		kf = DefaultKillfile()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(kf, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeAtomicFile(path, raw, 0o600)
}

// AuthorCounts tallies normalized From frequencies across a slice of overview
// entries so MaxPostsPerAuthor can catch burst floods.
func AuthorCounts(entries []svc.OverviewEntry) map[string]int {
	counts := make(map[string]int, len(entries))
	for _, e := range entries {
		key := normalizeAuthorKey(e.From)
		if key != "" {
			counts[key]++
		}
	}
	return counts
}

// EvaluateOverview checks an overview entry against killfile rules.
func (k *Killfile) EvaluateOverview(e svc.OverviewEntry, authorCounts map[string]int) (hidden bool, reason string) {
	if k == nil {
		return false, ""
	}
	if k.MaxLines > 0 && e.Lines > k.MaxLines {
		return true, "flood: exceeds max lines"
	}
	if k.MaxCrossposts > 0 && e.Xref != "" {
		// Xref format: "hostname group1:num1 group2:num2 ..."
		fields := strings.Fields(e.Xref)
		if len(fields) > 1 && len(fields)-1 > k.MaxCrossposts {
			return true, "spam: excessive crossposting"
		}
	}
	if k.MaxPostsPerAuthor > 0 && authorCounts != nil {
		if c := authorCounts[normalizeAuthorKey(e.From)]; c > k.MaxPostsPerAuthor {
			return true, "flood: author post burst"
		}
	}
	for _, id := range k.BlockedMessageIDs {
		if id != "" && strings.EqualFold(strings.TrimSpace(id), strings.TrimSpace(e.MessageID)) {
			return true, "killfile: blocked message-id"
		}
	}
	for _, tid := range k.BlockedThreads {
		tid = strings.TrimSpace(tid)
		if tid == "" {
			continue
		}
		if strings.EqualFold(tid, strings.TrimSpace(e.MessageID)) || strings.Contains(e.References, tid) {
			return true, "killfile: muted thread"
		}
	}
	if matchRuleList(e.From, k.BlockedFrom) {
		return true, "killfile: blocked author"
	}
	if matchRuleList(e.Subject, k.BlockedSubjects) {
		return true, "killfile: blocked subject"
	}
	return false, ""
}

// EvaluateArticle checks full article headers + decryption outcome against the
// killfile (including automatic hiding of undecryptable ciphertext).
func (k *Killfile) EvaluateArticle(headers map[string]string, outcome DecryptOutcome) (hidden bool, reason string) {
	if k == nil {
		return false, ""
	}
	if k.HideUndecryptable && outcome.Undecryptable {
		return true, "encrypted: undecryptable (" + string(outcome.CipherKind) + ")"
	}
	if k.MaxCrossposts > 0 {
		if ng := headers["newsgroups"]; ng != "" {
			if len(strings.Split(ng, ",")) > k.MaxCrossposts {
				return true, "spam: excessive crossposting"
			}
		}
	}
	entry := svc.OverviewEntry{
		From:       headers["from"],
		Subject:    headers["subject"],
		MessageID:  headers["message-id"],
		References: headers["references"],
	}
	return k.EvaluateOverview(entry, nil)
}

func normalizeAuthorKey(from string) string {
	return strings.ToLower(strings.TrimSpace(from))
}

func matchRuleList(value string, rules []string) bool {
	valLower := strings.ToLower(value)
	for _, r := range rules {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if len(r) >= 2 && strings.HasPrefix(r, "/") && strings.HasSuffix(r, "/") {
			re, err := regexp.Compile("(?i)" + r[1:len(r)-1])
			if err == nil && re.MatchString(value) {
				return true
			}
			continue
		}
		if strings.Contains(valLower, strings.ToLower(r)) {
			return true
		}
	}
	return false
}
