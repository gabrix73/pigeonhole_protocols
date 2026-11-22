// SPDX-License-Identifier: AGPL-3.0-only

// Package nntp implements a Usenet (NNTP, RFC 3977 / RFC 5536) gateway service
// over Katzenpost Pigeonhole mailboxes.
//
// Operators pin the service to a trusted upstream NNTP server (typically
// unauthenticated text-only servers such as news.tcpreset.net or Paganini);
// clients cannot choose arbitrary upstream hosts, preventing SSRF and port
// scanning. Large replies and large POST payloads are offloaded over
// go/protocols/stream.
package nntp

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// DefaultPort is the standard plaintext NNTP port.
	DefaultPort = "119"
	// DefaultTLSPort is the standard NNTPS (implicit TLS) port.
	DefaultTLSPort = "563"
	// DefaultNewsgroup is the dedicated Usenet group for Katzenpost messages.
	DefaultNewsgroup = "free.katzenpost-messages"

	// DefaultTimeout bounds each upstream NNTP exchange.
	DefaultTimeout = 20 * time.Second
	// DefaultMaxResponseBytes caps upstream NNTP response payloads (4 MiB).
	DefaultMaxResponseBytes = 4 * 1024 * 1024
	// DefaultMaxPostBytes caps outbound article size (256 KiB, text-only friendly).
	DefaultMaxPostBytes = 256 * 1024
	// DefaultMaxOverviewCount caps how many OVER entries one request may fetch.
	DefaultMaxOverviewCount = 500
	// DefaultMaxGroups caps how many groups LIST returns in one response.
	DefaultMaxGroups = 10000
	// DefaultPostRateLimit is the default max posts per gateway window when POST is enabled.
	DefaultPostRateLimit = 5
	// DefaultPostRateWindow is the sliding window for DefaultPostRateLimit.
	DefaultPostRateWindow = 15 * time.Minute
)

// Command names supported by the Pigeonhole NNTP protocol.
const (
	CmdList    = "LIST"
	CmdGroup   = "GROUP"
	CmdOver    = "OVER"
	CmdArticle = "ARTICLE"
	CmdPost    = "POST"
)

// Request is the CBOR-encoded RPC sent by a client to the NNTP service.
type Request struct {
	// Cmd is one of CmdList, CmdGroup, CmdOver, CmdArticle, or CmdPost.
	Cmd string
	// Group names the target newsgroup for GROUP, OVER, and numeric ARTICLE.
	Group string `cbor:",omitempty"`
	// Pattern is an optional wildmat filter for LIST (e.g. "free.*").
	Pattern string `cbor:",omitempty"`
	// From and To define the inclusive article number range for OVER.
	From uint64 `cbor:",omitempty"`
	To   uint64 `cbor:",omitempty"`
	// ArticleID selects an article by Message-ID ("<id@domain>") for ARTICLE.
	ArticleID string `cbor:",omitempty"`
	// ArticleNumber selects an article by group-local number for ARTICLE.
	ArticleNumber uint64 `cbor:",omitempty"`
	// Article carries the raw RFC 5536 article for POST when it fits in one box.
	Article []byte `cbor:",omitempty"`
	// ArticleStream carries a serialized bacap.ReadCap when a POST article
	// exceeds a single Pigeonhole box.
	ArticleStream []byte `cbor:",omitempty"`
}

// Response is the CBOR-encoded reply sent by the NNTP service to the client.
type Response struct {
	// Status is the NNTP 3-digit status code (e.g. 215, 211, 224, 220, 240, 411, 430, 440, 441).
	Status int
	// Message is a short status description.
	Message string `cbor:",omitempty"`
	// Payload holds the CBOR-encoded command result when it fits in one box.
	Payload []byte `cbor:",omitempty"`
	// PayloadStream carries a serialized bacap.ReadCap when Payload exceeds
	// a single Pigeonhole box and is published via go/protocols/stream.
	PayloadStream []byte `cbor:",omitempty"`
	// Error carries a sanitized gateway error string; empty on protocol-level success.
	Error string `cbor:",omitempty"`
}

// GroupInfo describes one newsgroup from LIST or GROUP.
type GroupInfo struct {
	Name   string
	High   uint64
	Low    uint64
	Count  uint64 `cbor:",omitempty"`
	Status string `cbor:",omitempty"` // "y", "n", "m", etc.
}

// ListResult is the CBOR payload for CmdList.
type ListResult struct {
	Groups    []GroupInfo
	Truncated bool `cbor:",omitempty"`
}

// GroupResult is the CBOR payload for CmdGroup.
type GroupResult struct {
	Group GroupInfo
}

// OverviewEntry represents one tab-separated RFC 3977 OVER/XOVER line.
type OverviewEntry struct {
	Number     uint64
	Subject    string
	From       string
	Date       string
	MessageID  string
	References string `cbor:",omitempty"`
	Bytes      uint64 `cbor:",omitempty"`
	Lines      uint64 `cbor:",omitempty"`
	Xref       string `cbor:",omitempty"`
}

// OverResult is the CBOR payload for CmdOver.
type OverResult struct {
	Group   string
	Entries []OverviewEntry
}

// ArticleResult is the CBOR payload for CmdArticle.
type ArticleResult struct {
	Number    uint64 `cbor:",omitempty"`
	MessageID string `cbor:",omitempty"`
	Raw       []byte
}

// PostResult is the CBOR payload for CmdPost.
type PostResult struct {
	Accepted  bool
	MessageID string `cbor:",omitempty"`
}

var (
	errInvalidRequest   = errors.New("invalid request")
	errPostDisabled     = errors.New("posting disabled")
	errPostNotAllowed   = errors.New("post rejected by gateway policy")
	errRateLimited      = errors.New("post rate limit exceeded")
	errUpstreamProtocol = errors.New("upstream protocol error")
	errUpstreamConnect  = errors.New("upstream connection failed")
)

// forbiddenPostHeaders lists headers that a privacy-preserving, Cleanfeed-NG /
// Postfilter-NG friendly gateway must reject from untrusted client submissions.
var forbiddenPostHeaders = map[string]bool{
	"approved":          true,
	"control":           true,
	"injection-info":    true,
	"nntp-posting-date": true,
	"nntp-posting-host": true,
	"path":              true,
	"received":          true,
	"supersedes":        true,
	"x-originating-ip":  true,
	"x-trace":           true,
	"xref":              true,
}

// ValidateGroupName checks that group is a safe RFC 5536 newsgroup name without
// control characters, whitespace, or wildcards.
func ValidateGroupName(group string) error {
	if len(group) == 0 || len(group) > 255 {
		return fmt.Errorf("%w: invalid newsgroup length", errInvalidRequest)
	}
	if strings.HasPrefix(group, ".") || strings.HasSuffix(group, ".") || strings.Contains(group, "..") {
		return fmt.Errorf("%w: malformed newsgroup name", errInvalidRequest)
	}
	for i := 0; i < len(group); i++ {
		c := group[i]
		ok := (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' || c == '+'
		if !ok {
			return fmt.Errorf("%w: invalid character in newsgroup name", errInvalidRequest)
		}
	}
	return nil
}

// ValidatePattern checks an optional NNTP LIST wildmat pattern.
func ValidatePattern(pattern string) error {
	if pattern == "" {
		return nil
	}
	if len(pattern) > 128 {
		return fmt.Errorf("%w: pattern too long", errInvalidRequest)
	}
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		ok := (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '-' || c == '_' || c == '+' || c == '*' || c == '?' || c == ',' || c == '!'
		if !ok {
			return fmt.Errorf("%w: invalid character in LIST pattern", errInvalidRequest)
		}
	}
	return nil
}

// ValidateMessageID checks an RFC 5536 Message-ID (<local@domain>) with no
// whitespace or control characters (preventing NNTP command injection).
func ValidateMessageID(id string) error {
	if len(id) < 5 || len(id) > 250 {
		return fmt.Errorf("%w: invalid message-id length", errInvalidRequest)
	}
	if id[0] != '<' || id[len(id)-1] != '>' {
		return fmt.Errorf("%w: message-id must be enclosed in angle brackets", errInvalidRequest)
	}
	inner := id[1 : len(id)-1]
	at := strings.IndexByte(inner, '@')
	if at <= 0 || at == len(inner)-1 || strings.IndexByte(inner[at+1:], '@') >= 0 {
		return fmt.Errorf("%w: malformed message-id", errInvalidRequest)
	}
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c <= 0x20 || c >= 0x7f || c == '<' || c == '>' {
			return fmt.Errorf("%w: invalid character in message-id", errInvalidRequest)
		}
	}
	return nil
}

// NormalizeArticleCRLF converts bare LF or CR line endings to CRLF without
// touching already-normalized CRLF sequences.
func NormalizeArticleCRLF(raw []byte) []byte {
	var out bytes.Buffer
	out.Grow(len(raw) + 64)
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '\r':
			out.WriteString("\r\n")
			if i+1 < len(raw) && raw[i+1] == '\n' {
				i++
			}
		case '\n':
			out.WriteString("\r\n")
		default:
			out.WriteByte(raw[i])
		}
	}
	return out.Bytes()
}

// SplitHeadersAndBody splits a raw RFC 5536 article into unfolded header pairs
// (preserving original casing in order plus a lowercased lookup map) and body.
func SplitHeadersAndBody(raw []byte) (headers map[string]string, body []byte, err error) {
	norm := NormalizeArticleCRLF(raw)
	sep := bytes.Index(norm, []byte("\r\n\r\n"))
	if sep < 0 {
		return nil, nil, fmt.Errorf("%w: article missing header/body separator", errInvalidRequest)
	}
	headerBlock := norm[:sep]
	body = norm[sep+4:]

	headers = make(map[string]string)
	lines := bytes.Split(headerBlock, []byte("\r\n"))
	var lastKey string
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if lastKey == "" {
				return nil, nil, fmt.Errorf("%w: malformed folded header", errInvalidRequest)
			}
			headers[lastKey] = headers[lastKey] + " " + strings.TrimSpace(string(line))
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			return nil, nil, fmt.Errorf("%w: malformed header line", errInvalidRequest)
		}
		name := strings.ToLower(strings.TrimSpace(string(line[:colon])))
		if name == "" {
			return nil, nil, fmt.Errorf("%w: empty header name", errInvalidRequest)
		}
		for i := 0; i < len(name); i++ {
			c := name[i]
			if c <= 0x20 || c >= 0x7f {
				return nil, nil, fmt.Errorf("%w: invalid header name", errInvalidRequest)
			}
		}
		val := strings.TrimSpace(string(line[colon+1:]))
		if _, exists := headers[name]; exists {
			return nil, nil, fmt.Errorf("%w: duplicate header %q", errInvalidRequest, name)
		}
		headers[name] = val
		lastKey = name
	}
	return headers, body, nil
}

// ValidatePostArticle enforces RFC 5536 basics, text-only cleanliness (for
// Cleanfeed-NG / Postfilter-NG compatibility), forbidden-header stripping, and
// optional newsgroup allowlisting before submitting an article upstream.
func ValidatePostArticle(raw []byte, maxBytes int, allowedGroups map[string]bool) ([]byte, []string, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPostBytes
	}
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("%w: empty article", errInvalidRequest)
	}
	if len(raw) > maxBytes {
		return nil, nil, fmt.Errorf("%w: article exceeds %d bytes", errPostNotAllowed, maxBytes)
	}
	if bytes.IndexByte(raw, 0) >= 0 {
		return nil, nil, fmt.Errorf("%w: binary NUL byte not permitted", errPostNotAllowed)
	}
	if !utf8.Valid(raw) {
		return nil, nil, fmt.Errorf("%w: article must be valid UTF-8 text", errPostNotAllowed)
	}

	norm := NormalizeArticleCRLF(raw)
	if len(norm) > maxBytes {
		return nil, nil, fmt.Errorf("%w: normalized article exceeds %d bytes", errPostNotAllowed, maxBytes)
	}

	headers, body, err := SplitHeadersAndBody(norm)
	if err != nil {
		return nil, nil, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, nil, fmt.Errorf("%w: empty article body", errInvalidRequest)
	}

	// Reject binary Usenet encodings (yEnc/uuencode) to stay Cleanfeed-NG text-only clean.
	for _, line := range bytes.Split(body, []byte("\r\n")) {
		if bytes.HasPrefix(line, []byte("=ybegin ")) || bytes.HasPrefix(line, []byte("begin 6")) {
			return nil, nil, fmt.Errorf("%w: binary attachments are not permitted", errPostNotAllowed)
		}
	}

	for name := range headers {
		if forbiddenPostHeaders[name] {
			return nil, nil, fmt.Errorf("%w: forbidden header %q", errPostNotAllowed, name)
		}
	}

	for _, req := range []string{"from", "newsgroups", "subject"} {
		if strings.TrimSpace(headers[req]) == "" {
			return nil, nil, fmt.Errorf("%w: missing required header %q", errInvalidRequest, req)
		}
	}
	if mid := headers["message-id"]; mid != "" {
		if err := ValidateMessageID(mid); err != nil {
			return nil, nil, err
		}
	}

	rawGroups := strings.Split(headers["newsgroups"], ",")
	if len(rawGroups) == 0 || len(rawGroups) > 4 {
		return nil, nil, fmt.Errorf("%w: too many crossposted newsgroups (max 4)", errPostNotAllowed)
	}
	groups := make([]string, 0, len(rawGroups))
	seen := make(map[string]bool, len(rawGroups))
	for _, g := range rawGroups {
		g = strings.TrimSpace(g)
		if err := ValidateGroupName(g); err != nil {
			return nil, nil, err
		}
		if seen[g] {
			continue
		}
		seen[g] = true
		if len(allowedGroups) > 0 && !allowedGroups[g] {
			return nil, nil, fmt.Errorf("%w: posting to %q is not allowed by gateway", errPostNotAllowed, g)
		}
		groups = append(groups, g)
	}

	if ft := headers["followup-to"]; ft != "" && !strings.EqualFold(ft, "poster") {
		for _, g := range strings.Split(ft, ",") {
			if err := ValidateGroupName(strings.TrimSpace(g)); err != nil {
				return nil, nil, err
			}
		}
	}

	if !bytes.HasSuffix(norm, []byte("\r\n")) {
		norm = append(norm, '\r', '\n')
	}
	return norm, groups, nil
}
