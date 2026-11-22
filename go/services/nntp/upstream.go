// SPDX-License-Identifier: AGPL-3.0-only

package nntp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

// Backend executes validated NNTP gateway requests.
type Backend interface {
	Execute(ctx context.Context, req *Request) (*Response, error)
}

// PostLimiter enforces a sliding-window rate limit on gateway POST operations.
type PostLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	times  []time.Time
	now    func() time.Time
}

// NewPostLimiter creates a PostLimiter allowing at most maxPosts per window.
func NewPostLimiter(maxPosts int, window time.Duration) *PostLimiter {
	if maxPosts <= 0 {
		maxPosts = DefaultPostRateLimit
	}
	if window <= 0 {
		window = DefaultPostRateWindow
	}
	return &PostLimiter{
		max:    maxPosts,
		window: window,
		now:    time.Now,
	}
}

// Allow reports whether another POST is permitted within the sliding window and
// records the timestamp when allowed.
func (l *PostLimiter) Allow() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.window)
	keep := l.times[:0]
	for _, ts := range l.times {
		if ts.After(cutoff) {
			keep = append(keep, ts)
		}
	}
	l.times = keep
	if len(l.times) >= l.max {
		return false
	}
	l.times = append(l.times, now)
	return true
}

// NNTPBackend connects to a single operator-configured upstream NNTP server
// without user authentication (e.g. news.tcpreset.net:563 over NNTPS/TLS).
//
// Implicit TLS (NNTPS, TLS 1.2+) is enabled by default. Plaintext NNTP (port
// 119) is disabled unless Plaintext is explicitly set to true; StartTLS upgrades
// a plaintext connection via RFC 4642 STARTTLS and refuses downgrade.
type NNTPBackend struct {
	// Addr is the upstream host:port configured by the gateway operator.
	Addr string
	// Plaintext disables implicit TLS (for local tests or legacy port-119 servers).
	// Public gateways should leave this false and connect over NNTPS (port 563).
	Plaintext bool
	// StartTLS upgrades a port-119 connection with RFC 4642 STARTTLS before
	// issuing any other command; refuses plaintext fallback if unsupported.
	StartTLS bool
	// TLSConfig overrides TLS settings for NNTPS or STARTTLS.
	TLSConfig *tls.Config
	// Timeout bounds each upstream NNTP session. Zero uses DefaultTimeout.
	Timeout time.Duration
	// MaxResponseBytes caps read response sizes. Zero uses DefaultMaxResponseBytes.
	MaxResponseBytes int64
	// MaxOverviewCount caps OVER entries per request. Zero uses DefaultMaxOverviewCount.
	MaxOverviewCount uint64
	// MaxGroups caps LIST entries returned. Zero uses DefaultMaxGroups.
	MaxGroups int
	// MaxPostBytes caps POST article sizes. Zero uses DefaultMaxPostBytes.
	MaxPostBytes int
	// AllowPost enables CmdPost. Disabled (false) by default.
	AllowPost bool
	// AllowedPostGroups restricts POST to specific newsgroups when non-empty.
	AllowedPostGroups []string
	// PostLimiter throttles POST submissions when AllowPost is true.
	PostLimiter *PostLimiter
}

func (b *NNTPBackend) timeout() time.Duration {
	if b.Timeout > 0 {
		return b.Timeout
	}
	return DefaultTimeout
}

func (b *NNTPBackend) maxResponseBytes() int64 {
	if b.MaxResponseBytes > 0 {
		return b.MaxResponseBytes
	}
	return DefaultMaxResponseBytes
}

func (b *NNTPBackend) maxOverviewCount() uint64 {
	if b.MaxOverviewCount > 0 {
		return b.MaxOverviewCount
	}
	return DefaultMaxOverviewCount
}

func (b *NNTPBackend) maxGroups() int {
	if b.MaxGroups > 0 {
		return b.MaxGroups
	}
	return DefaultMaxGroups
}

func (b *NNTPBackend) maxPostBytes() int {
	if b.MaxPostBytes > 0 {
		return b.MaxPostBytes
	}
	return DefaultMaxPostBytes
}

func (b *NNTPBackend) allowedPostSet() map[string]bool {
	if len(b.AllowedPostGroups) == 0 {
		return nil
	}
	m := make(map[string]bool, len(b.AllowedPostGroups))
	for _, g := range b.AllowedPostGroups {
		g = strings.TrimSpace(g)
		if g != "" {
			m[g] = true
		}
	}
	return m
}

// Execute runs a single NNTP RPC against the configured upstream server.
func (b *NNTPBackend) Execute(ctx context.Context, req *Request) (*Response, error) {
	if req == nil {
		return nil, fmt.Errorf("%w: nil request", errInvalidRequest)
	}
	if strings.TrimSpace(b.Addr) == "" {
		return nil, fmt.Errorf("%w: missing upstream NNTP address", errUpstreamConnect)
	}

	cmd := strings.ToUpper(strings.TrimSpace(req.Cmd))
	switch cmd {
	case CmdList:
		if err := ValidatePattern(req.Pattern); err != nil {
			return nil, err
		}
		return b.execList(ctx, req.Pattern)
	case CmdGroup:
		if err := ValidateGroupName(req.Group); err != nil {
			return nil, err
		}
		return b.execGroup(ctx, req.Group)
	case CmdOver:
		if err := ValidateGroupName(req.Group); err != nil {
			return nil, err
		}
		return b.execOver(ctx, req.Group, req.From, req.To)
	case CmdArticle:
		if req.ArticleID != "" {
			if err := ValidateMessageID(req.ArticleID); err != nil {
				return nil, err
			}
		} else {
			if err := ValidateGroupName(req.Group); err != nil {
				return nil, err
			}
			if req.ArticleNumber == 0 {
				return nil, fmt.Errorf("%w: article number must be > 0", errInvalidRequest)
			}
		}
		return b.execArticle(ctx, req.Group, req.ArticleNumber, req.ArticleID)
	case CmdPost:
		if !b.AllowPost {
			return &Response{Status: 440, Message: "posting not permitted by gateway"}, nil
		}
		norm, _, err := ValidatePostArticle(req.Article, b.maxPostBytes(), b.allowedPostSet())
		if err != nil {
			return nil, err
		}
		if b.PostLimiter != nil && !b.PostLimiter.Allow() {
			return nil, errRateLimited
		}
		return b.execPost(ctx, norm)
	default:
		return nil, fmt.Errorf("%w: unsupported command %q", errInvalidRequest, req.Cmd)
	}
}

type nntpWireConn struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

func (b *NNTPBackend) tlsConfigForAddr() (*tls.Config, error) {
	host, _, splitErr := net.SplitHostPort(b.Addr)
	if splitErr != nil {
		return nil, fmt.Errorf("%w: invalid address", errUpstreamConnect)
	}
	if b.TLSConfig == nil {
		return &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}, nil
	}
	tlsCfg := b.TLSConfig.Clone()
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = host
	}
	if tlsCfg.MinVersion < tls.VersionTLS12 {
		tlsCfg.MinVersion = tls.VersionTLS12
	}
	return tlsCfg, nil
}

func (b *NNTPBackend) dial(ctx context.Context) (*nntpWireConn, int, error) {
	timeout := b.timeout()
	connCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(connCtx, "tcp", b.Addr)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", errUpstreamConnect, err)
	}

	conn := rawConn
	useImplicitTLS := !b.Plaintext && !b.StartTLS
	if useImplicitTLS {
		tlsCfg, cfgErr := b.tlsConfigForAddr()
		if cfgErr != nil {
			rawConn.Close()
			return nil, 0, cfgErr
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(connCtx); err != nil {
			rawConn.Close()
			return nil, 0, fmt.Errorf("%w: TLS handshake failed: %v", errUpstreamConnect, err)
		}
		conn = tlsConn
	}

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)

	wc := &nntpWireConn{
		conn: conn,
		r:    bufio.NewReaderSize(conn, 32*1024),
		w:    bufio.NewWriterSize(conn, 16*1024),
	}

	code, _, err := wc.readStatus()
	if err != nil {
		wc.conn.Close()
		return nil, 0, err
	}
	if code != 200 && code != 201 {
		wc.closeQuiet()
		return nil, code, fmt.Errorf("%w: unexpected greeting %d", errUpstreamProtocol, code)
	}

	if b.StartTLS {
		tlsCfg, cfgErr := b.tlsConfigForAddr()
		if cfgErr != nil {
			wc.closeQuiet()
			return nil, 0, cfgErr
		}
		if err := wc.sendCmd("STARTTLS"); err != nil {
			wc.conn.Close()
			return nil, 0, err
		}
		stCode, _, err := wc.readStatus()
		if err != nil {
			wc.conn.Close()
			return nil, 0, err
		}
		if stCode != 382 {
			wc.closeQuiet()
			return nil, stCode, fmt.Errorf("%w: STARTTLS refused with %d", errUpstreamConnect, stCode)
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(connCtx); err != nil {
			rawConn.Close()
			return nil, 0, fmt.Errorf("%w: STARTTLS handshake failed: %v", errUpstreamConnect, err)
		}
		_ = tlsConn.SetDeadline(deadline)
		wc.conn = tlsConn
		wc.r = bufio.NewReaderSize(tlsConn, 32*1024)
		wc.w = bufio.NewWriterSize(tlsConn, 16*1024)
	}

	return wc, code, nil
}

func (wc *nntpWireConn) closeQuiet() {
	_, _ = wc.w.WriteString("QUIT\r\n")
	_ = wc.w.Flush()
	_ = wc.conn.Close()
}

func (wc *nntpWireConn) sendCmd(format string, args ...any) error {
	line := fmt.Sprintf(format, args...)
	if strings.ContainsAny(line, "\r\n") {
		return fmt.Errorf("%w: control character in NNTP command", errInvalidRequest)
	}
	if _, err := wc.w.WriteString(line + "\r\n"); err != nil {
		return fmt.Errorf("%w: write failed: %v", errUpstreamConnect, err)
	}
	if err := wc.w.Flush(); err != nil {
		return fmt.Errorf("%w: flush failed: %v", errUpstreamConnect, err)
	}
	return nil
}

func (wc *nntpWireConn) readLine(maxLen int) (string, error) {
	var buf []byte
	for {
		frag, isPrefix, err := wc.r.ReadLine()
		if err != nil {
			return "", fmt.Errorf("%w: read failed: %v", errUpstreamConnect, err)
		}
		if len(buf)+len(frag) > maxLen {
			return "", fmt.Errorf("%w: upstream line exceeds %d bytes", errUpstreamProtocol, maxLen)
		}
		buf = append(buf, frag...)
		if !isPrefix {
			return string(buf), nil
		}
	}
}

func (wc *nntpWireConn) readStatus() (int, string, error) {
	line, err := wc.readLine(4096)
	if err != nil {
		return 0, "", err
	}
	if len(line) < 3 {
		return 0, "", fmt.Errorf("%w: short status line", errUpstreamProtocol)
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil || code < 100 || code > 599 {
		return 0, "", fmt.Errorf("%w: invalid status code", errUpstreamProtocol)
	}
	msg := ""
	if len(line) > 4 {
		msg = strings.TrimSpace(line[4:])
	}
	return code, msg, nil
}

// readDotBlock reads a dot-terminated RFC 3977 multiline response, reversing
// dot-stuffing (".." -> ".") and bounding total output size.
func (wc *nntpWireConn) readDotBlock(maxBytes int64) ([]byte, error) {
	var out bytes.Buffer
	var total int64
	for {
		line, err := wc.readLine(64 * 1024)
		if err != nil {
			return nil, err
		}
		if line == "." {
			return out.Bytes(), nil
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		total += int64(len(line)) + 2
		if total > maxBytes {
			return nil, fmt.Errorf("%w: response exceeds %d bytes", errUpstreamProtocol, maxBytes)
		}
		out.WriteString(line)
		out.WriteString("\r\n")
	}
}

// writeDotBlock transmits a normalized CRLF article with RFC 3977 dot-stuffing.
func (wc *nntpWireConn) writeDotBlock(article []byte) error {
	lines := bytes.Split(bytes.TrimSuffix(article, []byte("\r\n")), []byte("\r\n"))
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte(".")) {
			if err := wc.w.WriteByte('.'); err != nil {
				return fmt.Errorf("%w: write failed: %v", errUpstreamConnect, err)
			}
		}
		if _, err := wc.w.Write(line); err != nil {
			return fmt.Errorf("%w: write failed: %v", errUpstreamConnect, err)
		}
		if _, err := wc.w.WriteString("\r\n"); err != nil {
			return fmt.Errorf("%w: write failed: %v", errUpstreamConnect, err)
		}
	}
	if _, err := wc.w.WriteString(".\r\n"); err != nil {
		return fmt.Errorf("%w: write failed: %v", errUpstreamConnect, err)
	}
	if err := wc.w.Flush(); err != nil {
		return fmt.Errorf("%w: flush failed: %v", errUpstreamConnect, err)
	}
	return nil
}

func (b *NNTPBackend) execList(ctx context.Context, pattern string) (*Response, error) {
	wc, _, err := b.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer wc.closeQuiet()

	clientFilter := false
	if pattern != "" {
		if err := wc.sendCmd("LIST ACTIVE %s", pattern); err != nil {
			return nil, err
		}
	} else {
		if err := wc.sendCmd("LIST ACTIVE"); err != nil {
			return nil, err
		}
	}
	code, msg, err := wc.readStatus()
	if err != nil {
		return nil, err
	}
	if (code == 500 || code == 501) && pattern != "" {
		// Fall back to plain LIST with client-side wildmat filtering.
		clientFilter = true
		if err := wc.sendCmd("LIST"); err != nil {
			return nil, err
		}
		code, msg, err = wc.readStatus()
		if err != nil {
			return nil, err
		}
	}
	if code != 215 {
		return &Response{Status: code, Message: sanitizeStatusMsg(msg)}, nil
	}
	block, err := wc.readDotBlock(b.maxResponseBytes())
	if err != nil {
		return nil, err
	}

	maxGroups := b.maxGroups()
	res := ListResult{}
	for _, rawLine := range strings.Split(strings.TrimSpace(string(block)), "\r\n") {
		if rawLine == "" {
			continue
		}
		fields := strings.Fields(rawLine)
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		if clientFilter && pattern != "" {
			matched, _ := path.Match(pattern, name)
			if !matched {
				continue
			}
		}
		if len(res.Groups) >= maxGroups {
			res.Truncated = true
			break
		}
		high, _ := strconv.ParseUint(fields[1], 10, 64)
		low, _ := strconv.ParseUint(fields[2], 10, 64)
		var count uint64
		if high >= low && high > 0 {
			count = high - low + 1
		}
		res.Groups = append(res.Groups, GroupInfo{
			Name:   name,
			High:   high,
			Low:    low,
			Count:  count,
			Status: fields[3],
		})
	}
	payload, err := common.Marshal(&res)
	if err != nil {
		return nil, err
	}
	return &Response{Status: 215, Message: "list of newsgroups follows", Payload: payload}, nil
}

func (b *NNTPBackend) execGroup(ctx context.Context, group string) (*Response, error) {
	wc, _, err := b.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer wc.closeQuiet()

	info, code, msg, err := selectGroup(wc, group)
	if err != nil {
		return nil, err
	}
	if code != 211 {
		return &Response{Status: code, Message: sanitizeStatusMsg(msg)}, nil
	}
	payload, err := common.Marshal(&GroupResult{Group: info})
	if err != nil {
		return nil, err
	}
	return &Response{Status: 211, Message: "group selected", Payload: payload}, nil
}

func selectGroup(wc *nntpWireConn, group string) (GroupInfo, int, string, error) {
	if err := wc.sendCmd("GROUP %s", group); err != nil {
		return GroupInfo{}, 0, "", err
	}
	code, msg, err := wc.readStatus()
	if err != nil {
		return GroupInfo{}, 0, "", err
	}
	if code != 211 {
		return GroupInfo{}, code, msg, nil
	}
	fields := strings.Fields(msg)
	if len(fields) < 3 {
		return GroupInfo{}, 0, "", fmt.Errorf("%w: malformed GROUP response", errUpstreamProtocol)
	}
	count, err1 := strconv.ParseUint(fields[0], 10, 64)
	low, err2 := strconv.ParseUint(fields[1], 10, 64)
	high, err3 := strconv.ParseUint(fields[2], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return GroupInfo{}, 0, "", fmt.Errorf("%w: non-numeric GROUP watermarks", errUpstreamProtocol)
	}
	name := group
	if len(fields) >= 4 {
		name = fields[3]
	}
	return GroupInfo{Name: name, Count: count, Low: low, High: high}, 211, msg, nil
}

func (b *NNTPBackend) execOver(ctx context.Context, group string, from, to uint64) (*Response, error) {
	wc, _, err := b.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer wc.closeQuiet()

	info, code, msg, err := selectGroup(wc, group)
	if err != nil {
		return nil, err
	}
	if code != 211 {
		return &Response{Status: code, Message: sanitizeStatusMsg(msg)}, nil
	}

	maxCount := b.maxOverviewCount()
	if info.Count == 0 || info.High == 0 {
		payload, err := common.Marshal(&OverResult{Group: info.Name})
		if err != nil {
			return nil, err
		}
		return &Response{Status: 224, Message: "overview information follows", Payload: payload}, nil
	}

	if from == 0 && to == 0 {
		to = info.High
		if info.High >= maxCount {
			from = info.High - maxCount + 1
		} else {
			from = info.Low
		}
		if from < info.Low {
			from = info.Low
		}
	} else {
		if from < info.Low {
			from = info.Low
		}
		if to == 0 || to > info.High {
			to = info.High
		}
		if from > to {
			payload, err := common.Marshal(&OverResult{Group: info.Name})
			if err != nil {
				return nil, err
			}
			return &Response{Status: 224, Message: "overview information follows", Payload: payload}, nil
		}
		if to-from+1 > maxCount {
			to = from + maxCount - 1
		}
	}

	rangeArg := fmt.Sprintf("%d-%d", from, to)
	if err := wc.sendCmd("OVER %s", rangeArg); err != nil {
		return nil, err
	}
	code, msg, err = wc.readStatus()
	if err != nil {
		return nil, err
	}
	if code == 500 || code == 501 {
		// Older servers only implement XOVER.
		if err := wc.sendCmd("XOVER %s", rangeArg); err != nil {
			return nil, err
		}
		code, msg, err = wc.readStatus()
		if err != nil {
			return nil, err
		}
	}
	if code != 224 {
		return &Response{Status: code, Message: sanitizeStatusMsg(msg)}, nil
	}
	block, err := wc.readDotBlock(b.maxResponseBytes())
	if err != nil {
		return nil, err
	}

	entries := parseOverviewBlock(block, maxCount)
	payload, err := common.Marshal(&OverResult{Group: info.Name, Entries: entries})
	if err != nil {
		return nil, err
	}
	return &Response{Status: 224, Message: "overview information follows", Payload: payload}, nil
}

func parseOverviewBlock(block []byte, maxCount uint64) []OverviewEntry {
	var entries []OverviewEntry
	for _, rawLine := range strings.Split(strings.TrimSuffix(string(block), "\r\n"), "\r\n") {
		if rawLine == "" {
			continue
		}
		if uint64(len(entries)) >= maxCount {
			break
		}
		cols := strings.Split(rawLine, "\t")
		if len(cols) < 5 {
			continue
		}
		num, err := strconv.ParseUint(strings.TrimSpace(cols[0]), 10, 64)
		if err != nil {
			continue
		}
		entry := OverviewEntry{
			Number:    num,
			Subject:   cols[1],
			From:      cols[2],
			Date:      cols[3],
			MessageID: cols[4],
		}
		if len(cols) > 5 {
			entry.References = cols[5]
		}
		if len(cols) > 6 {
			entry.Bytes, _ = strconv.ParseUint(strings.TrimSpace(cols[6]), 10, 64)
		}
		if len(cols) > 7 {
			entry.Lines, _ = strconv.ParseUint(strings.TrimSpace(cols[7]), 10, 64)
		}
		for i := 8; i < len(cols); i++ {
			if strings.HasPrefix(strings.ToLower(cols[i]), "xref:") {
				entry.Xref = strings.TrimSpace(cols[i][5:])
				break
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

func (b *NNTPBackend) execArticle(ctx context.Context, group string, num uint64, msgID string) (*Response, error) {
	wc, _, err := b.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer wc.closeQuiet()

	if msgID == "" {
		_, code, msg, err := selectGroup(wc, group)
		if err != nil {
			return nil, err
		}
		if code != 211 {
			return &Response{Status: code, Message: sanitizeStatusMsg(msg)}, nil
		}
		if err := wc.sendCmd("ARTICLE %d", num); err != nil {
			return nil, err
		}
	} else {
		if err := wc.sendCmd("ARTICLE %s", msgID); err != nil {
			return nil, err
		}
	}

	code, msg, err := wc.readStatus()
	if err != nil {
		return nil, err
	}
	if code != 220 {
		return &Response{Status: code, Message: sanitizeStatusMsg(msg)}, nil
	}

	rawArticle, err := wc.readDotBlock(b.maxResponseBytes())
	if err != nil {
		return nil, err
	}

	res := ArticleResult{
		Number:    num,
		MessageID: msgID,
		Raw:       rawArticle,
	}
	fields := strings.Fields(msg)
	if len(fields) >= 2 {
		if parsedNum, parseErr := strconv.ParseUint(fields[0], 10, 64); parseErr == nil && res.Number == 0 {
			res.Number = parsedNum
		}
		if strings.HasPrefix(fields[1], "<") && strings.HasSuffix(fields[1], ">") {
			res.MessageID = fields[1]
		}
	}
	payload, err := common.Marshal(&res)
	if err != nil {
		return nil, err
	}
	return &Response{Status: 220, Message: "article follows", Payload: payload}, nil
}

func (b *NNTPBackend) execPost(ctx context.Context, normArticle []byte) (*Response, error) {
	wc, greeting, err := b.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer wc.closeQuiet()

	if greeting == 201 {
		return &Response{Status: 440, Message: "posting not permitted by upstream"}, nil
	}

	if err := wc.sendCmd("POST"); err != nil {
		return nil, err
	}
	code, msg, err := wc.readStatus()
	if err != nil {
		return nil, err
	}
	if code != 340 {
		return &Response{Status: code, Message: sanitizeStatusMsg(msg)}, nil
	}
	if err := wc.writeDotBlock(normArticle); err != nil {
		return nil, err
	}
	code, msg, err = wc.readStatus()
	if err != nil {
		return nil, err
	}
	if code != 240 {
		return &Response{Status: code, Message: sanitizeStatusMsg(msg)}, nil
	}

	res := PostResult{Accepted: true}
	for _, tok := range strings.Fields(msg) {
		if strings.HasPrefix(tok, "<") && strings.HasSuffix(tok, ">") {
			res.MessageID = tok
			break
		}
	}
	payload, err := common.Marshal(&res)
	if err != nil {
		return nil, err
	}
	return &Response{Status: 240, Message: "article received ok", Payload: payload}, nil
}

// sanitizeStatusMsg returns a bounded, control-char-free status string so
// upstream banners cannot smuggle arbitrary text or internal infrastructure info.
func sanitizeStatusMsg(msg string) string {
	msg = strings.TrimSpace(msg)
	if len(msg) > 120 {
		msg = msg[:120]
	}
	var out strings.Builder
	out.Grow(len(msg))
	for i := 0; i < len(msg); i++ {
		c := msg[i]
		if c >= 0x20 && c < 0x7f {
			out.WriteByte(c)
		}
	}
	return out.String()
}

func sanitizeError(err error) string {
	switch {
	case errors.Is(err, errInvalidRequest):
		return "bad request: invalid NNTP request"
	case errors.Is(err, errPostDisabled):
		return "post rejected: posting disabled on gateway"
	case errors.Is(err, errPostNotAllowed):
		return "post rejected: violates gateway policy"
	case errors.Is(err, errRateLimited):
		return "post rejected: gateway rate limit exceeded"
	case errors.Is(err, errUpstreamProtocol):
		return "nntp failed: invalid upstream response"
	default:
		return "nntp failed: upstream connection failed"
	}
}
