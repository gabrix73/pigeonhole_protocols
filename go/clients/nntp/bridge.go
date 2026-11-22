// SPDX-License-Identifier: AGPL-3.0-only

package nntp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	svc "github.com/katzenpost/pigeonhole_protocols/go/services/nntp"
)

// DefaultBridgeAddr is the loopback-only listen address for the local NNTP bridge.
const DefaultBridgeAddr = "127.0.0.1:1119"

// LocalBridge exposes a standard RFC 3977 NNTP reader endpoint on loopback
// (default 127.0.0.1:1119) backed by Client over Pigeonhole, allowing ordinary
// Usenet newsreaders to read and post transparently over Katzenpost.
type LocalBridge struct {
	Client        *Client
	ListenAddr    string
	AllowPost     bool
	Keypair       *Keypair
	DecryptOnRead bool
	Killfile      *Killfile
	CacheTTL      time.Duration

	mu           sync.Mutex
	articleCache map[string]cachedArticle
	overCache    map[string]cachedOver
}

type cachedArticle struct {
	res *svc.ArticleResult
	exp time.Time
}

type cachedOver struct {
	res *svc.OverResult
	exp time.Time
}

// Serve accepts local NNTP reader connections on ln until ctx is cancelled.
func (b *LocalBridge) Serve(ctx context.Context, ln net.Listener) error {
	if b.CacheTTL <= 0 {
		b.CacheTTL = 2 * time.Minute
	}
	b.mu.Lock()
	if b.articleCache == nil {
		b.articleCache = make(map[string]cachedArticle)
	}
	if b.overCache == nil {
		b.overCache = make(map[string]cachedOver)
	}
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go b.handleClient(ctx, conn)
	}
}

// ListenAndServe binds ListenAddr (default 127.0.0.1:1119) and serves NNTP.
func (b *LocalBridge) ListenAndServe(ctx context.Context) error {
	addr := strings.TrimSpace(b.ListenAddr)
	if addr == "" {
		addr = DefaultBridgeAddr
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return b.Serve(ctx, ln)
}

func (b *LocalBridge) handleClient(ctx context.Context, c net.Conn) {
	defer c.Close()
	r := bufio.NewReaderSize(c, 32*1024)
	w := bufio.NewWriterSize(c, 32*1024)

	writeLine := func(s string) {
		_, _ = w.WriteString(s + "\r\n")
		_ = w.Flush()
	}

	if b.AllowPost {
		writeLine("200 pigeonhole-nntp local bridge ready (posting ok)")
	} else {
		writeLine("201 pigeonhole-nntp local bridge ready (no posting)")
	}

	var currentGroup string
	for {
		if ctx.Err() != nil {
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToUpper(parts[0])
		switch cmd {
		case "QUIT":
			writeLine("205 goodbye")
			return
		case "CAPABILITIES":
			writeLine("101 Capability list:")
			writeLine("VERSION 2")
			writeLine("READER")
			writeLine("LIST ACTIVE")
			writeLine("OVER")
			if b.AllowPost {
				writeLine("POST")
			}
			writeLine(".")
		case "MODE":
			if len(parts) >= 2 && strings.EqualFold(parts[1], "READER") {
				if b.AllowPost {
					writeLine("200 pigeonhole-nntp reader ready (posting ok)")
				} else {
					writeLine("201 pigeonhole-nntp reader ready (no posting)")
				}
			} else {
				writeLine("501 unsupported mode")
			}
		case "LIST":
			pattern := ""
			if len(parts) >= 3 && strings.EqualFold(parts[1], "ACTIVE") {
				pattern = parts[2]
			}
			res, err := b.Client.List(ctx, pattern)
			if err != nil {
				writeLine("403 upstream error")
				continue
			}
			writeLine("215 list of newsgroups follows")
			for _, g := range res.Groups {
				status := g.Status
				if status == "" {
					status = "y"
				}
				_, _ = fmt.Fprintf(w, "%s %d %d %s\r\n", g.Name, g.High, g.Low, status)
			}
			writeLine(".")
		case "GROUP":
			if len(parts) < 2 {
				writeLine("501 missing newsgroup")
				continue
			}
			info, err := b.Client.Group(ctx, parts[1])
			if err != nil {
				writeLine("411 no such newsgroup")
				continue
			}
			currentGroup = info.Name
			writeLine(fmt.Sprintf("211 %d %d %d %s", info.Count, info.Low, info.High, info.Name))
		case "OVER", "XOVER":
			if currentGroup == "" {
				writeLine("412 no newsgroup selected")
				continue
			}
			var from, to uint64
			if len(parts) >= 2 {
				rng := strings.SplitN(parts[1], "-", 2)
				from, _ = strconv.ParseUint(rng[0], 10, 64)
				if len(rng) == 2 {
					if rng[1] != "" {
						to, _ = strconv.ParseUint(rng[1], 10, 64)
					}
				} else {
					to = from
				}
			}
			res, err := b.fetchOverCached(ctx, currentGroup, from, to)
			if err != nil {
				writeLine("420 no overview available")
				continue
			}
			counts := AuthorCounts(res.Entries)
			writeLine("224 overview information follows")
			for _, e := range res.Entries {
				if b.Killfile != nil {
					if hidden, _ := b.Killfile.EvaluateOverview(e, counts); hidden {
						continue
					}
				}
				xrefField := ""
				if e.Xref != "" {
					xrefField = "\tXref: " + e.Xref
				}
				_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d%s\r\n",
					e.Number, e.Subject, e.From, e.Date, e.MessageID, e.References, e.Bytes, e.Lines, xrefField)
			}
			writeLine(".")
		case "ARTICLE", "HEAD", "BODY", "STAT":
			if len(parts) < 2 {
				writeLine("501 missing article specifier")
				continue
			}
			arg := parts[1]
			art, err := b.fetchArticleCached(ctx, currentGroup, arg)
			if err != nil {
				writeLine("430 no such article")
				continue
			}
			raw := b.maybeDecryptArticle(art.Raw)
			mid := art.MessageID
			if mid == "" {
				mid = "<0@pigeonhole.invalid>"
			}
			switch cmd {
			case "STAT":
				writeLine(fmt.Sprintf("223 %d %s status", art.Number, mid))
			case "ARTICLE":
				writeLine(fmt.Sprintf("220 %d %s article follows", art.Number, mid))
				writeDotStuffed(w, raw)
				writeLine(".")
			case "HEAD":
				hdr, _ := splitRawHeadBody(raw)
				writeLine(fmt.Sprintf("221 %d %s headers follow", art.Number, mid))
				writeDotStuffed(w, hdr)
				writeLine(".")
			case "BODY":
				_, body := splitRawHeadBody(raw)
				writeLine(fmt.Sprintf("222 %d %s body follows", art.Number, mid))
				writeDotStuffed(w, body)
				writeLine(".")
			}
		case "POST":
			if !b.AllowPost {
				writeLine("440 posting not permitted")
				continue
			}
			writeLine("340 send article to be posted")
			var buf bytes.Buffer
			tooLarge := false
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				l = strings.TrimRight(l, "\r\n")
				if l == "." {
					break
				}
				if strings.HasPrefix(l, "..") {
					l = l[1:]
				}
				if buf.Len()+len(l)+2 > svc.DefaultMaxPostBytes {
					tooLarge = true
					continue
				}
				buf.WriteString(l + "\r\n")
			}
			if tooLarge {
				writeLine("441 article exceeds maximum allowed size")
				continue
			}
			res, err := b.Client.Post(ctx, buf.Bytes())
			if err != nil || !res.Accepted {
				writeLine("441 posting failed")
				continue
			}
			writeLine("240 article received ok")
		default:
			writeLine("500 command not recognized")
		}
	}
}

func (b *LocalBridge) fetchOverCached(ctx context.Context, group string, from, to uint64) (*svc.OverResult, error) {
	key := fmt.Sprintf("%s:%d:%d", group, from, to)
	now := time.Now()
	b.mu.Lock()
	if ce, ok := b.overCache[key]; ok && now.Before(ce.exp) {
		b.mu.Unlock()
		return ce.res, nil
	}
	b.mu.Unlock()

	res, err := b.Client.Over(ctx, group, from, to)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.overCache[key] = cachedOver{res: res, exp: now.Add(b.CacheTTL)}
	b.mu.Unlock()
	return res, nil
}

func (b *LocalBridge) fetchArticleCached(ctx context.Context, group, arg string) (*svc.ArticleResult, error) {
	key := group + ":" + arg
	now := time.Now()
	b.mu.Lock()
	if ce, ok := b.articleCache[key]; ok && now.Before(ce.exp) {
		b.mu.Unlock()
		return ce.res, nil
	}
	b.mu.Unlock()

	var (
		res *svc.ArticleResult
		err error
	)
	if strings.HasPrefix(arg, "<") {
		res, err = b.Client.ArticleByID(ctx, arg)
	} else {
		if group == "" {
			return nil, fmt.Errorf("no newsgroup selected")
		}
		num, parseErr := strconv.ParseUint(arg, 10, 64)
		if parseErr != nil {
			return nil, parseErr
		}
		res, err = b.Client.ArticleByNum(ctx, group, num)
	}
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.articleCache[key] = cachedArticle{res: res, exp: now.Add(b.CacheTTL)}
	b.mu.Unlock()
	return res, nil
}

func (b *LocalBridge) maybeDecryptArticle(raw []byte) []byte {
	if !b.DecryptOnRead || b.Keypair == nil {
		return raw
	}
	hdr, body := splitRawHeadBody(raw)
	outcome := InspectBody(string(body), b.Keypair)
	if !outcome.Decrypted {
		return raw
	}
	var out bytes.Buffer
	out.Write(hdr)
	out.WriteString("X-Pigeonhole-HPQC: decrypted\r\n\r\n")
	out.Write(svc.NormalizeArticleCRLF([]byte(outcome.Plaintext)))
	return out.Bytes()
}

func splitRawHeadBody(raw []byte) (hdr, body []byte) {
	norm := svc.NormalizeArticleCRLF(raw)
	idx := bytes.Index(norm, []byte("\r\n\r\n"))
	if idx < 0 {
		return norm, nil
	}
	return norm[:idx+2], norm[idx+4:]
}

func writeDotStuffed(w *bufio.Writer, raw []byte) {
	norm := bytes.TrimSuffix(svc.NormalizeArticleCRLF(raw), []byte("\r\n"))
	if len(norm) == 0 {
		return
	}
	for _, line := range bytes.Split(norm, []byte("\r\n")) {
		if bytes.HasPrefix(line, []byte(".")) {
			_ = w.WriteByte('.')
		}
		_, _ = w.Write(line)
		_, _ = w.WriteString("\r\n")
	}
}
