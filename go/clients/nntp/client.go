// SPDX-License-Identifier: AGPL-3.0-only

// Package nntp implements the Katzenpost Pigeonhole Usenet (NNTP) client,
// optional HPQC ASCII-armored encryption, local killfile filtering, thread
// reconstruction, local NNTP bridge (127.0.0.1:1119), and 0%-JS local Web UI.
package nntp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/stream"
	svc "github.com/katzenpost/pigeonhole_protocols/go/services/nntp"
)

// ErrBadReply reports a malformed or ambiguous gateway response.
var ErrBadReply = errors.New("nntp client: bad reply")

// Transport sends a CBOR NNTP Request and returns the decoded Response.
type Transport interface {
	Call(ctx context.Context, req *svc.Request) (*svc.Response, error)
}

// PigeonholeTransport sends NNTP RPCs over a Pigeonhole service connection,
// automatically using go/protocols/stream for oversized POSTs and responses.
type PigeonholeTransport struct {
	mu          sync.Mutex
	Conn        svc.Conn
	PH          common.Pigeonhole
	MaxResponse int64
	Tuning      *stream.Tuning
}

// Call executes one RPC over the Pigeonhole session.
func (t *PigeonholeTransport) Call(ctx context.Context, req *svc.Request) (*svc.Response, error) {
	if t == nil || t.Conn == nil {
		return nil, errors.New("nntp client: missing pigeonhole connection")
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	wireReq := *req
	encoded, err := common.Marshal(&wireReq)
	if err != nil {
		return nil, fmt.Errorf("nntp client: encode request: %w", err)
	}
	if t.PH != nil && len(encoded) > t.PH.MaxPlaintext() && len(wireReq.Article) > 0 {
		rc, err := stream.Publish(ctx, t.PH, bytes.NewReader(wireReq.Article), t.Tuning)
		if err != nil {
			return nil, fmt.Errorf("nntp client: stream article publish: %w", err)
		}
		rcBytes, err := rc.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("nntp client: marshal read cap: %w", err)
		}
		wireReq.Article = nil
		wireReq.ArticleStream = rcBytes
		encoded, err = common.Marshal(&wireReq)
		if err != nil {
			return nil, fmt.Errorf("nntp client: encode streamed request: %w", err)
		}
	}

	if err := t.Conn.Send(ctx, encoded); err != nil {
		return nil, err
	}
	raw, err := t.Conn.Recv(ctx)
	if err != nil {
		return nil, err
	}

	var resp svc.Response
	if err := common.Unmarshal(raw, &resp); err != nil {
		return nil, ErrBadReply
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("nntp gateway: %s", resp.Error)
	}

	if len(resp.PayloadStream) > 0 {
		if len(resp.Payload) > 0 {
			return nil, ErrBadReply
		}
		if t.PH == nil {
			return nil, errors.New("nntp client: streamed response requires Pigeonhole transport")
		}
		rc, err := bacap.ReadCapFromBytes(resp.PayloadStream)
		if err != nil {
			return nil, ErrBadReply
		}
		limit := t.MaxResponse
		if limit <= 0 {
			limit = svc.DefaultMaxResponseBytes
		}
		var buf bytes.Buffer
		if err := stream.Fetch(ctx, t.PH, rc, &buf, limit, t.Tuning); err != nil {
			return nil, fmt.Errorf("nntp client: stream fetch: %w", err)
		}
		resp.Payload = buf.Bytes()
		resp.PayloadStream = nil
	}
	return &resp, nil
}

// DirectTransport bypasses the mixnet and talks directly to an nntp.Backend
// (for local diagnostics, testing, or direct upstream access).
type DirectTransport struct {
	Backend svc.Backend
}

// Call runs the request directly on Backend.
func (t *DirectTransport) Call(ctx context.Context, req *svc.Request) (*svc.Response, error) {
	if t == nil || t.Backend == nil {
		return nil, errors.New("nntp client: missing direct backend")
	}
	return t.Backend.Execute(ctx, req)
}

// Client provides typed Usenet operations over a Transport.
type Client struct {
	Transport Transport
}

// NewClient wraps a Transport in a typed NNTP Client.
func NewClient(tr Transport) *Client {
	return &Client{Transport: tr}
}

// List fetches newsgroups matching an optional wildmat pattern.
func (c *Client) List(ctx context.Context, pattern string) (*svc.ListResult, error) {
	resp, err := c.Transport.Call(ctx, &svc.Request{Cmd: svc.CmdList, Pattern: pattern})
	if err != nil {
		return nil, err
	}
	if resp.Status != 215 {
		return nil, fmt.Errorf("nntp LIST failed: %d %s", resp.Status, resp.Message)
	}
	var res svc.ListResult
	if err := common.Unmarshal(resp.Payload, &res); err != nil {
		return nil, ErrBadReply
	}
	return &res, nil
}

// Group selects a newsgroup and returns its watermarks.
func (c *Client) Group(ctx context.Context, group string) (*svc.GroupInfo, error) {
	resp, err := c.Transport.Call(ctx, &svc.Request{Cmd: svc.CmdGroup, Group: group})
	if err != nil {
		return nil, err
	}
	if resp.Status != 211 {
		return nil, fmt.Errorf("nntp GROUP %s failed: %d %s", group, resp.Status, resp.Message)
	}
	var res svc.GroupResult
	if err := common.Unmarshal(resp.Payload, &res); err != nil {
		return nil, ErrBadReply
	}
	return &res.Group, nil
}

// Over fetches overview entries for group in [from, to] (0,0 means latest window).
func (c *Client) Over(ctx context.Context, group string, from, to uint64) (*svc.OverResult, error) {
	resp, err := c.Transport.Call(ctx, &svc.Request{
		Cmd:   svc.CmdOver,
		Group: group,
		From:  from,
		To:    to,
	})
	if err != nil {
		return nil, err
	}
	if resp.Status != 224 {
		return nil, fmt.Errorf("nntp OVER %s failed: %d %s", group, resp.Status, resp.Message)
	}
	var res svc.OverResult
	if err := common.Unmarshal(resp.Payload, &res); err != nil {
		return nil, ErrBadReply
	}
	return &res, nil
}

// ArticleByNum fetches one article by group and numeric ID.
func (c *Client) ArticleByNum(ctx context.Context, group string, num uint64) (*svc.ArticleResult, error) {
	resp, err := c.Transport.Call(ctx, &svc.Request{
		Cmd:           svc.CmdArticle,
		Group:         group,
		ArticleNumber: num,
	})
	if err != nil {
		return nil, err
	}
	if resp.Status != 220 {
		return nil, fmt.Errorf("nntp ARTICLE %s %d failed: %d %s", group, num, resp.Status, resp.Message)
	}
	var res svc.ArticleResult
	if err := common.Unmarshal(resp.Payload, &res); err != nil {
		return nil, ErrBadReply
	}
	return &res, nil
}

// ArticleByID fetches one article by Message-ID ("<local@domain>").
func (c *Client) ArticleByID(ctx context.Context, msgID string) (*svc.ArticleResult, error) {
	resp, err := c.Transport.Call(ctx, &svc.Request{
		Cmd:       svc.CmdArticle,
		ArticleID: msgID,
	})
	if err != nil {
		return nil, err
	}
	if resp.Status != 220 {
		return nil, fmt.Errorf("nntp ARTICLE %s failed: %d %s", msgID, resp.Status, resp.Message)
	}
	var res svc.ArticleResult
	if err := common.Unmarshal(resp.Payload, &res); err != nil {
		return nil, ErrBadReply
	}
	return &res, nil
}

// Post submits a raw RFC 5536 article (requires opt-in POST on the gateway).
func (c *Client) Post(ctx context.Context, rawArticle []byte) (*svc.PostResult, error) {
	resp, err := c.Transport.Call(ctx, &svc.Request{
		Cmd:     svc.CmdPost,
		Article: rawArticle,
	})
	if err != nil {
		return nil, err
	}
	if resp.Status != 240 {
		return nil, fmt.Errorf("nntp POST failed: %d %s", resp.Status, resp.Message)
	}
	var res svc.PostResult
	if err := common.Unmarshal(resp.Payload, &res); err != nil {
		return nil, ErrBadReply
	}
	return &res, nil
}

// BuildArticle formats a clean, privacy-preserving RFC 5536 text/plain UTF-8
// article compatible with Cleanfeed-NG and Postfilter-NG.
func BuildArticle(group, from, subject, references, body string) ([]byte, error) {
	group = strings.TrimSpace(group)
	from = sanitizeHeaderVal(from)
	subject = sanitizeHeaderVal(subject)
	references = sanitizeHeaderVal(references)

	if err := svc.ValidateGroupName(group); err != nil {
		return nil, err
	}
	if from == "" {
		from = "Anonymous <anon@pigeonhole.invalid>"
	}
	if subject == "" {
		return nil, errors.New("nntp client: subject is required")
	}
	if strings.TrimSpace(body) == "" {
		return nil, errors.New("nntp client: body is required")
	}

	var rnd [12]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, err
	}
	msgID := fmt.Sprintf("<%d.%s@pigeonhole.invalid>", time.Now().UTC().Unix(), hex.EncodeToString(rnd[:]))

	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("Newsgroups: " + group + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Message-ID: " + msgID + "\r\n")
	if references != "" {
		b.WriteString("References: " + references + "\r\n")
	}
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")

	normBody := svc.NormalizeArticleCRLF([]byte(body))
	b.Write(normBody)
	if !bytes.HasSuffix(normBody, []byte("\r\n")) {
		b.WriteString("\r\n")
	}
	return []byte(b.String()), nil
}

func sanitizeHeaderVal(v string) string {
	v = strings.ReplaceAll(v, "\r", " ")
	v = strings.ReplaceAll(v, "\n", " ")
	return strings.TrimSpace(v)
}
