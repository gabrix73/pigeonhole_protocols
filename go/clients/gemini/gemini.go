// Package gemini fetches Gemini capsules from the service in services/gemini.
package gemini

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/stream"
	"github.com/katzenpost/pigeonhole_protocols/go/services/gemini"
)

// ErrBadReply reports a reply that does not decode.
var ErrBadReply = errors.New("gemini: bad reply")

// Fetch asks for a Gemini URL over a Pigeonhole connection to the service.
func Fetch(ctx context.Context, conn gemini.Conn, rawURL string) (*gemini.Response, error) {
	return FetchStream(ctx, conn, nil, rawURL, gemini.DefaultMaxBodyBytes, nil)
}

// FetchStream asks for a Gemini URL over a Pigeonhole connection and fetches any
// offloaded body from the Pigeonhole stream referenced by BodyStream.
func FetchStream(ctx context.Context, conn gemini.Conn, ph common.Pigeonhole, rawURL string, maxBody int64, tuning *stream.Tuning) (*gemini.Response, error) {
	req, err := common.Marshal(&gemini.Request{URL: rawURL})
	if err != nil {
		return nil, fmt.Errorf("gemini: failed to encode request: %w", err)
	}
	if err := conn.Send(ctx, req); err != nil {
		return nil, err
	}
	raw, err := conn.Recv(ctx)
	if err != nil {
		return nil, err
	}
	var resp gemini.Response
	if err := common.Unmarshal(raw, &resp); err != nil {
		return nil, ErrBadReply
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("gemini: %s", resp.Error)
	}
	if len(resp.BodyStream) > 0 {
		if len(resp.Body) > 0 {
			return nil, ErrBadReply
		}
		if ph == nil {
			return nil, errors.New("gemini: streamed response requires a Pigeonhole transport")
		}
		rc, err := bacap.ReadCapFromBytes(resp.BodyStream)
		if err != nil {
			return nil, ErrBadReply
		}
		if maxBody <= 0 {
			maxBody = gemini.DefaultMaxBodyBytes
		}
		var buf bytes.Buffer
		if err := stream.Fetch(ctx, ph, rc, &buf, maxBody, tuning); err != nil {
			return nil, fmt.Errorf("gemini: stream fetch failed: %w", err)
		}
		resp.Body = buf.Bytes()
		resp.BodyStream = nil
	}
	return &resp, nil
}
