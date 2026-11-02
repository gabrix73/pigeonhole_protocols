// Package gemini fetches Gemini capsules from the service in services/gemini.
package gemini

import (
	"context"
	"errors"
	"fmt"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/pigeonhole_protocols/go/services/gemini"
)

// ErrBadReply reports a reply that does not decode.
var ErrBadReply = errors.New("gemini: bad reply")

// Fetch asks for a Gemini URL over a Pigeonhole connection to the service.
func Fetch(ctx context.Context, conn gemini.Conn, rawURL string) (*gemini.Response, error) {
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
	return &resp, nil
}
