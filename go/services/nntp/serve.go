// SPDX-License-Identifier: AGPL-3.0-only

package nntp

import (
	"bytes"
	"context"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/stream"
)

// Conn is one end of a Pigeonhole connection: a *pigeonservice.Session on the
// service side, or a *voucher_router.Conn on the client side.
type Conn interface {
	Recv(ctx context.Context) ([]byte, error)
	Send(ctx context.Context, msg []byte) error
}

// Serve answers NNTP requests on one client connection without stream offloading.
func Serve(ctx context.Context, s Conn, backend Backend) error {
	return ServeStream(ctx, s, nil, backend, nil)
}

// ServeStream answers NNTP requests on one client connection.
//
// When ph is non-nil:
//   - Oversized POST articles sent via Request.ArticleStream are fetched from
//     the referenced Pigeonhole stream up to DefaultMaxPostBytes.
//   - Oversized responses whose CBOR encoding exceeds ph.MaxPlaintext() have
//     their Payload published to a new Pigeonhole stream, returning the
//     serialized bacap.ReadCap in Response.PayloadStream.
func ServeStream(ctx context.Context, s Conn, ph common.Pigeonhole, backend Backend, tuning *stream.Tuning) error {
	for {
		raw, err := s.Recv(ctx)
		if err != nil {
			return err
		}

		var req Request
		var resp Response
		if err := common.Unmarshal(raw, &req); err != nil {
			resp.Error = "bad request: failed to decode CBOR"
		} else if len(req.ArticleStream) > 0 && len(req.Article) > 0 {
			resp.Error = "bad request: ambiguous article payload"
		} else {
			streamErr := false
			if len(req.ArticleStream) > 0 {
				if ph == nil {
					resp.Error = "bad request: streamed article requires Pigeonhole transport"
					streamErr = true
				} else if rc, err := bacap.ReadCapFromBytes(req.ArticleStream); err != nil {
					resp.Error = "bad request: invalid article stream capability"
					streamErr = true
				} else {
					var buf bytes.Buffer
					if err := stream.Fetch(ctx, ph, rc, &buf, int64(DefaultMaxPostBytes), tuning); err != nil {
						resp.Error = "bad request: failed to fetch article stream"
						streamErr = true
					} else {
						req.Article = buf.Bytes()
						req.ArticleStream = nil
					}
				}
			}

			if !streamErr {
				r, err := backend.Execute(ctx, &req)
				if err != nil {
					resp.Error = sanitizeError(err)
				} else if r == nil {
					resp.Error = "nntp failed: empty backend response"
				} else {
					resp = *r
				}
			}
		}

		reply, err := common.Marshal(&resp)
		if err != nil {
			return err
		}
		if ph != nil && len(reply) > ph.MaxPlaintext() && len(resp.Payload) > 0 {
			rc, err := stream.Publish(ctx, ph, bytes.NewReader(resp.Payload), tuning)
			if err != nil {
				resp = Response{Error: "nntp failed: stream publish failed"}
			} else if rcBytes, err := rc.MarshalBinary(); err != nil {
				resp = Response{Error: "nntp failed: stream publish failed"}
			} else {
				resp = Response{
					Status:        resp.Status,
					Message:       resp.Message,
					PayloadStream: rcBytes,
				}
			}
			reply, err = common.Marshal(&resp)
			if err != nil {
				return err
			}
		}

		if err := s.Send(ctx, reply); err != nil {
			return err
		}
	}
}
