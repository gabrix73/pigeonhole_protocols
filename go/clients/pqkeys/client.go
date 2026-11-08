// Package pqkeys provides a client library for querying and registering post-quantum
// public keys over Pigeonhole services.
package pqkeys

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/pigeonhole_protocols/go/services/pqkeys"
)

var (
	ErrServerReply = errors.New("pqkeys: server returned an error")
	ErrBadReply    = errors.New("pqkeys: bad reply from server")
)

// Client interacts with the PQKeys directory service over a Pigeonhole connection.
type Client struct {
	conn pqkeys.Conn
}

// NewClient creates a new PQKeys client wrapping a connection.
func NewClient(conn pqkeys.Conn) *Client {
	return &Client{conn: conn}
}

// Publish registers or updates an armored post-quantum public key with self-signature.
func (c *Client) Publish(ctx context.Context, userID, armoredKey string, edPriv ed25519.PrivateKey) (*pqkeys.KeyRecord, error) {
	ts := time.Now().Unix()
	payload := pqkeys.SignedPayload(userID, armoredKey, ts)
	sig := ed25519.Sign(edPriv, payload)

	req := &pqkeys.Request{
		Action: pqkeys.ActionPublish,
		Publish: &pqkeys.PublishPayload{
			UserID:           userID,
			ArmoredPublicKey: armoredKey,
			Signature:        sig,
			Timestamp:        ts,
		},
	}

	reply, err := c.roundtrip(ctx, req)
	if err != nil {
		return nil, err
	}
	if !reply.Success {
		return nil, fmt.Errorf("%w: %s", ErrServerReply, reply.Error)
	}
	return reply.KeyRecord, nil
}

// Lookup queries a public key by fingerprint or user ID, and verifies the self-signature.
func (c *Client) Lookup(ctx context.Context, query string) (*pqkeys.KeyRecord, error) {
	req := &pqkeys.Request{
		Action: pqkeys.ActionLookup,
		Lookup: &pqkeys.LookupPayload{
			Query: query,
		},
	}

	reply, err := c.roundtrip(ctx, req)
	if err != nil {
		return nil, err
	}
	if !reply.Success || reply.KeyRecord == nil {
		return nil, fmt.Errorf("%w: %s", ErrServerReply, reply.Error)
	}

	rec := reply.KeyRecord
	// Zero-trust verification: verify self-signature before returning to caller
	if err := pqkeys.VerifySelfSignature(rec.UserID, rec.ArmoredPublicKey, rec.Timestamp, rec.Signature); err != nil {
		return nil, fmt.Errorf("pqkeys: received key failed self-signature verification: %w", err)
	}

	return rec, nil
}

// Revoke revokes a registered key using the owner's private signing key.
func (c *Client) Revoke(ctx context.Context, fingerprint, reason string, edPriv ed25519.PrivateKey) (*pqkeys.KeyRecord, error) {
	ts := time.Now().Unix()
	payload := pqkeys.RevocationSignedPayload(fingerprint, reason, ts)
	sig := ed25519.Sign(edPriv, payload)

	req := &pqkeys.Request{
		Action: pqkeys.ActionRevoke,
		Revoke: &pqkeys.RevokePayload{
			Fingerprint: fingerprint,
			Reason:      reason,
			Signature:   sig,
			Timestamp:   ts,
		},
	}

	reply, err := c.roundtrip(ctx, req)
	if err != nil {
		return nil, err
	}
	if !reply.Success || reply.KeyRecord == nil {
		return nil, fmt.Errorf("%w: %s", ErrServerReply, reply.Error)
	}
	return reply.KeyRecord, nil
}

// List retrieves paginated summaries of registered public keys.
func (c *Client) List(ctx context.Context, limit, offset int) ([]*pqkeys.KeyRecordSummary, error) {
	req := &pqkeys.Request{
		Action: pqkeys.ActionList,
		List: &pqkeys.ListPayload{
			Limit:  limit,
			Offset: offset,
		},
	}

	reply, err := c.roundtrip(ctx, req)
	if err != nil {
		return nil, err
	}
	if !reply.Success {
		return nil, fmt.Errorf("%w: %s", ErrServerReply, reply.Error)
	}
	return reply.Keys, nil
}

func (c *Client) roundtrip(ctx context.Context, req *pqkeys.Request) (*pqkeys.Reply, error) {
	raw, err := common.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("pqkeys: failed to marshal request: %w", err)
	}

	if err := c.conn.Send(ctx, raw); err != nil {
		return nil, fmt.Errorf("pqkeys: send failed: %w", err)
	}

	rawReply, err := c.conn.Recv(ctx)
	if err != nil {
		return nil, fmt.Errorf("pqkeys: recv failed: %w", err)
	}

	var reply pqkeys.Reply
	if err := common.Unmarshal(rawReply, &reply); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadReply, err)
	}
	return &reply, nil
}
