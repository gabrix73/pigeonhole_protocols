// Package git implements a Git service and protocol over Pigeonhole.
// It allows cloning, fetching, pushing, and bundle transfers of Git repositories
// over the Katzenpost Pigeonhole dead-drop mixnet architecture.
package git

import (
	"context"
	"errors"
)

// Common error definitions.
var (
	ErrInvalidRepoName = errors.New("git: invalid or unsafe repository name")
	ErrRepoNotFound    = errors.New("git: repository not found")
	ErrUnsupportedCmd  = errors.New("git: unsupported command or action")
	ErrServiceFailed   = errors.New("git: git subprocess execution failed")
)

// Action identifies the requested Git operation.
type Action string

const (
	// ActionConnect initiates a bidirectional streaming session to git-upload-pack or git-receive-pack.
	ActionConnect Action = "connect"

	// ActionInfoRefs requests ref advertisement (stateless RPC).
	ActionInfoRefs Action = "info-refs"

	// ActionUploadPack performs stateless packfile negotiation (clone/fetch).
	ActionUploadPack Action = "upload-pack"

	// ActionReceivePack performs stateless ref update and packfile ingestion (push).
	ActionReceivePack Action = "receive-pack"

	// ActionBundle creates and returns a standalone self-contained Git bundle.
	ActionBundle Action = "bundle"
)

// Request defines a Git operation request sent over Pigeonhole.
type Request struct {
	Action  Action `cbor:"action"`
	Repo    string `cbor:"repo"`
	Service string `cbor:"service,omitempty"` // "git-upload-pack" or "git-receive-pack"
	Payload []byte `cbor:"payload,omitempty"` // Stdin / negotiation data
	Ref     string `cbor:"ref,omitempty"`     // Specific ref or empty for --all
}

// Response defines the server's reply to a Git request.
type Response struct {
	Payload []byte `cbor:"payload,omitempty"`
	Error   string `cbor:"error,omitempty"`
}

// StreamChunk carries stream data for bidirectional session streaming.
type StreamChunk struct {
	Data []byte `cbor:"data,omitempty"`
	EOF  bool   `cbor:"eof,omitempty"`
	Err  string `cbor:"err,omitempty"`
}

// Conn represents one end of a Pigeonhole connection or session.
type Conn interface {
	Recv(ctx context.Context) ([]byte, error)
	Send(ctx context.Context, msg []byte) error
}
