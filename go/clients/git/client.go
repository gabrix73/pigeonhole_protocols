// Package git provides client helpers for interacting with the Pigeonhole Git service.
package git

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	services "github.com/katzenpost/pigeonhole_protocols/go/services/git"
)

var (
	// ErrBadResponse indicates an unparsable response from the service.
	ErrBadResponse = errors.New("git client: bad response from service")
)

// GetInfoRefs requests the remote ref advertisement for repo and service ("git-upload-pack" or "git-receive-pack").
func GetInfoRefs(ctx context.Context, conn services.Conn, repo, service string) ([]byte, error) {
	req := &services.Request{
		Action:  services.ActionInfoRefs,
		Repo:    repo,
		Service: service,
	}
	resp, err := roundtrip(ctx, conn, req)
	if err != nil {
		return nil, err
	}
	return resp.Payload, nil
}

// UploadPack executes a stateless upload-pack negotiation against repo.
func UploadPack(ctx context.Context, conn services.Conn, repo string, stdin []byte) ([]byte, error) {
	req := &services.Request{
		Action:  services.ActionUploadPack,
		Repo:    repo,
		Payload: stdin,
	}
	resp, err := roundtrip(ctx, conn, req)
	if err != nil {
		return nil, err
	}
	return resp.Payload, nil
}

// ReceivePack executes a stateless receive-pack push operation against repo.
func ReceivePack(ctx context.Context, conn services.Conn, repo string, stdin []byte) ([]byte, error) {
	req := &services.Request{
		Action:  services.ActionReceivePack,
		Repo:    repo,
		Payload: stdin,
	}
	resp, err := roundtrip(ctx, conn, req)
	if err != nil {
		return nil, err
	}
	return resp.Payload, nil
}

// GetBundle downloads a complete self-contained Git bundle from the service.
func GetBundle(ctx context.Context, conn services.Conn, repo, ref string) ([]byte, error) {
	req := &services.Request{
		Action: services.ActionBundle,
		Repo:   repo,
		Ref:    ref,
	}
	resp, err := roundtrip(ctx, conn, req)
	if err != nil {
		return nil, err
	}
	return resp.Payload, nil
}

// ConnectSession initiates a bidirectional streaming session and bridges r/w to the remote service.
func ConnectSession(ctx context.Context, conn services.Conn, repo, service string, r io.Reader, w io.Writer) error {
	req := &services.Request{
		Action:  services.ActionConnect,
		Repo:    repo,
		Service: service,
	}
	rawReq, err := common.Marshal(req)
	if err != nil {
		return err
	}
	if err := conn.Send(ctx, rawReq); err != nil {
		return err
	}

	// Read initial response to verify connection establishment
	rawReady, err := conn.Recv(ctx)
	if err != nil {
		return err
	}
	var readyResp services.Response
	if err := common.Unmarshal(rawReady, &readyResp); err != nil {
		return ErrBadResponse
	}
	if readyResp.Error != "" {
		return errors.New(readyResp.Error)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)

	// Goroutine: stream stdin r -> conn StreamChunk
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, readErr := r.Read(buf)
			if n > 0 {
				chunk := services.StreamChunk{Data: buf[:n]}
				rawChunk, _ := common.Marshal(&chunk)
				if sendErr := conn.Send(ctx, rawChunk); sendErr != nil {
					errCh <- sendErr
					return
				}
			}
			if readErr != nil {
				if readErr == io.EOF {
					chunk := services.StreamChunk{EOF: true}
					rawChunk, _ := common.Marshal(&chunk)
					_ = conn.Send(ctx, rawChunk)
				} else {
					errCh <- readErr
				}
				return
			}
		}
	}()

	// Goroutine: stream conn StreamChunk -> stdout w
	go func() {
		defer wg.Done()
		for {
			rawChunk, recvErr := conn.Recv(ctx)
			if recvErr != nil {
				errCh <- recvErr
				return
			}
			var chunk services.StreamChunk
			if err := common.Unmarshal(rawChunk, &chunk); err != nil {
				errCh <- err
				return
			}
			if chunk.EOF {
				return
			}
			if len(chunk.Data) > 0 {
				if _, writeErr := w.Write(chunk.Data); writeErr != nil {
					errCh <- writeErr
					return
				}
			}
		}
	}()

	wg.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func roundtrip(ctx context.Context, conn services.Conn, req *services.Request) (*services.Response, error) {
	raw, err := common.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("git client: failed to marshal request: %w", err)
	}
	if err := conn.Send(ctx, raw); err != nil {
		return nil, err
	}

	rawResp, err := conn.Recv(ctx)
	if err != nil {
		return nil, err
	}

	var resp services.Response
	if err := common.Unmarshal(rawResp, &resp); err != nil {
		return nil, ErrBadResponse
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return &resp, nil
}
