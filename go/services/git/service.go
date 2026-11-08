// Package git implements the server side of the Pigeonhole Git service.
package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

// Server serves Git repositories over Pigeonhole.
type Server struct {
	reposDir string
}

// NewServer creates a new Git server rooted at reposDir.
func NewServer(reposDir string) (*Server, error) {
	abs, err := filepath.Abs(reposDir)
	if err != nil {
		return nil, fmt.Errorf("git: invalid repos directory: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("git: repos directory error: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("git: %s is not a directory", abs)
	}
	return &Server{reposDir: abs}, nil
}

// ResolveRepo finds the on-disk git directory, preventing path traversal.
func (s *Server) ResolveRepo(name string) (string, error) {
	clean := filepath.Clean(name)
	// Strip leading slashes
	for strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "\\") {
		clean = clean[1:]
	}
	if clean == "" || clean == "." || strings.Contains(clean, "..") {
		return "", ErrInvalidRepoName
	}

	// Try exact, .git extension, or directory containing .git
	candidates := []string{
		filepath.Join(s.reposDir, clean),
		filepath.Join(s.reposDir, clean+".git"),
		filepath.Join(s.reposDir, strings.TrimSuffix(clean, ".git")),
	}

	for _, cand := range candidates {
		// Ensure it stays inside reposDir
		rel, err := filepath.Rel(s.reposDir, cand)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", ErrInvalidRepoName
		}

		info, err := os.Stat(cand)
		if err == nil && info.IsDir() {
			// Check if bare repo or working tree
			if isGitDir(cand) {
				return cand, nil
			}
			dotGit := filepath.Join(cand, ".git")
			if infoDot, errDot := os.Stat(dotGit); errDot == nil && infoDot.IsDir() {
				return dotGit, nil
			}
		}
	}

	return "", fmt.Errorf("%w: %s", ErrRepoNotFound, name)
}

func isGitDir(path string) bool {
	// A bare git repo typically has HEAD, objects, and refs
	head := filepath.Join(path, "HEAD")
	objects := filepath.Join(path, "objects")
	refs := filepath.Join(path, "refs")

	if _, err := os.Stat(head); err != nil {
		return false
	}
	if _, err := os.Stat(objects); err != nil {
		return false
	}
	if _, err := os.Stat(refs); err != nil {
		return false
	}
	return true
}

// Handle processes an incoming connection from a client.
func (s *Server) Handle(ctx context.Context, conn Conn) error {
	raw, err := conn.Recv(ctx)
	if err != nil {
		return err
	}

	var req Request
	if err := common.Unmarshal(raw, &req); err != nil {
		_ = sendError(ctx, conn, "git: malformed request")
		return err
	}

	repoPath, err := s.ResolveRepo(req.Repo)
	if err != nil {
		_ = sendError(ctx, conn, err.Error())
		return err
	}

	switch req.Action {
	case ActionInfoRefs:
		return s.handleInfoRefs(ctx, conn, repoPath, req.Service)
	case ActionUploadPack:
		return s.handleUploadPack(ctx, conn, repoPath, req.Payload)
	case ActionReceivePack:
		return s.handleReceivePack(ctx, conn, repoPath, req.Payload)
	case ActionBundle:
		return s.handleBundle(ctx, conn, repoPath, req.Ref)
	case ActionConnect:
		return s.handleConnect(ctx, conn, repoPath, req.Service)
	default:
		_ = sendError(ctx, conn, ErrUnsupportedCmd.Error())
		return ErrUnsupportedCmd
	}
}

func (s *Server) handleInfoRefs(ctx context.Context, conn Conn, repoPath, service string) error {
	if service != "git-upload-pack" && service != "git-receive-pack" {
		service = "git-upload-pack"
	}

	subCmd := strings.TrimPrefix(service, "git-")
	cmd := exec.CommandContext(ctx, "git", subCmd, "--stateless-rpc", "--advertise-refs", repoPath)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			_ = sendError(ctx, conn, fmt.Sprintf("git: advertise-refs error: %s", string(exitErr.Stderr)))
		} else {
			_ = sendError(ctx, conn, err.Error())
		}
		return err
	}

	// Format smart HTTP pkt-line prefix
	var buf bytes.Buffer
	prefixPayload := fmt.Sprintf("# service=%s\n", service)
	prefixPkt := fmt.Sprintf("%04x%s0000", len(prefixPayload)+4, prefixPayload)
	buf.WriteString(prefixPkt)
	buf.Write(out)

	resp, err := common.Marshal(&Response{Payload: buf.Bytes()})
	if err != nil {
		return err
	}
	return conn.Send(ctx, resp)
}

func (s *Server) handleUploadPack(ctx context.Context, conn Conn, repoPath string, stdinData []byte) error {
	cmd := exec.CommandContext(ctx, "git", "upload-pack", "--stateless-rpc", repoPath)
	cmd.Stdin = bytes.NewReader(stdinData)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		_ = sendError(ctx, conn, fmt.Sprintf("git: upload-pack error: %s (err: %v)", stderr.String(), err))
		return err
	}

	resp, err := common.Marshal(&Response{Payload: stdout.Bytes()})
	if err != nil {
		return err
	}
	return conn.Send(ctx, resp)
}

func (s *Server) handleReceivePack(ctx context.Context, conn Conn, repoPath string, stdinData []byte) error {
	cmd := exec.CommandContext(ctx, "git", "receive-pack", "--stateless-rpc", repoPath)
	cmd.Stdin = bytes.NewReader(stdinData)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		_ = sendError(ctx, conn, fmt.Sprintf("git: receive-pack error: %s (err: %v)", stderr.String(), err))
		return err
	}

	resp, err := common.Marshal(&Response{Payload: stdout.Bytes()})
	if err != nil {
		return err
	}
	return conn.Send(ctx, resp)
}

func (s *Server) handleBundle(ctx context.Context, conn Conn, repoPath, ref string) error {
	tmpFile, err := os.CreateTemp("", "pigeonhole-bundle-*.bundle")
	if err != nil {
		_ = sendError(ctx, conn, err.Error())
		return err
	}
	tmpPath := tmpFile.Name()
	_ = tmpFile.Close()
	defer os.Remove(tmpPath)

	args := []string{"-C", repoPath, "bundle", "create", tmpPath}
	if ref != "" {
		args = append(args, ref)
	} else {
		args = append(args, "--all")
	}

	cmd := exec.CommandContext(ctx, "git", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		_ = sendError(ctx, conn, fmt.Sprintf("git: bundle error: %s (err: %v)", stderr.String(), err))
		return err
	}

	bundleData, err := os.ReadFile(tmpPath)
	if err != nil {
		_ = sendError(ctx, conn, err.Error())
		return err
	}

	resp, err := common.Marshal(&Response{Payload: bundleData})
	if err != nil {
		return err
	}
	return conn.Send(ctx, resp)
}

func (s *Server) handleConnect(ctx context.Context, conn Conn, repoPath, service string) error {
	if service != "git-upload-pack" && service != "git-receive-pack" {
		_ = sendError(ctx, conn, "git: invalid service for connect")
		return ErrUnsupportedCmd
	}

	subCmd := strings.TrimPrefix(service, "git-")
	cmd := exec.CommandContext(ctx, "git", subCmd, repoPath)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		_ = sendError(ctx, conn, err.Error())
		return err
	}
	defer stdinPipe.Close()

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		_ = sendError(ctx, conn, err.Error())
		return err
	}

	if err := cmd.Start(); err != nil {
		_ = sendError(ctx, conn, err.Error())
		return err
	}

	// Send initial empty Response to signal connection established
	readyMsg, err := common.Marshal(&Response{})
	if err != nil {
		return err
	}
	if err := conn.Send(ctx, readyMsg); err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)

	// Goroutine: Inbound chunks from client -> process Stdin
	go func() {
		defer wg.Done()
		defer stdinPipe.Close()
		for {
			rawChunk, err := conn.Recv(ctx)
			if err != nil {
				errCh <- err
				return
			}
			var chunk StreamChunk
			if err := common.Unmarshal(rawChunk, &chunk); err != nil {
				errCh <- err
				return
			}
			if chunk.EOF {
				return
			}
			if len(chunk.Data) > 0 {
				if _, err := stdinPipe.Write(chunk.Data); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	// Goroutine: Process Stdout -> outbound chunks to client
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				chunk := StreamChunk{Data: buf[:n]}
				rawChunk, _ := common.Marshal(&chunk)
				if sendErr := conn.Send(ctx, rawChunk); sendErr != nil {
					errCh <- sendErr
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					chunk := StreamChunk{EOF: true}
					rawChunk, _ := common.Marshal(&chunk)
					_ = conn.Send(ctx, rawChunk)
				} else {
					errCh <- err
				}
				return
			}
		}
	}()

	wg.Wait()
	_ = cmd.Wait()

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func sendError(ctx context.Context, conn Conn, msg string) error {
	raw, err := common.Marshal(&Response{Error: msg})
	if err != nil {
		return err
	}
	return conn.Send(ctx, raw)
}
