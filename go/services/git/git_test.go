package git

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

// mockConn connects two in-memory channels mimicking a duplex Pigeonhole session.
type mockConn struct {
	in  chan []byte
	out chan []byte
}

func newMockPair() (*mockConn, *mockConn) {
	c1 := make(chan []byte, 100)
	c2 := make(chan []byte, 100)
	return &mockConn{in: c1, out: c2}, &mockConn{in: c2, out: c1}
}

func (m *mockConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg, ok := <-m.in:
		if !ok {
			return nil, os.ErrClosed
		}
		return msg, nil
	}
}

func (m *mockConn) Send(ctx context.Context, msg []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.out <- msg:
		return nil
	}
}

// initTestRepo creates a valid temporary Git repository with an initial commit.
func initTestRepo(t *testing.T, dir, name string) string {
	t.Helper()
	repoPath := filepath.Join(dir, name)
	if err := os.MkdirAll(repoPath, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	runGit(t, repoPath, "init")
	runGit(t, repoPath, "config", "user.name", "Test Author")
	runGit(t, repoPath, "config", "user.email", "author@example.com")
	runGit(t, repoPath, "config", "commit.gpgsign", "false")

	testFile := filepath.Join(repoPath, "hello.txt")
	if err := os.WriteFile(testFile, []byte("Hello Pigeonhole Git!\n"), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	runGit(t, repoPath, "add", "hello.txt")
	runGit(t, repoPath, "commit", "-m", "Initial commit")
	return repoPath
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v failed: %v: %s", args, err, stderr.String())
	}
	return out.String()
}

func TestServerPathSecurity(t *testing.T) {
	tmpDir := t.TempDir()
	initTestRepo(t, tmpDir, "valid-repo")

	server, err := NewServer(tmpDir)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Valid access
	path, err := server.ResolveRepo("valid-repo")
	if err != nil {
		t.Errorf("expected valid-repo to resolve, got: %v", err)
	}
	if !strings.HasPrefix(path, tmpDir) {
		t.Errorf("path %s escaped tmpDir %s", path, tmpDir)
	}

	// Path traversal attempts
	traversalCases := []string{
		"../etc/passwd",
		"../../secret",
		"/etc/passwd",
		"valid-repo/../../etc",
		"",
		".",
		"non-existent",
	}

	for _, tc := range traversalCases {
		_, err := server.ResolveRepo(tc)
		if err == nil {
			t.Errorf("expected error for %q, got nil", tc)
		}
	}
}

func TestInfoRefsAndBundle(t *testing.T) {
	tmpDir := t.TempDir()
	initTestRepo(t, tmpDir, "demo.git")

	server, err := NewServer(tmpDir)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Test InfoRefs
	srvConn, clientConn := newMockPair()
	reqBytes, err := common.Marshal(&Request{
		Action:  ActionInfoRefs,
		Repo:    "demo.git",
		Service: "git-upload-pack",
	})
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Handle(ctx, srvConn); err != nil {
			t.Errorf("Handle failed: %v", err)
		}
	}()

	if err := clientConn.Send(ctx, reqBytes); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	rawResp, err := clientConn.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv failed: %v", err)
	}

	var resp Response
	if err := common.Unmarshal(rawResp, &resp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if resp.Error != "" {
		t.Fatalf("unexpected error response: %s", resp.Error)
	}
	if !bytes.Contains(resp.Payload, []byte("# service=git-upload-pack")) {
		t.Errorf("expected pkt-line service header, got:\n%s", string(resp.Payload))
	}
	if !bytes.Contains(resp.Payload, []byte("refs/heads/")) {
		t.Errorf("expected refs advertisement, got:\n%s", string(resp.Payload))
	}
	wg.Wait()

	// 2. Test Bundle creation
	srvConn2, clientConn2 := newMockPair()
	bundleReqBytes, _ := common.Marshal(&Request{
		Action: ActionBundle,
		Repo:   "demo.git",
	})

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Handle(ctx, srvConn2); err != nil {
			t.Errorf("Handle failed: %v", err)
		}
	}()

	_ = clientConn2.Send(ctx, bundleReqBytes)
	rawBundleResp, err := clientConn2.Recv(ctx)
	if err != nil {
		t.Fatalf("Recv failed: %v", err)
	}

	var bundleResp Response
	_ = common.Unmarshal(rawBundleResp, &bundleResp)
	if bundleResp.Error != "" {
		t.Fatalf("bundle error: %s", bundleResp.Error)
	}
	if !bytes.HasPrefix(bundleResp.Payload, []byte("# v2 git bundle")) && !bytes.HasPrefix(bundleResp.Payload, []byte("# v3 git bundle")) {
		t.Errorf("expected git bundle magic header, got: %q", string(bundleResp.Payload[:20]))
	}
	wg.Wait()
}
