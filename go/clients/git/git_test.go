package git

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	services "github.com/katzenpost/pigeonhole_protocols/go/services/git"
)

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

func initTestRepo(t *testing.T, dir, name string) string {
	t.Helper()
	repoPath := filepath.Join(dir, name)
	if err := os.MkdirAll(repoPath, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	runGit(t, repoPath, "init")
	runGit(t, repoPath, "config", "user.name", "Pigeonhole Tester")
	runGit(t, repoPath, "config", "user.email", "tester@example.com")
	runGit(t, repoPath, "config", "commit.gpgsign", "false")

	testFile := filepath.Join(repoPath, "README.md")
	if err := os.WriteFile(testFile, []byte("# Test Repo\n"), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	runGit(t, repoPath, "add", "README.md")
	runGit(t, repoPath, "commit", "-m", "First commit")
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

func TestClientEndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	initTestRepo(t, tmpDir, "myrepo.git")

	server, err := services.NewServer(tmpDir)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 1. Test GetInfoRefs
	srvConn, clientConn := newMockPair()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Handle(ctx, srvConn); err != nil {
			t.Errorf("server.Handle failed: %v", err)
		}
	}()

	refsData, err := GetInfoRefs(ctx, clientConn, "myrepo.git", "git-upload-pack")
	if err != nil {
		t.Fatalf("GetInfoRefs failed: %v", err)
	}
	if !bytes.Contains(refsData, []byte("refs/heads/")) {
		t.Errorf("expected refs advertisement, got:\n%s", string(refsData))
	}
	wg.Wait()

	// 2. Test GetBundle
	srvConn2, clientConn2 := newMockPair()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := server.Handle(ctx, srvConn2); err != nil {
			t.Errorf("server.Handle failed: %v", err)
		}
	}()

	bundleBytes, err := GetBundle(ctx, clientConn2, "myrepo.git", "")
	if err != nil {
		t.Fatalf("GetBundle failed: %v", err)
	}
	if !bytes.HasPrefix(bundleBytes, []byte("# v2 git bundle")) && !bytes.HasPrefix(bundleBytes, []byte("# v3 git bundle")) {
		t.Errorf("expected git bundle header, got %q", string(bundleBytes[:20]))
	}
	wg.Wait()
}
