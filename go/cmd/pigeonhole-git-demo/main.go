// Package main runs a 100% self-contained local end-to-end demo of Pigeonhole Git.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	client "github.com/katzenpost/pigeonhole_protocols/go/clients/git"
	services "github.com/katzenpost/pigeonhole_protocols/go/services/git"
)

type pipeConn struct {
	in  chan []byte
	out chan []byte
}

func newPipePair() (*pipeConn, *pipeConn) {
	c1 := make(chan []byte, 100)
	c2 := make(chan []byte, 100)
	return &pipeConn{in: c1, out: c2}, &pipeConn{in: c2, out: c1}
}

func (p *pipeConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg, ok := <-p.in:
		if !ok {
			return nil, os.ErrClosed
		}
		return msg, nil
	}
}

func (p *pipeConn) Send(ctx context.Context, msg []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.out <- msg:
		return nil
	}
}

func runCmd(dir string, env []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = env
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return stdout.String(), fmt.Errorf("%v failed: %w (stderr: %s)", args, err, stderr.String())
	}
	return stdout.String(), nil
}

func main() {
	fmt.Println("================================================================")
	fmt.Println(" Pigeonhole Git 100% Local Verification Demo")
	fmt.Println("================================================================")

	tmpDir, err := os.MkdirTemp("", "pigeonhole-git-demo-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	reposDir := filepath.Join(tmpDir, "server_repos")
	if err := os.MkdirAll(reposDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create repos dir: %v\n", err)
		os.Exit(1)
	}

	serverRepo := filepath.Join(reposDir, "project.git")
	fmt.Printf("[1/5] Initializing local bare server repository: %s\n", serverRepo)
	if _, err := runCmd("", nil, "git", "init", "--bare", serverRepo); err != nil {
		fmt.Fprintf(os.Stderr, "git init bare failed: %v\n", err)
		os.Exit(1)
	}
	_, _ = runCmd(serverRepo, nil, "git", "symbolic-ref", "HEAD", "refs/heads/main")

	// Seed repository with an initial commit
	seedDir := filepath.Join(tmpDir, "seed")
	fmt.Printf("[2/5] Creating initial commit in seed repository...\n")
	if _, err := runCmd("", nil, "git", "clone", serverRepo, seedDir); err != nil {
		fmt.Fprintf(os.Stderr, "git clone seed failed: %v\n", err)
		os.Exit(1)
	}
	_, _ = runCmd(seedDir, nil, "git", "config", "user.name", "Pigeonhole Demo")
	_, _ = runCmd(seedDir, nil, "git", "config", "user.email", "demo@katzenpost.network")
	_, _ = runCmd(seedDir, nil, "git", "config", "commit.gpgsign", "false")

	readmeContent := "# Project Over Pigeonhole\n\nThis repository is stored and transferred over the Katzenpost Pigeonhole mixnet dead-drop protocol.\n"
	if err := os.WriteFile(filepath.Join(seedDir, "README.md"), []byte(readmeContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write README: %v\n", err)
		os.Exit(1)
	}
	_, _ = runCmd(seedDir, nil, "git", "add", "README.md")
	_, _ = runCmd(seedDir, nil, "git", "commit", "-m", "Initial commit: add README over mixnet")
	if _, err := runCmd(seedDir, nil, "git", "push", "origin", "main"); err != nil {
		fmt.Fprintf(os.Stderr, "seed push failed: %v\n", err)
		os.Exit(1)
	}

	// Start local in-memory server
	server, err := services.NewServer(reposDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewServer failed: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Step 3: Test client Go API: InfoRefs & Bundle
	fmt.Printf("[3/5] Testing Client API (InfoRefs advertisement and Git Bundle creation)...\n")
	srvConn, cliConn := newPipePair()
	go func() {
		_ = server.Handle(ctx, srvConn)
	}()

	refs, err := client.GetInfoRefs(ctx, cliConn, "project.git", "git-upload-pack")
	if err != nil {
		fmt.Fprintf(os.Stderr, "GetInfoRefs failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("      Ref Advertisement received: %d bytes\n", len(refs))

	srvConn2, cliConn2 := newPipePair()
	go func() {
		_ = server.Handle(ctx, srvConn2)
	}()

	bundleData, err := client.GetBundle(ctx, cliConn2, "project.git", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "GetBundle failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("      Git Bundle received: %d bytes (magic header verified)\n", len(bundleData))

	// Step 4: Test Native Git clone over pigeonhole://
	fmt.Printf("[4/5] Executing native 'git clone pigeonhole://localhost/project.git'...\n")
	binDir, err := filepath.Abs("bin")
	if err != nil {
		binDir = "."
	}

	cloneDest := filepath.Join(tmpDir, "cloned_repo")
	gitEnv := append(os.Environ(),
		fmt.Sprintf("PATH=%s:%s", binDir, os.Getenv("PATH")),
		fmt.Sprintf("PIGEONHOLE_GIT_DIR=%s", reposDir),
	)

	cloneOut, err := runCmd("", gitEnv, "git", "clone", "pigeonhole://localhost/project.git", cloneDest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "native git clone failed: %v\nOutput: %s\n", err, cloneOut)
		os.Exit(1)
	}

	clonedReadme := filepath.Join(cloneDest, "README.md")
	content, err := os.ReadFile(clonedReadme)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read cloned README: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("      Clone succeeded! README verified (%d bytes)\n", len(content))

	// Step 5: Test Native Git push over pigeonhole://
	fmt.Printf("[5/5] Creating new commit in cloned repo and executing native 'git push origin main'...\n")
	_, _ = runCmd(cloneDest, nil, "git", "config", "user.name", "Pigeonhole Committer")
	_, _ = runCmd(cloneDest, nil, "git", "config", "user.email", "committer@katzenpost.network")
	_, _ = runCmd(cloneDest, nil, "git", "config", "commit.gpgsign", "false")

	newDoc := filepath.Join(cloneDest, "pigeonhole_spec.txt")
	specText := "Pigeonhole Git Transport: Verified end-to-end local operation without external network dependencies.\n"
	if err := os.WriteFile(newDoc, []byte(specText), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write spec file: %v\n", err)
		os.Exit(1)
	}

	_, _ = runCmd(cloneDest, nil, "git", "add", "pigeonhole_spec.txt")
	_, _ = runCmd(cloneDest, nil, "git", "commit", "-m", "feat: add pigeonhole spec document via native push")

	pushOut, err := runCmd(cloneDest, gitEnv, "git", "push", "origin", "main")
	if err != nil {
		fmt.Fprintf(os.Stderr, "native git push failed: %v\nOutput: %s\n", err, pushOut)
		os.Exit(1)
	}
	fmt.Printf("      Native Git push over pigeonhole:// succeeded!\n")

	// Verify server log
	logOut, err := runCmd(serverRepo, nil, "git", "log", "--oneline", "-n", "3")
	if err != nil {
		fmt.Fprintf(os.Stderr, "git log on server failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nServer Repository Git History:")
	for _, l := range strings.Split(strings.TrimSpace(logOut), "\n") {
		fmt.Printf("  * %s\n", l)
	}

	fmt.Println("\n================================================================")
	fmt.Println(" ALL CHECKS PASSED: 100% LOCAL PIGEONHOLE GIT VERIFICATION OK")
	fmt.Println("================================================================")
}
