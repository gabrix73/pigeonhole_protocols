// git-remote-pigeonhole is a native Git remote helper for the pigeonhole:// protocol.
//
// Usage by Git:
//
//	git clone pigeonhole://<service-id>/<repo-name>
//	git fetch origin
//	git push origin main
//
// When PIGEONHOLE_GIT_DIR is set or the host is "local"/"localhost", the helper
// operates directly against the local repository store for self-contained operation.
package main

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	services "github.com/katzenpost/pigeonhole_protocols/go/services/git"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: git-remote-pigeonhole <remote-name> <url>\n")
		os.Exit(1)
	}

	remoteURL := os.Args[2]
	u, err := url.Parse(remoteURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "git-remote-pigeonhole: invalid URL %q: %v\n", remoteURL, err)
		os.Exit(1)
	}

	if u.Scheme != "pigeonhole" {
		fmt.Fprintf(os.Stderr, "git-remote-pigeonhole: expected scheme 'pigeonhole', got %q\n", u.Scheme)
		os.Exit(1)
	}

	repoName := strings.TrimPrefix(u.Path, "/")
	if repoName == "" {
		fmt.Fprintf(os.Stderr, "git-remote-pigeonhole: missing repository path in URL\n")
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			break
		}

		parts := strings.Fields(line)
		cmd := parts[0]

		switch cmd {
		case "capabilities":
			// We support connect (bidirectional streaming) and stateless-connect
			fmt.Println("connect")
			fmt.Println("") // Blank line terminates capabilities

		case "connect":
			if len(parts) < 2 {
				fmt.Fprintf(os.Stderr, "git-remote-pigeonhole: connect requires service argument\n")
				os.Exit(1)
			}
			service := parts[1]
			if err := handleConnect(u.Host, repoName, service); err != nil {
				fmt.Fprintf(os.Stderr, "git-remote-pigeonhole: connect failed: %v\n", err)
				os.Exit(1)
			}
			return

		default:
			fmt.Fprintf(os.Stderr, "git-remote-pigeonhole: unsupported command %q\n", cmd)
			os.Exit(1)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "git-remote-pigeonhole: stdin scan error: %v\n", err)
		os.Exit(1)
	}
}

// pipeConn bridges an in-memory services.Server to the standard connect protocol.
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

func handleConnect(host, repo, service string) error {
	ctx := context.Background()

	// Check if local store directory is configured
	localDir := os.Getenv("PIGEONHOLE_GIT_DIR")
	if localDir == "" && (host == "local" || host == "localhost" || host == "") {
		// Default to current directory or standard local cache
		localDir = "."
	}

	if localDir != "" {
		absDir, err := filepath.Abs(localDir)
		if err != nil {
			return err
		}

		server, err := services.NewServer(absDir)
		if err != nil {
			return fmt.Errorf("local server init failed: %w", err)
		}

		srvConn, cliConn := newPipePair()

		// Run server in goroutine
		serverErrCh := make(chan error, 1)
		go func() {
			serverErrCh <- server.Handle(ctx, srvConn)
		}()

		// Signal Git that connection is established (empty line terminating positive response)
		fmt.Println("")

		// Send ActionConnect request
		initReq := &services.Request{
			Action:  services.ActionConnect,
			Repo:    repo,
			Service: service,
		}
		rawReq, err := commonMarshal(initReq)
		if err != nil {
			return err
		}
		if err := cliConn.Send(ctx, rawReq); err != nil {
			return err
		}

		// Read ready response
		rawReady, err := cliConn.Recv(ctx)
		if err != nil {
			return err
		}
		var readyResp services.Response
		if err := commonUnmarshal(rawReady, &readyResp); err != nil {
			return err
		}
		if readyResp.Error != "" {
			return fmt.Errorf("server error: %s", readyResp.Error)
		}

		// Stream os.Stdin -> cliConn
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := os.Stdin.Read(buf)
				if n > 0 {
					chunk := services.StreamChunk{Data: buf[:n]}
					rawChunk, _ := commonMarshal(&chunk)
					_ = cliConn.Send(ctx, rawChunk)
				}
				if err != nil {
					chunk := services.StreamChunk{EOF: true}
					rawChunk, _ := commonMarshal(&chunk)
					_ = cliConn.Send(ctx, rawChunk)
					return
				}
			}
		}()

		// Stream cliConn -> os.Stdout
		for {
			rawChunk, err := cliConn.Recv(ctx)
			if err != nil {
				break
			}
			var chunk services.StreamChunk
			if err := commonUnmarshal(rawChunk, &chunk); err != nil {
				break
			}
			if chunk.EOF {
				break
			}
			if len(chunk.Data) > 0 {
				_, _ = os.Stdout.Write(chunk.Data)
			}
		}

		_ = <-serverErrCh
		return nil
	}

	return fmt.Errorf("remote connection to host %q not configured without PIGEONHOLE_GIT_DIR", host)
}

func commonMarshal(v interface{}) ([]byte, error) {
	return common.Marshal(v)
}

func commonUnmarshal(data []byte, v interface{}) error {
	return common.Unmarshal(data, v)
}
