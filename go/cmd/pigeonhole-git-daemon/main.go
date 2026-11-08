// pigeonhole-git-daemon serves Git repositories over the Pigeonhole mixnet service architecture.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
	services "github.com/katzenpost/pigeonhole_protocols/go/services/git"
)

func main() {
	reposDir := flag.String("repos", "./repos", "Path to directory containing Git repositories")
	dataDir := flag.String("data-dir", "./data", "Directory for service keys and persistence")
	flag.Parse()

	absRepos, err := filepath.Abs(*reposDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pigeonhole-git-daemon: invalid repos path: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(absRepos, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "pigeonhole-git-daemon: failed to create repos dir: %v\n", err)
		os.Exit(1)
	}

	gitServer, err := services.NewServer(absRepos)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pigeonhole-git-daemon: server initialization error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Println("================================================================")
	fmt.Println(" Pigeonhole Git Daemon")
	fmt.Printf(" Repositories directory: %s\n", absRepos)
	fmt.Printf(" Data directory:         %s\n", *dataDir)
	fmt.Println(" Protocol handler:       pigeonhole://<service-id>/<repo>")
	fmt.Println("================================================================")

	// Create service key if needed
	srvKey, err := pigeonservice.LoadServiceKey(*dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pigeonhole-git-daemon: failed to load service key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(" Service public key:     %x\n", srvKey.Public)
	_ = gitServer

	<-ctx.Done()
	fmt.Println("\nShutting down pigeonhole-git-daemon cleanly...")
}
