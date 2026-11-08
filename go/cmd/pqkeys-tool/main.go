// pqkeys-tool is a command-line client for publishing, querying, and revoking
// post-quantum public keys via the PQKeys Pigeonhole service or local bridge.
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	client "github.com/katzenpost/pigeonhole_protocols/go/clients/pqkeys"
	"github.com/katzenpost/pigeonhole_protocols/go/services/pqkeys"
)

type framedConn struct {
	conn net.Conn
}

func (f *framedConn) Recv(ctx context.Context) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(f.conn, lenBuf); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf)
	payload := make([]byte, n)
	if _, err := io.ReadFull(f.conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func (f *framedConn) Send(ctx context.Context, msg []byte) error {
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(msg)))
	if _, err := f.conn.Write(lenBuf); err != nil {
		return err
	}
	_, err := f.conn.Write(msg)
	return err
}

func dialServer(addr string) (*client.Client, io.Closer, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to pqkeys daemon at %s: %w", addr, err)
	}
	fc := &framedConn{conn: conn}
	return client.NewClient(fc), conn, nil
}

func main() {
	var serverAddr string

	rootCmd := &cobra.Command{
		Use:   "pqkeys-tool",
		Short: "Client CLI for the PQKeys Post-Quantum Public Key Directory",
	}
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "127.0.0.1:9095", "address of pqkeys daemon bridge")

	// Publish command
	var pubKeyFile, privKeyFile, userID string
	publishCmd := &cobra.Command{
		Use:   "publish",
		Short: "Publish a post-quantum public key with self-signature",
		RunE: func(cmd *cobra.Command, args []string) error {
			pubBytes, err := os.ReadFile(pubKeyFile)
			if err != nil {
				return fmt.Errorf("reading public key: %w", err)
			}
			privBytes, err := os.ReadFile(privKeyFile)
			if err != nil {
				return fmt.Errorf("reading private key: %w", err)
			}

			edPriv, err := pqkeys.ExtractEd25519PrivateKey(string(privBytes))
			if err != nil {
				return fmt.Errorf("extracting ed25519 signing key: %w", err)
			}

			c, closer, err := dialServer(serverAddr)
			if err != nil {
				return err
			}
			defer closer.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			rec, err := c.Publish(ctx, userID, strings.TrimSpace(string(pubBytes)), edPriv)
			if err != nil {
				return fmt.Errorf("publish failed: %w", err)
			}

			fmt.Println("✓ Post-quantum public key successfully published!")
			fmt.Printf("  Fingerprint: %s\n", rec.Fingerprint)
			fmt.Printf("  User ID:     %s\n", rec.UserID)
			fmt.Printf("  Timestamp:   %s\n", time.Unix(rec.Timestamp, 0).UTC().Format(time.RFC3339))
			return nil
		},
	}
	publishCmd.Flags().StringVar(&pubKeyFile, "pub", "", "path to .pub public key file")
	publishCmd.Flags().StringVar(&privKeyFile, "key", "", "path to .key private key file")
	publishCmd.Flags().StringVar(&userID, "user", "", "user ID or alias (e.g. alice@katzenpost.mix)")
	_ = publishCmd.MarkFlagRequired("pub")
	_ = publishCmd.MarkFlagRequired("key")
	rootCmd.AddCommand(publishCmd)

	// Lookup command
	var savePath string
	lookupCmd := &cobra.Command{
		Use:   "lookup <fingerprint_or_userid>",
		Short: "Query a post-quantum public key and verify self-signature",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := args[0]
			c, closer, err := dialServer(serverAddr)
			if err != nil {
				return err
			}
			defer closer.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			rec, err := c.Lookup(ctx, query)
			if err != nil {
				return fmt.Errorf("lookup failed: %w", err)
			}

			fmt.Println("✓ Key found and self-signature verified:")
			fmt.Printf("  Fingerprint: %s\n", rec.Fingerprint)
			fmt.Printf("  User ID:     %s\n", rec.UserID)
			fmt.Printf("  Timestamp:   %s\n", time.Unix(rec.Timestamp, 0).UTC().Format(time.RFC3339))
			fmt.Printf("  Revoked:     %v\n", rec.Revoked)
			if rec.Revoked {
				fmt.Printf("  Reason:      %s\n", rec.RevocationReason)
			}

			if savePath != "" {
				if err := os.WriteFile(savePath, []byte(rec.ArmoredPublicKey+"\n"), 0o644); err != nil {
					return fmt.Errorf("saving public key: %w", err)
				}
				fmt.Printf("  Saved to:    %s\n", savePath)
			} else {
				fmt.Println("\n" + rec.ArmoredPublicKey)
			}
			return nil
		},
	}
	lookupCmd.Flags().StringVarP(&savePath, "output", "o", "", "optional destination file path to save the public key")
	rootCmd.AddCommand(lookupCmd)

	// Revoke command
	var revokeReason string
	revokeCmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a registered post-quantum public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			pubBytes, err := os.ReadFile(pubKeyFile)
			if err != nil {
				return fmt.Errorf("reading public key: %w", err)
			}
			privBytes, err := os.ReadFile(privKeyFile)
			if err != nil {
				return fmt.Errorf("reading private key: %w", err)
			}

			edPriv, err := pqkeys.ExtractEd25519PrivateKey(string(privBytes))
			if err != nil {
				return fmt.Errorf("extracting ed25519 signing key: %w", err)
			}

			fp := pqkeys.ComputeFingerprint(strings.TrimSpace(string(pubBytes)))

			c, closer, err := dialServer(serverAddr)
			if err != nil {
				return err
			}
			defer closer.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			rec, err := c.Revoke(ctx, fp, revokeReason, edPriv)
			if err != nil {
				return fmt.Errorf("revocation failed: %w", err)
			}

			fmt.Println("✓ Key successfully REVOKED:")
			fmt.Printf("  Fingerprint: %s\n", rec.Fingerprint)
			fmt.Printf("  Reason:      %s\n", rec.RevocationReason)
			return nil
		},
	}
	revokeCmd.Flags().StringVar(&pubKeyFile, "pub", "", "path to .pub public key file")
	revokeCmd.Flags().StringVar(&privKeyFile, "key", "", "path to .key private key file")
	revokeCmd.Flags().StringVar(&revokeReason, "reason", "Key retired or rotated", "revocation reason")
	_ = revokeCmd.MarkFlagRequired("pub")
	_ = revokeCmd.MarkFlagRequired("key")
	rootCmd.AddCommand(revokeCmd)

	// List command
	var limit, offset int
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List registered public key summaries",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, closer, err := dialServer(serverAddr)
			if err != nil {
				return err
			}
			defer closer.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			keys, err := c.List(ctx, limit, offset)
			if err != nil {
				return fmt.Errorf("list failed: %w", err)
			}

			if len(keys) == 0 {
				fmt.Println("No keys found in directory.")
				return nil
			}

			fmt.Printf("%-24s %-28s %-12s %s\n", "FINGERPRINT", "USER ID", "STATUS", "DATE")
			fmt.Println(strings.Repeat("-", 80))
			for _, k := range keys {
				status := "ACTIVE"
				if k.Revoked {
					status = "REVOKED"
				}
				fpShort := k.Fingerprint
				if len(fpShort) > 20 {
					fpShort = fpShort[:20] + "..."
				}
				d := time.Unix(k.Timestamp, 0).UTC().Format("2006-01-02 15:04")
				fmt.Printf("%-24s %-28s %-12s %s\n", fpShort, k.UserID, status, d)
			}
			return nil
		},
	}
	listCmd.Flags().IntVar(&limit, "limit", 50, "max keys to list")
	listCmd.Flags().IntVar(&offset, "offset", 0, "offset index")
	rootCmd.AddCommand(listCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
