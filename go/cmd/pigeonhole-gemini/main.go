// pigeonhole-gemini fetches Gemini capsules over Pigeonhole mixnet mailboxes
// or directly via TLS for offline inspection.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	client "github.com/katzenpost/pigeonhole_protocols/go/clients/gemini"
	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
	"github.com/katzenpost/pigeonhole_protocols/go/services/gemini"
)

func main() {
	var (
		thinConfig   string
		logLevel     string
		pollInterval time.Duration
		directFetch  bool
		outputFile   string
	)

	cmd := &cobra.Command{
		Use:   "pigeonhole-gemini [SERVICE_ID] GEMINI_URL",
		Short: "Fetch Gemini capsules over Pigeonhole mixnet mailboxes",
		Long: `pigeonhole-gemini fetches Gemini capsules (text/gemini) over the Katzenpost
Pigeonhole mixnet, implementing metadata-free offline browsing.

When running through the mixnet:
  pigeonhole-gemini --thinclient_config thinclient.toml <SERVICE_ID> gemini://geminispace.info/

When fetching directly for local testing:
  pigeonhole-gemini --direct gemini://geminispace.info/`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			var targetURL string
			var serviceIDHex string

			if directFetch {
				targetURL = args[0]
				fetcher := &gemini.TLSFetcher{
					Timeout: 15 * time.Second,
				}
				resp, err := fetcher.Fetch(ctx, targetURL)
				if err != nil {
					return err
				}
				return outputResponse(resp, outputFile)
			}

			if len(args) != 2 {
				return errors.New("when not using --direct, specify both SERVICE_ID and GEMINI_URL")
			}
			serviceIDHex = args[0]
			targetURL = args[1]

			rawID, err := hex.DecodeString(serviceIDHex)
			if err != nil || len(rawID) != 32 {
				return errors.New("SERVICE_ID must be 64 hexadecimal characters")
			}

			if thinConfig == "" {
				return errors.New("--thinclient_config is required for mixnet fetch")
			}

			cfg, err := thin.LoadFile(thinConfig)
			if err != nil {
				return fmt.Errorf("failed to load thin client config: %w", err)
			}
			c := thin.NewThinClient(cfg, &config.Logging{Level: logLevel})
			if err := c.Dial(); err != nil {
				return fmt.Errorf("failed to dial thin client: %w", err)
			}
			defer c.Close()

			ph := common.NewThinPigeonhole(c)
			dir, err := discovery.NewAll(ph, nil, pollInterval)
			if err != nil {
				return fmt.Errorf("failed to initialize discovery: %w", err)
			}

			d, err := dir.Lookup(ctx, common.ServiceID(rawID))
			if err != nil {
				return fmt.Errorf("service lookup failed: %w", err)
			}

			conn, err := ps.Dial(ctx, ph, d, "gemini client", pollInterval)
			if err != nil {
				return fmt.Errorf("failed to dial service: %w", err)
			}

			resp, err := client.Fetch(ctx, conn, targetURL)
			if err != nil {
				return fmt.Errorf("fetch failed: %w", err)
			}

			return outputResponse(resp, outputFile)
		},
	}

	cmd.Flags().StringVar(&thinConfig, "thinclient_config", "", "thin client configuration file")
	cmd.Flags().StringVar(&logLevel, "log_level", "ERROR", "log level (DEBUG, INFO, ERROR)")
	cmd.Flags().DurationVar(&pollInterval, "poll_interval", common.DefaultPollInterval, "how often a pending read is retried")
	cmd.Flags().BoolVar(&directFetch, "direct", false, "fetch directly over TLS without mixnet (for diagnostics and local tests)")
	cmd.Flags().StringVarP(&outputFile, "out", "o", "", "file to write the capsule body to (defaults to stdout)")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func outputResponse(resp *gemini.Response, outFile string) error {
	if resp.Error != "" {
		return fmt.Errorf("gemini gateway error: %s", resp.Error)
	}

	fmt.Fprintf(os.Stderr, "Gemini Status: %d (%s)\n", resp.Status, resp.Meta)
	if len(resp.Body) > 0 {
		if outFile != "" {
			if err := os.WriteFile(outFile, resp.Body, 0o644); err != nil {
				return fmt.Errorf("failed to save output to %s: %w", outFile, err)
			}
			fmt.Fprintf(os.Stderr, "Saved %d bytes to %s\n", len(resp.Body), outFile)
		} else {
			_, err := os.Stdout.Write(resp.Body)
			if err != nil {
				return err
			}
			if len(resp.Body) > 0 && resp.Body[len(resp.Body)-1] != '\n' {
				fmt.Println()
			}
		}
	}
	return nil
}
