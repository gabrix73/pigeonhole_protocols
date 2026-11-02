// pigeonhole-gemini-service runs a Gemini gateway service over Pigeonhole.
// Clients send gemini:// URLs to the service's mailbox; the daemon fetches the
// capsule over TLS and returns the Gemtext/MIME response back through Pigeonhole.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
	"github.com/katzenpost/pigeonhole_protocols/go/services/gemini"
)

func main() {
	var (
		thinConfig   string
		dataDir      string
		logLevel     string
		pollInterval time.Duration
		fetchTimeout time.Duration
		maxBodyMB    int64
	)

	cmd := &cobra.Command{
		Use:   "pigeonhole-gemini-service",
		Short: "Serve a Gemini gateway over Katzenpost Pigeonhole",
		Long: `pigeonhole-gemini-service listens for incoming Gemini fetch requests on its
Pigeonhole service mailbox, retrieves capsules over outbound TLS, and returns
the response back to the requesting client via mixnet mailboxes.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			logBackend, err := log.New("", logLevel, false)
			if err != nil {
				return err
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

			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				return fmt.Errorf("failed to create data directory: %w", err)
			}
			key, err := common.LoadServiceKey(dataDir)
			if err != nil {
				return fmt.Errorf("failed to load service key: %w", err)
			}
			adv, err := discovery.NewAll(ph, key, pollInterval)
			if err != nil {
				return fmt.Errorf("failed to create discovery advertiser: %w", err)
			}

			svc, err := ps.NewService(ps.Config{
				Key:          key,
				DataDir:      dataDir,
				DisplayName:  "gemini-gateway",
				Advertiser:   adv,
				PollInterval: pollInterval,
				Log:          logBackend.GetLogger("gemini-service"),
			}, ph)
			if err != nil {
				return fmt.Errorf("failed to create service: %w", err)
			}
			defer svc.Close()

			id := svc.ID()
			fmt.Println("Pigeonhole Gemini Service ID:")
			fmt.Println(hex.EncodeToString(id[:]))

			fetcher := &gemini.TLSFetcher{
				Timeout:      fetchTimeout,
				MaxBodyBytes: maxBodyMB * 1024 * 1024,
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			err = svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
				_ = gemini.Serve(ctx, s, fetcher)
			}))
			if ctx.Err() != nil {
				return nil
			}
			return err
		},
	}

	cmd.Flags().StringVar(&thinConfig, "thinclient_config", "", "thin client configuration file")
	cmd.Flags().StringVar(&dataDir, "datadir", "", "directory for the service's key and persistent state")
	cmd.Flags().StringVar(&logLevel, "log_level", "INFO", "log level (DEBUG, INFO, ERROR)")
	cmd.Flags().DurationVar(&pollInterval, "poll_interval", common.DefaultPollInterval, "how often a pending read is retried")
	cmd.Flags().DurationVar(&fetchTimeout, "fetch_timeout", 15*time.Second, "outbound Gemini TLS connection timeout")
	cmd.Flags().Int64Var(&maxBodyMB, "max_body_mb", 5, "maximum allowed capsule body size in megabytes")

	_ = cmd.MarkFlagRequired("thinclient_config")
	_ = cmd.MarkFlagRequired("datadir")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
