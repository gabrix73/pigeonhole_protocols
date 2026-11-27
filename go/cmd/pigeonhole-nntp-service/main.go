// SPDX-License-Identifier: AGPL-3.0-only

// pigeonhole-nntp-service runs an NNTP Usenet gateway over Katzenpost
// Pigeonhole mailboxes against an operator-configured unauthenticated NNTPS
// server (e.g. news.tcpreset.net:563 over TLS 1.2+).
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
	"github.com/katzenpost/pigeonhole_protocols/go/services/nntp"
)

func main() {
	var (
		thinConfig        string
		dataDir           string
		logLevel          string
		pollInterval      time.Duration
		nntpAddr          string
		nntpStartTLS      bool
		nntpPlaintext     bool
		nntpTimeout       time.Duration
		maxResponseMB     int64
		maxOverviewCount  uint64
		allowPost         bool
		allowedPostGroups string
		postRateLimit     int
		postRateWindow    time.Duration
	)

	cmd := &cobra.Command{
		Use:   "pigeonhole-nntp-service",
		Short: "Serve a Usenet (NNTP) gateway over Katzenpost Pigeonhole",
		Long: `pigeonhole-nntp-service bridges Katzenpost Pigeonhole clients to a
single operator-configured unauthenticated NNTPS server (for example
news.tcpreset.net:563 over implicit TLS 1.2+), supporting LIST, GROUP, OVER,
ARTICLE, and opt-in rate-limited POST with go/protocols/stream offloading.`,
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
				DisplayName:  "nntp-gateway",
				Advertiser:   adv,
				PollInterval: pollInterval,
				Log:          logBackend.GetLogger("nntp-service"),
			}, ph)
			if err != nil {
				return fmt.Errorf("failed to create service: %w", err)
			}
			defer svc.Close()

			var allowGroups []string
			for _, g := range strings.Split(allowedPostGroups, ",") {
				g = strings.TrimSpace(g)
				if g != "" {
					if err := nntp.ValidateGroupName(g); err != nil {
						return fmt.Errorf("invalid group in --allowed_post_groups (%q): %w", g, err)
					}
					allowGroups = append(allowGroups, g)
				}
			}

			backend := &nntp.NNTPBackend{
				Addr:              nntpAddr,
				Plaintext:         nntpPlaintext,
				StartTLS:          nntpStartTLS,
				Timeout:           nntpTimeout,
				MaxResponseBytes:  maxResponseMB * 1024 * 1024,
				MaxOverviewCount:  maxOverviewCount,
				AllowPost:         allowPost,
				AllowedPostGroups: allowGroups,
				PostLimiter:       nntp.NewPostLimiter(postRateLimit, postRateWindow),
			}

			id := svc.ID()
			fmt.Println("Pigeonhole NNTP Service ID:")
			fmt.Println(hex.EncodeToString(id[:]))

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			err = svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
				_ = nntp.ServeStream(ctx, s, ph, backend, nil)
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
	cmd.Flags().StringVar(&nntpAddr, "nntp_addr", "news.tcpreset.net:563", "upstream unauthenticated NNTPS host:port (implicit TLS 1.2+ by default)")
	cmd.Flags().BoolVar(&nntpStartTLS, "nntp_starttls", false, "upgrade a port-119 upstream connection via mandatory RFC 4642 STARTTLS")
	cmd.Flags().BoolVar(&nntpPlaintext, "nntp_insecure_plaintext", false, "disable TLS and connect in plaintext (for local testing or legacy port-119 servers only)")
	cmd.Flags().DurationVar(&nntpTimeout, "nntp_timeout", nntp.DefaultTimeout, "upstream NNTP request timeout")
	cmd.Flags().Int64Var(&maxResponseMB, "max_response_mb", 4, "maximum upstream NNTP response size in megabytes")
	cmd.Flags().Uint64Var(&maxOverviewCount, "max_overview", nntp.DefaultMaxOverviewCount, "maximum OVER entries per request")
	cmd.Flags().BoolVar(&allowPost, "allow_post", false, "enable opt-in NNTP POST through this gateway (Cleanfeed-NG/Postfilter-NG friendly)")
	cmd.Flags().StringVar(&allowedPostGroups, "allowed_post_groups", "", "comma-separated allowlist of newsgroups permitted for POST (empty allows any validated text group)")
	cmd.Flags().IntVar(&postRateLimit, "post_rate_limit", nntp.DefaultPostRateLimit, "maximum POSTs accepted per rate window")
	cmd.Flags().DurationVar(&postRateWindow, "post_rate_window", nntp.DefaultPostRateWindow, "sliding window duration for POST rate limiting")

	_ = cmd.MarkFlagRequired("thinclient_config")
	_ = cmd.MarkFlagRequired("datadir")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
