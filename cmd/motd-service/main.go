// motd-service serves the message of the day over Pigeonhole. It rereads
// the message file for every request, so editing the file changes the
// message.
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
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	ps "github.com/katzenpost/pigeonhole_protocols/pigeonservice"
	"github.com/katzenpost/pigeonhole_protocols/services/motd"
)

func main() {
	var (
		thinConfig   string
		dataDir      string
		messageFile  string
		logLevel     string
		pollInterval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "motd-service",
		Short: "Serve the message of the day over Pigeonhole",
		RunE: func(cmd *cobra.Command, args []string) error {
			logBackend, err := log.New("", logLevel, false)
			if err != nil {
				return err
			}
			cfg, err := thin.LoadFile(thinConfig)
			if err != nil {
				return err
			}
			c := thin.NewThinClient(cfg, &config.Logging{Level: logLevel})
			if err := c.Dial(); err != nil {
				return err
			}
			defer c.Close()
			ph := common.NewThinPigeonhole(c)

			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				return err
			}
			key, err := common.LoadServiceKey(dataDir)
			if err != nil {
				return err
			}
			adv, err := discovery.NewAll(ph, key, pollInterval)
			if err != nil {
				return err
			}
			svc, err := ps.NewService(ps.Config{
				Key:          key,
				DataDir:      dataDir,
				DisplayName:  "motd",
				Advertiser:   adv,
				PollInterval: pollInterval,
				Log:          logBackend.GetLogger("motd"),
			}, ph)
			if err != nil {
				return err
			}
			defer svc.Close()
			id := svc.ID()
			fmt.Println(hex.EncodeToString(id[:]))

			source := func() (string, error) {
				b, err := os.ReadFile(messageFile)
				return strings.TrimSpace(string(b)), err
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			err = svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
				_ = motd.Serve(ctx, s, source, motd.SystemClock{})
			}))
			if ctx.Err() != nil {
				return nil
			}
			return err
		},
	}
	cmd.Flags().StringVar(&thinConfig, "thinclient_config", "", "thin client configuration file")
	cmd.Flags().StringVar(&dataDir, "datadir", "", "directory for the service's key and state")
	cmd.Flags().StringVar(&messageFile, "message", "", "file holding the message of the day")
	cmd.Flags().StringVar(&logLevel, "log_level", "INFO", "log level")
	cmd.Flags().DurationVar(&pollInterval, "poll_interval", common.DefaultPollInterval, "how often a pending read is retried")
	for _, f := range []string{"thinclient_config", "datadir", "message"} {
		_ = cmd.MarkFlagRequired(f)
	}
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
