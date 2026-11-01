// motd fetches the message of the day from a motd-service.
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
	"github.com/katzenpost/pigeonhole_protocols/clients/motd"
	ps "github.com/katzenpost/pigeonhole_protocols/pigeonservice"
)

func main() {
	var (
		thinConfig   string
		logLevel     string
		pollInterval time.Duration
	)
	cmd := &cobra.Command{
		Use:   "motd SERVICE_ID",
		Short: "Fetch the message of the day from a motd-service",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := hex.DecodeString(args[0])
			if err != nil || len(raw) != 32 {
				return errors.New("a service ID is 64 hex digits")
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
			dir, err := discovery.NewAll(ph, nil, pollInterval)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			d, err := dir.Lookup(ctx, common.ServiceID(raw))
			if err != nil {
				return err
			}
			conn, err := ps.Dial(ctx, ph, d, "motd client", pollInterval)
			if err != nil {
				return err
			}
			reply, err := motd.Fetch(ctx, conn)
			if err != nil {
				return err
			}
			fmt.Printf("%s: %s\n", reply.Day, reply.Message)
			return nil
		},
	}
	cmd.Flags().StringVar(&thinConfig, "thinclient_config", "", "thin client configuration file")
	cmd.Flags().StringVar(&logLevel, "log_level", "ERROR", "log level")
	cmd.Flags().DurationVar(&pollInterval, "poll_interval", common.DefaultPollInterval, "how often a pending read is retried")
	_ = cmd.MarkFlagRequired("thinclient_config")
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
