// pqkeys-daemon serves the post-quantum public key directory service over Pigeonhole,
// and optionally exposes a local bridge listener for standalone development/testing.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"

	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
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

func main() {
	var (
		thinConfig   string
		dataDir      string
		dbPath       string
		listenAddr   string
		logLevel     string
		pollInterval time.Duration
	)

	cmd := &cobra.Command{
		Use:   "pqkeys-daemon",
		Short: "Post-quantum public key directory daemon for Pigeonhole",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			// Initialize store
			var store pqkeys.Store
			if dbPath != "" {
				bStore, err := pqkeys.NewBoltStore(dbPath)
				if err != nil {
					return fmt.Errorf("failed to open database: %w", err)
				}
				defer bStore.Close()
				store = bStore
				fmt.Println("[pqkeys-daemon] Using persistent BoltDB storage at:", dbPath)
			} else {
				store = pqkeys.NewMemoryStore()
				fmt.Println("[pqkeys-daemon] Using ephemeral in-memory storage")
			}

			// Local bridge mode if listenAddr is provided
			if listenAddr != "" {
				l, err := net.Listen("tcp", listenAddr)
				if err != nil {
					return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
				}
				defer l.Close()
				fmt.Printf("[pqkeys-daemon] Local bridge listening on tcp://%s\n", listenAddr)

				go func() {
					for {
						c, err := l.Accept()
						if err != nil {
							return
						}
						go func(conn net.Conn) {
							defer conn.Close()
							fc := &framedConn{conn: conn}
							_ = pqkeys.Serve(ctx, fc, store)
						}(c)
					}
				}()
			}

			// Pigeonhole mixnet mode if thinclient_config is provided
			if thinConfig != "" {
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

				if dataDir == "" {
					dataDir = filepath.Join(os.Getenv("HOME"), ".local/share/katzenpost/pqkeys")
				}
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
					DisplayName:  "pqkeys",
					Advertiser:   adv,
					PollInterval: pollInterval,
					Log:          logBackend.GetLogger("pqkeys"),
				}, ph)
				if err != nil {
					return err
				}
				defer svc.Close()
				id := svc.ID()
				fmt.Printf("[pqkeys-daemon] Pigeonhole Service ID: %s\n", hex.EncodeToString(id[:]))

				err = svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
					_ = pqkeys.Serve(ctx, s, store)
				}))
				if ctx.Err() != nil {
					return nil
				}
				return err
			}

			// If only listenAddr was specified, wait for interrupt
			if listenAddr != "" {
				<-ctx.Done()
				return nil
			}

			return fmt.Errorf("either --thinclient_config or --listen must be specified")
		},
	}

	cmd.Flags().StringVar(&thinConfig, "thinclient_config", "", "thin client configuration file for Pigeonhole mixnet")
	cmd.Flags().StringVar(&dataDir, "datadir", "", "directory for the service's key and state")
	cmd.Flags().StringVar(&dbPath, "db", "", "path to BoltDB database file for persistence (optional)")
	cmd.Flags().StringVar(&listenAddr, "listen", "", "optional TCP address for local bridge testing (e.g. 127.0.0.1:9095)")
	cmd.Flags().StringVar(&logLevel, "log_level", "INFO", "log level")
	cmd.Flags().DurationVar(&pollInterval, "poll_interval", common.DefaultPollInterval, "how often a pending read is retried")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
