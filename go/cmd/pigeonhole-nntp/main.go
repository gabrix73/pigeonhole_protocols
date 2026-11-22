// SPDX-License-Identifier: AGPL-3.0-only

// pigeonhole-nntp is the Katzenpost Usenet client: CLI, local loopback NNTP
// bridge (127.0.0.1:1119), 0%-JS Gemini-style local Web UI, local killfile, and
// optional HPQC ASCII-armored encryption.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	nntpcli "github.com/katzenpost/pigeonhole_protocols/go/clients/nntp"
	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
	"github.com/katzenpost/pigeonhole_protocols/go/services/nntp"
)

type globalOpts struct {
	thinConfig    string
	serviceID     string
	logLevel      string
	pollInterval  time.Duration
	direct        bool
	nntpAddr      string
	nntpStartTLS  bool
	nntpPlaintext bool
	keyDir        string
	killfilePath  string
}

func defaultStatePath(elem ...string) string {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return filepath.Join(elem...)
	}
	parts := append([]string{cfgDir, "pigeonhole-nntp"}, elem...)
	return filepath.Join(parts...)
}

func openClient(ctx context.Context, opts *globalOpts, allowDirectPost bool) (*nntpcli.Client, func(), error) {
	if opts.direct {
		if strings.TrimSpace(opts.nntpAddr) == "" {
			return nil, nil, errors.New("--nntp_addr is required with --direct")
		}
		be := &nntp.NNTPBackend{
			Addr:      opts.nntpAddr,
			Plaintext: opts.nntpPlaintext,
			StartTLS:  opts.nntpStartTLS,
			AllowPost: allowDirectPost,
		}
		return nntpcli.NewClient(&nntpcli.DirectTransport{Backend: be}), func() {}, nil
	}

	if opts.thinConfig == "" || opts.serviceID == "" {
		return nil, nil, errors.New("--thinclient_config and --service_id are required (or pass --direct)")
	}
	rawID, err := hex.DecodeString(opts.serviceID)
	if err != nil || len(rawID) != 32 {
		return nil, nil, errors.New("--service_id must be 64 hexadecimal characters")
	}
	cfg, err := thin.LoadFile(opts.thinConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load thin client config: %w", err)
	}
	c := thin.NewThinClient(cfg, &config.Logging{Level: opts.logLevel})
	if err := c.Dial(); err != nil {
		return nil, nil, fmt.Errorf("failed to dial thin client: %w", err)
	}
	ph := common.NewThinPigeonhole(c)
	dir, err := discovery.NewAll(ph, nil, opts.pollInterval)
	if err != nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("failed to initialize discovery: %w", err)
	}
	d, err := dir.Lookup(ctx, common.ServiceID(rawID))
	if err != nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("service lookup failed: %w", err)
	}
	conn, err := ps.Dial(ctx, ph, d, "nntp client", opts.pollInterval)
	if err != nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("failed to dial NNTP service: %w", err)
	}
	tr := &nntpcli.PigeonholeTransport{Conn: conn, PH: ph}
	return nntpcli.NewClient(tr), func() { _ = c.Close() }, nil
}

func loadOptionalKeypair(keyDir string) *nntpcli.Keypair {
	if strings.TrimSpace(keyDir) == "" {
		return nil
	}
	kp, err := nntpcli.LoadKeypair(keyDir)
	if err != nil {
		return nil
	}
	return kp
}

func main() {
	opts := &globalOpts{
		pollInterval: common.DefaultPollInterval,
		logLevel:     "ERROR",
		nntpAddr:     "news.tcpreset.net:563",
		keyDir:       defaultStatePath("keys"),
		killfilePath: defaultStatePath("killfile.json"),
	}

	root := &cobra.Command{
		Use:   "pigeonhole-nntp",
		Short: "Usenet (NNTP) client, local bridge, and 0%-JS Web UI over Katzenpost Pigeonhole",
	}
	root.PersistentFlags().StringVar(&opts.thinConfig, "thinclient_config", "", "thin client configuration file")
	root.PersistentFlags().StringVar(&opts.serviceID, "service_id", "", "64-hex Pigeonhole NNTP Service ID")
	root.PersistentFlags().StringVar(&opts.logLevel, "log_level", opts.logLevel, "log level (DEBUG, INFO, ERROR)")
	root.PersistentFlags().DurationVar(&opts.pollInterval, "poll_interval", opts.pollInterval, "pending read poll interval")
	root.PersistentFlags().BoolVar(&opts.direct, "direct", false, "connect directly to --nntp_addr without mixnet (for local diagnostics)")
	root.PersistentFlags().StringVar(&opts.nntpAddr, "nntp_addr", opts.nntpAddr, "direct NNTPS host:port when --direct is set (implicit TLS 1.2+ by default)")
	root.PersistentFlags().BoolVar(&opts.nntpStartTLS, "nntp_starttls", false, "use mandatory RFC 4642 STARTTLS with --direct")
	root.PersistentFlags().BoolVar(&opts.nntpPlaintext, "nntp_insecure_plaintext", false, "disable TLS with --direct (local tests or legacy port-119 servers only)")
	root.PersistentFlags().StringVar(&opts.keyDir, "keydir", opts.keyDir, "directory holding local HPQC public.asc/private.asc")
	root.PersistentFlags().StringVar(&opts.killfilePath, "killfile", opts.killfilePath, "path to editable local JSON killfile")

	// list
	listCmd := &cobra.Command{
		Use:   "list [PATTERN]",
		Short: "List available newsgroups (optional wildmat, e.g. free.*)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			cli, closeFn, err := openClient(ctx, opts, false)
			if err != nil {
				return err
			}
			defer closeFn()
			pattern := ""
			if len(args) == 1 {
				pattern = args[0]
			}
			res, err := cli.List(ctx, pattern)
			if err != nil {
				return err
			}
			for _, g := range res.Groups {
				fmt.Printf("%s %d %d %s\n", g.Name, g.High, g.Low, g.Status)
			}
			return nil
		},
	}

	// group
	groupCmd := &cobra.Command{
		Use:   "group <NEWSGROUP>",
		Short: "Fetch article count and watermarks for a newsgroup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			cli, closeFn, err := openClient(ctx, opts, false)
			if err != nil {
				return err
			}
			defer closeFn()
			g, err := cli.Group(ctx, args[0])
			if err != nil {
				return err
			}
			fmt.Printf("%s: count=%d low=%d high=%d\n", g.Name, g.Count, g.Low, g.High)
			return nil
		},
	}

	// over
	var fromNum, toNum uint64
	var showHidden bool
	overCmd := &cobra.Command{
		Use:   "over <NEWSGROUP>",
		Short: "Fetch threaded overview headers for a newsgroup",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			cli, closeFn, err := openClient(ctx, opts, false)
			if err != nil {
				return err
			}
			defer closeFn()
			kf, err := nntpcli.LoadKillfile(opts.killfilePath)
			if err != nil {
				return err
			}
			res, err := cli.Over(ctx, args[0], fromNum, toNum)
			if err != nil {
				return err
			}
			roots := nntpcli.BuildThreads(res.Entries, kf)
			var printTree func(nodes []*nntpcli.ThreadNode)
			printTree = func(nodes []*nntpcli.ThreadNode) {
				for _, n := range nodes {
					if !n.Hidden || showHidden {
						indent := strings.Repeat("  ", n.Depth)
						tag := ""
						if n.Hidden {
							tag = " [hidden: " + n.HideReason + "]"
						}
						fmt.Printf("%s#%d %s | %s | %s%s\n", indent, n.Entry.Number, n.Entry.Subject, n.Entry.From, n.Entry.MessageID, tag)
					}
					printTree(n.Children)
				}
			}
			printTree(roots)
			return nil
		},
	}
	overCmd.Flags().Uint64Var(&fromNum, "from", 0, "first article number")
	overCmd.Flags().Uint64Var(&toNum, "to", 0, "last article number")
	overCmd.Flags().BoolVar(&showHidden, "show-hidden", false, "include articles filtered by local killfile")

	// article
	var rawOutput bool
	articleCmd := &cobra.Command{
		Use:   "article (<MESSAGE-ID> | <NEWSGROUP> <NUMBER>)",
		Short: "Fetch an article (auto-decrypts HPQC if addressed to local key)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			cli, closeFn, err := openClient(ctx, opts, false)
			if err != nil {
				return err
			}
			defer closeFn()
			var art *nntp.ArticleResult
			if len(args) == 1 {
				art, err = cli.ArticleByID(ctx, args[0])
			} else {
				num, parseErr := strconv.ParseUint(args[1], 10, 64)
				if parseErr != nil {
					return parseErr
				}
				art, err = cli.ArticleByNum(ctx, args[0], num)
			}
			if err != nil {
				return err
			}
			if rawOutput {
				_, err = os.Stdout.Write(art.Raw)
				return err
			}
			headers, bodyBytes, err := nntp.SplitHeadersAndBody(art.Raw)
			if err != nil {
				_, err = os.Stdout.Write(art.Raw)
				return err
			}
			bodyText := strings.ReplaceAll(string(bodyBytes), "\r\n", "\n")
			kp := loadOptionalKeypair(opts.keyDir)
			outcome := nntpcli.InspectBody(bodyText, kp)
			fmt.Printf("From: %s\nSubject: %s\nDate: %s\nMessage-ID: %s\n", headers["from"], headers["subject"], headers["date"], headers["message-id"])
			if outcome.Decrypted {
				fmt.Printf("X-Pigeonhole-HPQC: decrypted\n\n%s\n", outcome.Plaintext)
			} else {
				fmt.Printf("\n%s\n", bodyText)
			}
			return nil
		},
	}
	articleCmd.Flags().BoolVar(&rawOutput, "raw", false, "print raw RFC 5536 article without HPQC auto-decryption")

	// post
	var postGroup, postFrom, postSubject, postRefs, encryptTo, bodyFile string
	postCmd := &cobra.Command{
		Use:   "post",
		Short: "Post an article (optionally HPQC-encrypted or containing free-form PGP/pqpg/age ciphertext)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			var bodyRaw []byte
			var err error
			if bodyFile != "" {
				bodyRaw, err = os.ReadFile(bodyFile)
			} else {
				bodyRaw, err = io.ReadAll(os.Stdin)
			}
			if err != nil {
				return err
			}
			body := string(bodyRaw)
			if encryptTo != "" {
				pubRaw, err := os.ReadFile(encryptTo)
				if err != nil {
					return fmt.Errorf("read recipient public key: %w", err)
				}
				sch, pub, err := nntpcli.ParseArmoredPublicKey(string(pubRaw))
				if err != nil {
					return err
				}
				body, err = nntpcli.SealArmored(sch, pub, bodyRaw)
				if err != nil {
					return err
				}
			}
			rawArt, err := nntpcli.BuildArticle(postGroup, postFrom, postSubject, postRefs, body)
			if err != nil {
				return err
			}
			cli, closeFn, err := openClient(ctx, opts, true)
			if err != nil {
				return err
			}
			defer closeFn()
			res, err := cli.Post(ctx, rawArt)
			if err != nil {
				return err
			}
			fmt.Printf("Posted (accepted=%v id=%s)\n", res.Accepted, res.MessageID)
			return nil
		},
	}
	postCmd.Flags().StringVar(&postGroup, "group", nntp.DefaultNewsgroup, "target newsgroup")
	postCmd.Flags().StringVar(&postFrom, "from", "Anonymous <anon@pigeonhole.invalid>", "From header")
	postCmd.Flags().StringVar(&postSubject, "subject", "", "article Subject")
	postCmd.Flags().StringVar(&postRefs, "references", "", "optional References header")
	postCmd.Flags().StringVar(&encryptTo, "encrypt-to", "", "path to recipient HPQC ASCII-armored public key")
	postCmd.Flags().StringVar(&bodyFile, "body-file", "", "file with message body (defaults to stdin)")
	_ = postCmd.MarkFlagRequired("subject")

	// bridge
	var bridgeListen string
	var bridgeAllowPost, bridgeDecrypt bool
	bridgeCmd := &cobra.Command{
		Use:   "bridge",
		Short: "Run local loopback NNTP bridge (default 127.0.0.1:1119) for standard newsreaders",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			cli, closeFn, err := openClient(ctx, opts, bridgeAllowPost)
			if err != nil {
				return err
			}
			defer closeFn()
			kf, err := nntpcli.LoadKillfile(opts.killfilePath)
			if err != nil {
				return err
			}
			b := &nntpcli.LocalBridge{
				Client:        cli,
				ListenAddr:    bridgeListen,
				AllowPost:     bridgeAllowPost,
				Keypair:       loadOptionalKeypair(opts.keyDir),
				DecryptOnRead: bridgeDecrypt,
				Killfile:      kf,
			}
			fmt.Fprintf(os.Stderr, "pigeonhole-nntp local NNTP bridge listening on %s\n", bridgeListen)
			return b.ListenAndServe(ctx)
		},
	}
	bridgeCmd.Flags().StringVar(&bridgeListen, "listen", nntpcli.DefaultBridgeAddr, "local loopback NNTP listen address")
	bridgeCmd.Flags().BoolVar(&bridgeAllowPost, "allow-post", false, "enable POST through the local bridge")
	bridgeCmd.Flags().BoolVar(&bridgeDecrypt, "decrypt", true, "transparently decrypt HPQC articles addressed to local key")

	// web
	var webListen string
	var webAllowPost bool
	webCmd := &cobra.Command{
		Use:   "web",
		Short: "Run local 0%-JS Gemini-style Web UI (default 127.0.0.1:8119)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			cli, closeFn, err := openClient(ctx, opts, webAllowPost)
			if err != nil {
				return err
			}
			defer closeFn()
			ui, err := nntpcli.NewWebUI(cli, opts.killfilePath, loadOptionalKeypair(opts.keyDir), webAllowPost)
			if err != nil {
				return err
			}
			srv := &http.Server{
				Addr:              webListen,
				Handler:           ui.Handler(),
				ReadHeaderTimeout: 10 * time.Second,
			}
			go func() {
				<-ctx.Done()
				_ = srv.Close()
			}()
			fmt.Fprintf(os.Stderr, "pigeonhole-nntp Web UI (0%% JS) listening on http://%s/\n", webListen)
			err = srv.ListenAndServe()
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		},
	}
	webCmd.Flags().StringVar(&webListen, "listen", nntpcli.DefaultWebAddr, "local loopback HTTP listen address")
	webCmd.Flags().BoolVar(&webAllowPost, "allow-post", false, "enable posting/inline replies from the Web UI")

	// keygen / seal / open
	var keyScheme string
	keygenCmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a local HPQC NIKE keypair (default X25519-CTIDH1024) for Usenet sealedbox armor",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := nntpcli.GenerateKeypair(keyScheme)
			if err != nil {
				return err
			}
			if err := nntpcli.SaveKeypair(opts.keyDir, kp); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Saved HPQC keypair (%s, fp=%s) to %s\n", kp.Scheme.Name(), kp.Fingerprint(), opts.keyDir)
			fmt.Print(kp.ArmorPublicKey())
			return nil
		},
	}
	keygenCmd.Flags().StringVar(&keyScheme, "scheme", "", "HPQC NIKE scheme (default: X25519-CTIDH1024)")

	sealCmd := &cobra.Command{
		Use:   "seal <RECIPIENT_PUBLIC_KEY_FILE>",
		Short: "Encrypt stdin into a Katzenpost HPQC ASCII-armored block",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pubRaw, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			sch, pub, err := nntpcli.ParseArmoredPublicKey(string(pubRaw))
			if err != nil {
				return err
			}
			pt, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
			armored, err := nntpcli.SealArmored(sch, pub, pt)
			if err != nil {
				return err
			}
			fmt.Print(armored)
			return nil
		},
	}

	openCmd := &cobra.Command{
		Use:   "open",
		Short: "Decrypt a Katzenpost HPQC ASCII-armored block from stdin using local --keydir",
		RunE: func(cmd *cobra.Command, args []string) error {
			kp, err := nntpcli.LoadKeypair(opts.keyDir)
			if err != nil {
				return err
			}
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return err
			}
			pt, err := nntpcli.OpenArmored(kp, string(raw))
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(pt)
			return err
		},
	}

	root.AddCommand(listCmd, groupCmd, overCmd, articleCmd, postCmd, bridgeCmd, webCmd, keygenCmd, sealCmd, openCmd)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
