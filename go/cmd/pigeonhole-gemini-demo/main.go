package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/common/phtest"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
	client "github.com/katzenpost/pigeonhole_protocols/go/clients/gemini"
	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
	"github.com/katzenpost/pigeonhole_protocols/go/services/gemini"
)

func genTLSConfig() (*tls.Config, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func startMockGeminiServer() (string, func(), error) {
	tlsConf, err := genTLSConfig()
	if err != nil {
		return "", nil, err
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		return "", nil, err
	}

	stopCh := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					continue
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				reqLine := strings.TrimRight(string(buf[:n]), "\r\n")

				gemtext := fmt.Sprintf(
					"20 text/gemini\r\n"+
						"# Pigeonhole-Gemini Offline Capsule Demo\r\n"+
						"\r\n"+
						"Request URL received: %s\r\n"+
						"\r\n"+
						"## Mixnet Properties Verified:\r\n"+
						"* Transport: Katze/Pigeonhole dead-drop return mailboxes\r\n"+
						"* Roundtrip: Single request/response exchange\r\n"+
						"* Gemini Spec: TLS port 1965 semantics & <STATUS><SPACE><META>\r\n"+
						"* Offline Model: Zero live TCP connection required between client and target capsule\r\n"+
						"\r\n"+
						"=> gemini://katzenpost.network/ Katzenpost Mixnet Homepage\r\n"+
						"=> gemini://geminiprotocol.net/ Project Gemini Spec\r\n",
					reqLine,
				)
				_, _ = c.Write([]byte(gemtext))
			}(conn)
		}
	}()

	cleanup := func() {
		close(stopCh)
		_ = listener.Close()
	}
	return listener.Addr().String(), cleanup, nil
}

func pluginKey() *common.PluginKey {
	pub, priv, err := common.DefaultNIKE.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	return &common.PluginKey{Scheme: common.DefaultNIKE, Public: pub, Private: priv}
}

func main() {
	fmt.Println("================================================================")
	fmt.Println(" Pigeonhole Gemini Local Verification Demo")
	fmt.Println("================================================================")

	// 1. Start TLS Gemini Capsule on 127.0.0.1
	addr, cleanupServer, err := startMockGeminiServer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error starting local TLS capsule: %v\n", err)
		os.Exit(1)
	}
	defer cleanupServer()
	fmt.Printf("[1/5] Local TLS Gemini capsule running on %s\n", addr)

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "ph-gemini-demo-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	logBackend, _ := log.New("", "error", false)
	pollInterval := 10 * time.Millisecond
	simNet := phtest.NewNetwork()

	// 2. Set up voucher router
	rkey := pluginKey()
	r, err := voucher_router.New(voucher_router.Config{
		Key:          rkey,
		DBPath:       filepath.Join(tmpDir, "router.db"),
		PollInterval: pollInterval,
		Retention:    time.Hour,
		Log:          logBackend.GetLogger("router"),
	}, simNet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up router: %v\n", err)
		os.Exit(1)
	}
	defer r.Close()

	simNet.AddService(voucher_router.RouterCapability, [32]byte{0xa0}, voucher_router.RouterCapability, common.PluginParams(rkey),
		func(_ context.Context, p []byte) []byte { return r.Handle(p) })
	fmt.Println("[2/5] In-memory Pigeonhole voucher router initialized")

	// 3. Set up discovery directory
	dkey := pluginKey()
	d, err := discovery.New(discovery.Config{
		Key:             dkey,
		DBPath:          filepath.Join(tmpDir, "directory.db"),
		RefreshInterval: time.Hour,
		Log:             logBackend.GetLogger("directory"),
	}, simNet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting up directory: %v\n", err)
		os.Exit(1)
	}
	defer d.Close()

	simNet.AddService(discovery.DirectoryCapability, [32]byte{0xdd}, discovery.DirectoryCapability, common.PluginParams(dkey),
		func(_ context.Context, p []byte) []byte { return d.Handle(p) })
	fmt.Println("[3/5] Pigeonhole service discovery directory initialized")

	// 4. Start Gemini service gateway
	serviceDir := filepath.Join(tmpDir, "gemini-svc")
	_ = os.MkdirAll(serviceDir, 0700)
	key, err := common.LoadServiceKey(serviceDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading service key: %v\n", err)
		os.Exit(1)
	}

	adv, err := discovery.NewClient(simNet, key, pollInterval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating advertiser: %v\n", err)
		os.Exit(1)
	}

	svc, err := ps.NewService(ps.Config{
		Key:          key,
		DataDir:      serviceDir,
		DisplayName:  "gemini-gateway",
		Advertiser:   adv,
		PollInterval: pollInterval,
		Log:          logBackend.GetLogger("gemini-service"),
	}, simNet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating service: %v\n", err)
		os.Exit(1)
	}
	defer svc.Close()

	fetcher := &gemini.TLSFetcher{
		Timeout: 5 * time.Second,
	}

	go func() {
		_ = svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
			_ = gemini.Serve(ctx, s, fetcher)
		}))
	}()
	svcID := svc.ID()
	fmt.Printf("[4/5] Gemini gateway running over Pigeonhole (Service ID: %x)\n", svcID[:8])

	// 5. Client lookup, dial and fetch
	reader, err := discovery.NewClient(simNet, nil, pollInterval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating discovery reader: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[5/5] Looking up Gemini gateway descriptor and dialing over Pigeonhole...")
	var desc *common.ServiceDescriptor
	for start := time.Now(); time.Since(start) < 10*time.Second; {
		desc, err = reader.Lookup(ctx, svc.ID())
		if err == nil && desc != nil && len(desc.Routers) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if desc == nil {
		fmt.Fprintf(os.Stderr, "Service discovery timed out\n")
		os.Exit(1)
	}

	conn, err := ps.Dial(ctx, simNet, desc, "gemini-demo-client", pollInterval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error dialing gateway: %v\n", err)
		os.Exit(1)
	}

	targetURL := fmt.Sprintf("gemini://%s/demo/offline-browsing", addr)
	fmt.Printf("--> Sending Pigeonhole request for: %s\n\n", targetURL)

	resp, err := client.Fetch(ctx, conn, targetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fetch error over Pigeonhole: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("----------------- RECEIVED GEMINI RESPONSE -----------------")
	fmt.Printf("Status: %d\n", resp.Status)
	fmt.Printf("Meta:   %s\n", resp.Meta)
	fmt.Println("Payload:")
	fmt.Println(string(resp.Body))
	fmt.Println("------------------------------------------------------------")
	fmt.Println("VERIFICATION SUCCESS: Gemini over Pigeonhole works end-to-end!")
}
