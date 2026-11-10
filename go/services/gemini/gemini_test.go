package gemini_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/common/phtest"
	"github.com/katzenpost/katzenpost/pigeonservice/discovery"
	"github.com/katzenpost/katzenpost/pigeonservice/voucher_router"
	client "github.com/katzenpost/pigeonhole_protocols/go/clients/gemini"
	ps "github.com/katzenpost/pigeonhole_protocols/go/pigeonservice"
	"github.com/katzenpost/pigeonhole_protocols/go/services/gemini"
)

type pipeEnd struct {
	in  chan []byte
	out chan []byte
}

func (p *pipeEnd) Recv(ctx context.Context) ([]byte, error) {
	select {
	case m, ok := <-p.in:
		if !ok {
			return nil, io.EOF
		}
		return m, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *pipeEnd) Send(ctx context.Context, msg []byte) error {
	select {
	case p.out <- msg:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newPipe() (*pipeEnd, *pipeEnd) {
	c1 := make(chan []byte, 8)
	c2 := make(chan []byte, 8)
	return &pipeEnd{in: c1, out: c2}, &pipeEnd{in: c2, out: c1}
}

type mockFetcher struct {
	fn func(ctx context.Context, rawURL string) (*gemini.Response, error)
}

func (m *mockFetcher) Fetch(ctx context.Context, rawURL string) (*gemini.Response, error) {
	return m.fn(ctx, rawURL)
}

func TestServeSuccess(t *testing.T) {
	srvConn, cliConn := newPipe()
	fetcher := &mockFetcher{
		fn: func(ctx context.Context, rawURL string) (*gemini.Response, error) {
			return &gemini.Response{
				Status: 20,
				Meta:   "text/gemini",
				Body:   []byte("# Gemini Title\r\nHello mixnet!"),
			}, nil
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- gemini.Serve(context.Background(), srvConn, fetcher)
	}()

	resp, err := client.Fetch(context.Background(), cliConn, "gemini://example.org/test")
	require.NoError(t, err)
	require.Equal(t, 20, resp.Status)
	require.Equal(t, "text/gemini", resp.Meta)
	require.Equal(t, "# Gemini Title\r\nHello mixnet!", string(resp.Body))

	close(srvConn.in)
	require.Equal(t, io.EOF, <-done)
}

func TestServeErrors(t *testing.T) {
	srvConn, cliConn := newPipe()
	fetcher := &mockFetcher{
		fn: func(ctx context.Context, rawURL string) (*gemini.Response, error) {
			if strings.Contains(rawURL, "fail") {
				return nil, errors.New("simulated fetch failure")
			}
			return &gemini.Response{Status: 20, Meta: "text/gemini"}, nil
		},
	}

	done := make(chan error, 1)
	go func() {
		done <- gemini.Serve(context.Background(), srvConn, fetcher)
	}()

	// 1. Fetcher error
	_, err := client.Fetch(context.Background(), cliConn, "gemini://example.org/fail")
	require.Error(t, err)
	require.Contains(t, err.Error(), "simulated fetch failure")

	// 2. Empty URL
	reqRaw, err := common.Marshal(&gemini.Request{URL: ""})
	require.NoError(t, err)
	require.NoError(t, cliConn.Send(context.Background(), reqRaw))
	replyRaw, err := cliConn.Recv(context.Background())
	require.NoError(t, err)
	var reply gemini.Response
	require.NoError(t, common.Unmarshal(replyRaw, &reply))
	require.Contains(t, reply.Error, "missing URL")

	// 3. Corrupt CBOR
	require.NoError(t, cliConn.Send(context.Background(), []byte{0xff, 0x00, 0x99}))
	replyRaw, err = cliConn.Recv(context.Background())
	require.NoError(t, err)
	require.NoError(t, common.Unmarshal(replyRaw, &reply))
	require.Contains(t, reply.Error, "failed to decode CBOR")

	close(srvConn.in)
	require.Equal(t, io.EOF, <-done)
}

// generateCert creates a self-signed TLS certificate for local tests.
func generateCert(t *testing.T) tls.Certificate {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Katzenpost Gemini Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}
}

func startMockGeminiServer(t *testing.T, handler func(rawReq string) string) (string, func()) {
	cert := generateCert(t)
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				reqLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				resp := handler(strings.TrimRight(reqLine, "\r\n"))
				_, _ = io.WriteString(c, resp)
			}(conn)
		}
	}()

	addr := listener.Addr().String()
	cleanup := func() {
		_ = listener.Close()
		<-done
	}
	return addr, cleanup
}

func TestTLSFetcherSuccess(t *testing.T) {
	addr, cleanup := startMockGeminiServer(t, func(rawReq string) string {
		require.Contains(t, rawReq, "/capsule")
		return "20 text/gemini\r\n# Hello Offline Mixnet\r\nWelcome to Gemini over Pigeonhole!\r\n"
	})
	defer cleanup()

	fetcher := &gemini.TLSFetcher{
		Timeout: 5 * time.Second,
	}

	geminiURL := fmt.Sprintf("gemini://%s/capsule", addr)
	resp, err := fetcher.Fetch(context.Background(), geminiURL)
	require.NoError(t, err)
	require.Equal(t, 20, resp.Status)
	require.Equal(t, "text/gemini", resp.Meta)
	require.Contains(t, string(resp.Body), "Welcome to Gemini over Pigeonhole!")
}

func TestTLSFetcherRedirectAndErrors(t *testing.T) {
	addr, cleanup := startMockGeminiServer(t, func(rawReq string) string {
		if strings.Contains(rawReq, "/redirect") {
			return "30 gemini://example.com/target\r\n"
		}
		if strings.Contains(rawReq, "/notfound") {
			return "51 Resource Not Found\r\n"
		}
		return "20 text/gemini\r\nOK"
	})
	defer cleanup()

	fetcher := &gemini.TLSFetcher{Timeout: 5 * time.Second}

	// 1. Redirect
	resp, err := fetcher.Fetch(context.Background(), fmt.Sprintf("gemini://%s/redirect", addr))
	require.NoError(t, err)
	require.Equal(t, 30, resp.Status)
	require.Equal(t, "gemini://example.com/target", resp.Meta)
	require.Empty(t, resp.Body)

	// 2. Permanent Failure (51)
	resp, err = fetcher.Fetch(context.Background(), fmt.Sprintf("gemini://%s/notfound", addr))
	require.NoError(t, err)
	require.Equal(t, 51, resp.Status)
	require.Equal(t, "Resource Not Found", resp.Meta)
	require.Empty(t, resp.Body)

	// 3. Invalid scheme
	_, err = fetcher.Fetch(context.Background(), "https://example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported scheme")

	// 4. Missing host
	_, err = fetcher.Fetch(context.Background(), "gemini:///path")
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing host")
}

func pluginKey(t *testing.T) *common.PluginKey {
	pub, priv, err := common.DefaultNIKE.GenerateKeyPair()
	require.NoError(t, err)
	return &common.PluginKey{Scheme: common.DefaultNIKE, Public: pub, Private: priv}
}

func TestGeminiOverPigeonholeIntegration(t *testing.T) {
	// 1. Start a local mock TLS Gemini server serving authentic Gemtext
	addr, cleanupServer := startMockGeminiServer(t, func(rawReq string) string {
		return "20 text/gemini\r\n# Stallman Offline Browsing Capsule\r\n" +
			"=> gemini://katzenpost.network/ Katzenpost Mixnet\r\n" +
			"* Feature 1: Single-roundtrip request/response\r\n" +
			"* Feature 2: High latency tolerance\r\n" +
			"* Feature 3: Asynchronous Pigeonhole return mailboxes\r\n"
	})
	defer cleanupServer()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logBackend, err := log.New("", "error", false)
	require.NoError(t, err)

	pollInterval := 10 * time.Millisecond
	simNet := phtest.NewNetwork()

	// 2. Set up voucher router on simulated network
	rkey := pluginKey(t)
	r, err := voucher_router.New(voucher_router.Config{
		Key:          rkey,
		DBPath:       filepath.Join(t.TempDir(), "router.db"),
		PollInterval: pollInterval,
		Retention:    time.Hour,
		Log:          logBackend.GetLogger("router"),
	}, simNet)
	require.NoError(t, err)
	defer r.Close()

	simNet.AddService(voucher_router.RouterCapability, [32]byte{0xa0}, voucher_router.RouterCapability, common.PluginParams(rkey),
		func(_ context.Context, p []byte) []byte { return r.Handle(p) })

	// 3. Set up discovery directory on simulated network
	dkey := pluginKey(t)
	d, err := discovery.New(discovery.Config{
		Key:             dkey,
		DBPath:          filepath.Join(t.TempDir(), "directory.db"),
		RefreshInterval: time.Hour,
		Log:             logBackend.GetLogger("directory"),
	}, simNet)
	require.NoError(t, err)
	defer d.Close()

	simNet.AddService(discovery.DirectoryCapability, [32]byte{0xdd}, discovery.DirectoryCapability, common.PluginParams(dkey),
		func(_ context.Context, p []byte) []byte { return d.Handle(p) })

	// 4. Start Gemini service gateway on Pigeonhole
	dataDir := t.TempDir()
	key, err := common.LoadServiceKey(dataDir)
	require.NoError(t, err)

	adv, err := discovery.NewClient(simNet, key, pollInterval)
	require.NoError(t, err)

	svc, err := ps.NewService(ps.Config{
		Key:          key,
		DataDir:      dataDir,
		DisplayName:  "gemini-gateway",
		Advertiser:   adv,
		PollInterval: pollInterval,
		Log:          logBackend.GetLogger("gemini-service"),
	}, simNet)
	require.NoError(t, err)
	defer svc.Close()

	fetcher := &gemini.TLSFetcher{
		Timeout: 5 * time.Second,
	}

	go func() {
		_ = svc.Run(ctx, ps.HandlerFunc(func(ctx context.Context, s *ps.Session) {
			_ = gemini.Serve(ctx, s, fetcher)
		}))
	}()

	// 5. Client discovers Gemini gateway from service directory
	reader, err := discovery.NewClient(simNet, nil, pollInterval)
	require.NoError(t, err)

	var desc *common.ServiceDescriptor
	require.Eventually(t, func() bool {
		desc, err = reader.Lookup(ctx, svc.ID())
		return err == nil && desc != nil && len(desc.Routers) == 1
	}, 30*time.Second, 20*time.Millisecond, "Gemini gateway service discovery")

	// 6. Client dials the Gemini gateway through Pigeonhole
	conn, err := ps.Dial(ctx, simNet, desc, "gemini client", pollInterval)
	require.NoError(t, err)

	// 7. Client requests the Gemini URL over Pigeonhole
	geminiTargetURL := fmt.Sprintf("gemini://%s/offline-stallman", addr)
	resp, err := client.Fetch(ctx, conn, geminiTargetURL)
	require.NoError(t, err)

	// 8. Assert authentic Gemini Gemtext response arrived across Pigeonhole
	require.Equal(t, 20, resp.Status)
	require.Equal(t, "text/gemini", resp.Meta)
	bodyStr := string(resp.Body)
	require.Contains(t, bodyStr, "# Stallman Offline Browsing Capsule")
	require.Contains(t, bodyStr, "Asynchronous Pigeonhole return mailboxes")
	require.Contains(t, bodyStr, "gemini://katzenpost.network/")
}
