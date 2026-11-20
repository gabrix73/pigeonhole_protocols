// Package gemini implements a Gemini protocol gateway and service over Pigeonhole.
// Clients submit a Request with a gemini:// URL over a Pigeonhole connection;
// the service fetches the capsule and returns a Response with the Gemini status,
// meta, and body.
package gemini

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/stream"
)

// DefaultPort is the standard port for the Gemini protocol.
const DefaultPort = "1965"

// MaxURLBytes is the maximum allowed URL length in bytes per Gemini specification.
const MaxURLBytes = 1024

// MaxMetaBytes is the maximum allowed META length in bytes per Gemini specification.
const MaxMetaBytes = 1024

// DefaultMaxBodyBytes limits response body to 5 MiB to protect memory.
const DefaultMaxBodyBytes = 5 * 1024 * 1024

// DefaultTimeout is the default network fetch timeout.
const DefaultTimeout = 15 * time.Second

// Request asks the Gemini service to fetch a URL.
type Request struct {
	// URL is the gemini:// URL to fetch.
	URL string
}

// Response contains the response from the Gemini server.
type Response struct {
	// Status is the 2-digit Gemini status code (e.g. 20 for success, 30 for redirect).
	Status int
	// Meta is the response meta header (MIME type for 2x, target for 3x, error for 4x/5x).
	Meta string
	// Body contains the payload bytes for status 2x when it fits in one box.
	Body []byte `cbor:",omitempty"`
	// BodyStream carries a serialized bacap.ReadCap when Body is published to a
	// separate Pigeonhole stream because the full response exceeds a single box.
	BodyStream []byte `cbor:",omitempty"`
	// Error carries a gateway/transport error; empty on success.
	Error string `cbor:",omitempty"`
}

// Conn is one end of a connection: a *pigeonservice.Session on the service's side, a
// *pigeonservice.Conn on the client's.
type Conn interface {
	Recv(ctx context.Context) ([]byte, error)
	Send(ctx context.Context, msg []byte) error
}

// Fetcher performs Gemini fetches against capsules.
type Fetcher interface {
	Fetch(ctx context.Context, rawURL string) (*Response, error)
}

// TLSFetcher is the standard network fetcher over TLS.
type TLSFetcher struct {
	// MaxBodyBytes limits the response body size. If zero, DefaultMaxBodyBytes is used.
	MaxBodyBytes int64
	// Timeout limits the connection and read time. If zero, DefaultTimeout is used.
	Timeout time.Duration
	// TLSConfig allows overriding the TLS configuration (e.g. for custom root CAs).
	TLSConfig *tls.Config
	// TOFU pins the first certificate seen for each host and port. When nil,
	// standard certificate verification is used.
	TOFU *TOFUStore
	// AllowNonPublic permits loopback and private targets, for local testing.
	// Public gateway services must leave this false.
	AllowNonPublic bool
	// AllowArbitraryPort permits ports other than DefaultPort (1965), for
	// local testing. Public gateway services must leave this false.
	AllowArbitraryPort bool
}

var (
	errInvalidRequest   = errors.New("invalid request")
	errDisallowedTarget = errors.New("disallowed target")
	errTLSVerification  = errors.New("tls verification failed")
	errUpstreamProtocol = errors.New("upstream protocol error")
)

var blockedPublicRanges = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// publicDialAddress checks the resolved address immediately before connect,
// so DNS names that resolve to private addresses cannot bypass the boundary.
func publicDialAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: gemini: unresolved dial address %q", errDisallowedTarget, address)
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return fmt.Errorf("%w: gemini: non-public target %s is not allowed", errDisallowedTarget, ip)
	}
	for _, prefix := range blockedPublicRanges {
		if prefix.Contains(ip) {
			return fmt.Errorf("%w: gemini: non-public target %s is not allowed", errDisallowedTarget, ip)
		}
	}
	return nil
}

// Fetch fetches the given Gemini URL over a TLS connection.
func (f *TLSFetcher) Fetch(ctx context.Context, rawURL string) (*Response, error) {
	if len(rawURL) > MaxURLBytes {
		return nil, fmt.Errorf("%w: gemini: URL exceeds maximum length of %d bytes", errInvalidRequest, MaxURLBytes)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: gemini: invalid URL: %w", errInvalidRequest, err)
	}

	if !strings.EqualFold(u.Scheme, "gemini") {
		return nil, fmt.Errorf("%w: gemini: unsupported scheme %q (expected gemini)", errInvalidRequest, u.Scheme)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("%w: gemini: missing host in URL", errInvalidRequest)
	}

	port := u.Port()
	if port == "" {
		port = DefaultPort
	}
	if port != DefaultPort && !f.AllowArbitraryPort {
		return nil, fmt.Errorf("%w: gemini: port %s is not allowed (only %s is permitted)", errDisallowedTarget, port, DefaultPort)
	}
	targetAddr := net.JoinHostPort(hostname, port)

	timeout := f.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}
	if !f.AllowNonPublic {
		dialer.ControlContext = func(_ context.Context, _, address string, _ syscall.RawConn) error {
			return publicDialAddress(address)
		}
	}

	tlsConf := f.TLSConfig
	if f.TOFU != nil {
		if tlsConf != nil {
			return nil, errors.New("gemini: TLSConfig and TOFU cannot be combined")
		}
		// Gemini capsules commonly use self-signed certificates. Pin the
		// SubjectPublicKeyInfo (SPKI) on first contact so renewals with the
		// same key succeed, and reject a changed public key.
		tlsConf = &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true, //nolint:gosec // VerifyConnection checks the persistent TOFU pin
			MinVersion:         tls.VersionTLS12,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return fmt.Errorf("%w: gemini: TLS peer supplied no certificate", errTLSVerification)
				}
				if err := f.TOFU.Verify(strings.ToLower(targetAddr), state.PeerCertificates[0].RawSubjectPublicKeyInfo); err != nil {
					return fmt.Errorf("%w: %w", errTLSVerification, err)
				}
				return nil
			},
		}
	} else if tlsConf == nil {
		tlsConf = &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12}
	} else if tlsConf.ServerName == "" {
		tlsConf = tlsConf.Clone()
		tlsConf.ServerName = hostname
	}

	connCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rawConn, err := dialer.DialContext(connCtx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("gemini: connection failed to %s: %w", targetAddr, err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, tlsConf)
	if err := tlsConn.HandshakeContext(connCtx); err != nil {
		return nil, fmt.Errorf("gemini: TLS handshake failed: %w", err)
	}
	defer tlsConn.Close()
	if deadline, ok := connCtx.Deadline(); ok {
		if err := tlsConn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("gemini: failed to set network deadline: %w", err)
		}
	}

	// Send request line: <URL>\r\n
	reqLine := rawURL + "\r\n"
	if _, err := io.WriteString(tlsConn, reqLine); err != nil {
		return nil, fmt.Errorf("gemini: failed to send request: %w", err)
	}

	// Read response header: <STATUS><SPACE><META>\r\n
	reader := bufio.NewReaderSize(tlsConn, MaxMetaBytes+8)
	headerBytes, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return nil, fmt.Errorf("%w: gemini: response header exceeds %d bytes", errUpstreamProtocol, MaxMetaBytes+5)
	}
	if err != nil {
		return nil, fmt.Errorf("gemini: failed to read response header: %w", err)
	}

	headerLine := strings.TrimRight(string(headerBytes), "\r\n")
	parts := strings.SplitN(headerLine, " ", 2)
	if len(parts) < 1 || len(parts[0]) != 2 {
		return nil, fmt.Errorf("%w: gemini: malformed status header %q", errUpstreamProtocol, headerLine)
	}

	status, err := strconv.Atoi(parts[0])
	if err != nil || status < 10 || status > 69 {
		return nil, fmt.Errorf("%w: gemini: invalid status code %q", errUpstreamProtocol, parts[0])
	}

	meta := ""
	if len(parts) == 2 {
		meta = parts[1]
	}
	if len(meta) > MaxMetaBytes {
		return nil, fmt.Errorf("%w: gemini: META exceeds maximum length of %d bytes", errUpstreamProtocol, MaxMetaBytes)
	}

	resp := &Response{
		Status: status,
		Meta:   meta,
	}

	// For 2x SUCCESS, read body
	if status >= 20 && status < 30 {
		maxBody := f.MaxBodyBytes
		if maxBody <= 0 {
			maxBody = DefaultMaxBodyBytes
		}
		bodyReader := io.LimitReader(reader, maxBody+1)
		body, err := io.ReadAll(bodyReader)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("gemini: failed reading response body: %w", err)
		}
		if int64(len(body)) > maxBody {
			return nil, fmt.Errorf("%w: gemini: response body exceeds limit of %d bytes", errUpstreamProtocol, maxBody)
		}
		resp.Body = body
	}

	return resp, nil
}

func sanitizeFetchError(err error) string {
	switch {
	case errors.Is(err, errInvalidRequest):
		return "bad request: invalid URL"
	case errors.Is(err, errDisallowedTarget):
		return "fetch failed: target not allowed"
	case errors.Is(err, errTLSVerification):
		return "fetch failed: TLS verification failed"
	case errors.Is(err, errUpstreamProtocol):
		return "fetch failed: invalid upstream response"
	default:
		return "fetch failed: upstream connection failed"
	}
}

// Serve answers requests from one client connection without stream offloading.
// Requests that fail decoding or fetching return a Response with Error set.
func Serve(ctx context.Context, s Conn, fetcher Fetcher) error {
	return ServeStream(ctx, s, nil, fetcher, nil)
}

// ServeStream answers requests from one client connection. When ph is non-nil
// and a response exceeds ph.MaxPlaintext(), the body is published to a new
// Pigeonhole stream and its read capability is returned in BodyStream.
func ServeStream(ctx context.Context, s Conn, ph common.Pigeonhole, fetcher Fetcher, tuning *stream.Tuning) error {
	for {
		raw, err := s.Recv(ctx)
		if err != nil {
			return err
		}
		var req Request
		var resp Response
		if err := common.Unmarshal(raw, &req); err != nil {
			resp.Error = "bad request: failed to decode CBOR"
		} else if req.URL == "" {
			resp.Error = "bad request: missing URL"
		} else {
			r, err := fetcher.Fetch(ctx, req.URL)
			if err != nil {
				resp.Error = sanitizeFetchError(err)
			} else {
				resp = *r
			}
		}

		reply, err := common.Marshal(&resp)
		if err != nil {
			return err
		}
		if ph != nil && len(reply) > ph.MaxPlaintext() && len(resp.Body) > 0 {
			rc, err := stream.Publish(ctx, ph, bytes.NewReader(resp.Body), tuning)
			if err != nil {
				resp = Response{Error: "fetch failed: stream publish failed"}
			} else if rcBytes, err := rc.MarshalBinary(); err != nil {
				resp = Response{Error: "fetch failed: stream publish failed"}
			} else {
				resp = Response{
					Status:     resp.Status,
					Meta:       resp.Meta,
					BodyStream: rcBytes,
				}
			}
			reply, err = common.Marshal(&resp)
			if err != nil {
				return err
			}
		}
		if err := s.Send(ctx, reply); err != nil {
			return err
		}
	}
}
