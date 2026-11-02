// Package gemini implements a Gemini protocol gateway and service over Pigeonhole.
// Clients submit a Request with a gemini:// URL over a Pigeonhole connection;
// the service fetches the capsule and returns a Response with the Gemini status,
// meta, and body.
package gemini

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
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
	// Body contains the payload bytes for status 2x.
	Body []byte `cbor:",omitempty"`
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
}

// Fetch fetches the given Gemini URL over a TLS connection.
func (f *TLSFetcher) Fetch(ctx context.Context, rawURL string) (*Response, error) {
	if len(rawURL) > MaxURLBytes {
		return nil, fmt.Errorf("gemini: URL exceeds maximum length of %d bytes", MaxURLBytes)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("gemini: invalid URL: %w", err)
	}

	if !strings.EqualFold(u.Scheme, "gemini") {
		return nil, fmt.Errorf("gemini: unsupported scheme %q (expected gemini)", u.Scheme)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, errors.New("gemini: missing host in URL")
	}

	port := u.Port()
	if port == "" {
		port = DefaultPort
	}
	targetAddr := net.JoinHostPort(hostname, port)

	timeout := f.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	tlsConf := f.TLSConfig
	if tlsConf == nil {
		// In the Gemini ecosystem, self-signed certificates and TOFU (Trust On First Use)
		// are standard. Clients accept certificates directly without standard CA PKI.
		tlsConf = &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true, //nolint:gosec // standard for Gemini capsules
			MinVersion:         tls.VersionTLS12,
		}
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

	// Send request line: <URL>\r\n
	reqLine := rawURL + "\r\n"
	if _, err := io.WriteString(tlsConn, reqLine); err != nil {
		return nil, fmt.Errorf("gemini: failed to send request: %w", err)
	}

	// Read response header: <STATUS><SPACE><META>\r\n
	reader := bufio.NewReader(tlsConn)
	headerLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("gemini: failed to read response header: %w", err)
	}

	headerLine = strings.TrimRight(headerLine, "\r\n")
	parts := strings.SplitN(headerLine, " ", 2)
	if len(parts) < 1 || len(parts[0]) != 2 {
		return nil, fmt.Errorf("gemini: malformed status header %q", headerLine)
	}

	status, err := strconv.Atoi(parts[0])
	if err != nil || status < 10 || status > 69 {
		return nil, fmt.Errorf("gemini: invalid status code %q", parts[0])
	}

	meta := ""
	if len(parts) == 2 {
		meta = parts[1]
	}
	if len(meta) > MaxMetaBytes {
		return nil, fmt.Errorf("gemini: META exceeds maximum length of %d bytes", MaxMetaBytes)
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
			return nil, fmt.Errorf("gemini: response body exceeds limit of %d bytes", maxBody)
		}
		resp.Body = body
	}

	return resp, nil
}

// Serve answers requests from one client connection.
// Requests that fail decoding or fetching return a Response with Error set.
func Serve(ctx context.Context, s Conn, fetcher Fetcher) error {
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
				resp.Error = err.Error()
			} else {
				resp = *r
			}
		}

		reply, err := common.Marshal(&resp)
		if err != nil {
			return err
		}
		if err := s.Send(ctx, reply); err != nil {
			return err
		}
	}
}
