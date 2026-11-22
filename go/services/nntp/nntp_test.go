// SPDX-License-Identifier: AGPL-3.0-only

package nntp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/common/phtest"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/stream"
)

// fakeNNTPServer is an in-process RFC 3977 test server bound to 127.0.0.1:0.
type fakeNNTPServer struct {
	ln          net.Listener
	mu          sync.Mutex
	groups      map[string][]fakeArticle
	byID        map[string]fakeArticle
	allowPost   bool
	noOver      bool // forces 500 on OVER to verify XOVER fallback
	postedRaw   []string
	nextPostNum uint64
}

type fakeArticle struct {
	Num        uint64
	MessageID  string
	Subject    string
	From       string
	Date       string
	References string
	Raw        string
}

func startFakeNNTPServer(t *testing.T, allowPost, noOver bool) *fakeNNTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	a1 := fakeArticle{
		Num:       10,
		MessageID: "<a1@news.tcpreset.net>",
		Subject:   "Welcome to free.katzenpost-messages",
		From:      "Alice <alice@example.invalid>",
		Date:      "Sat, 21 Nov 2026 10:00:00 +0000",
		Raw: strings.Join([]string{
			"From: Alice <alice@example.invalid>",
			"Newsgroups: free.katzenpost-messages",
			"Subject: Welcome to free.katzenpost-messages",
			"Date: Sat, 21 Nov 2026 10:00:00 +0000",
			"Message-ID: <a1@news.tcpreset.net>",
			"",
			"Hello Usenet over Katzenpost.",
			".dot-stuffed line test",
		}, "\r\n") + "\r\n",
	}
	a2 := fakeArticle{
		Num:        11,
		MessageID:  "<a2@news.tcpreset.net>",
		Subject:    "Re: Welcome to free.katzenpost-messages",
		From:       "Bob <bob@example.invalid>",
		Date:       "Sat, 21 Nov 2026 10:05:00 +0000",
		References: "<a1@news.tcpreset.net>",
		Raw: strings.Join([]string{
			"From: Bob <bob@example.invalid>",
			"Newsgroups: free.katzenpost-messages",
			"Subject: Re: Welcome to free.katzenpost-messages",
			"Date: Sat, 21 Nov 2026 10:05:00 +0000",
			"Message-ID: <a2@news.tcpreset.net>",
			"References: <a1@news.tcpreset.net>",
			"",
			strings.Repeat("Large body line over Pigeonhole stream.\r\n", 150),
		}, "\r\n"),
	}

	s := &fakeNNTPServer{
		ln: ln,
		groups: map[string][]fakeArticle{
			"free.katzenpost-messages": {a1, a2},
			"misc.test":                {},
		},
		byID: map[string]fakeArticle{
			a1.MessageID: a1,
			a2.MessageID: a2,
		},
		allowPost:   allowPost,
		noOver:      noOver,
		nextPostNum: 12,
	}

	go s.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeNNTPServer) addr() string { return s.ln.Addr().String() }

func (s *fakeNNTPServer) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(c)
	}
}

func (s *fakeNNTPServer) handleConn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := bufio.NewWriter(c)
	writeLine := func(line string) {
		_, _ = w.WriteString(line + "\r\n")
		_ = w.Flush()
	}
	if s.allowPost {
		writeLine("200 fake.tcpreset.net NNTP ready (posting ok)")
	} else {
		writeLine("201 fake.tcpreset.net NNTP ready (no posting)")
	}

	currentGroup := ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		cmd := strings.ToUpper(parts[0])
		switch cmd {
		case "QUIT":
			writeLine("205 closing connection")
			return
		case "LIST":
			pattern := ""
			if len(parts) >= 3 && strings.ToUpper(parts[1]) == "ACTIVE" {
				pattern = parts[2]
			}
			writeLine("215 list of newsgroups follows")
			s.mu.Lock()
			for name, arts := range s.groups {
				if pattern != "" {
					ok, _ := path.Match(pattern, name)
					if !ok {
						continue
					}
				}
				var low, high uint64
				if len(arts) > 0 {
					low = arts[0].Num
					high = arts[len(arts)-1].Num
				}
				_, _ = fmt.Fprintf(w, "%s %d %d y\r\n", name, high, low)
			}
			s.mu.Unlock()
			writeLine(".")
		case "GROUP":
			if len(parts) < 2 {
				writeLine("501 syntax error")
				continue
			}
			name := parts[1]
			s.mu.Lock()
			arts, ok := s.groups[name]
			s.mu.Unlock()
			if !ok {
				writeLine("411 no such newsgroup")
				continue
			}
			currentGroup = name
			var low, high uint64
			if len(arts) > 0 {
				low = arts[0].Num
				high = arts[len(arts)-1].Num
			}
			writeLine(fmt.Sprintf("211 %d %d %d %s", len(arts), low, high, name))
		case "OVER", "XOVER":
			if cmd == "OVER" && s.noOver {
				writeLine("500 OVER not supported")
				continue
			}
			if currentGroup == "" {
				writeLine("412 no newsgroup selected")
				continue
			}
			var from, to uint64
			if len(parts) >= 2 {
				rng := strings.SplitN(parts[1], "-", 2)
				from, _ = strconv.ParseUint(rng[0], 10, 64)
				if len(rng) == 2 && rng[1] != "" {
					to, _ = strconv.ParseUint(rng[1], 10, 64)
				} else {
					to = from
				}
			}
			writeLine("224 overview information follows")
			s.mu.Lock()
			for _, a := range s.groups[currentGroup] {
				if from > 0 && a.Num < from {
					continue
				}
				if to > 0 && a.Num > to {
					continue
				}
				_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\tXref: fake %s:%d\r\n",
					a.Num, a.Subject, a.From, a.Date, a.MessageID, a.References, len(a.Raw), strings.Count(a.Raw, "\n"), currentGroup, a.Num)
			}
			s.mu.Unlock()
			writeLine(".")
		case "ARTICLE":
			if len(parts) < 2 {
				writeLine("501 syntax error")
				continue
			}
			arg := parts[1]
			var found *fakeArticle
			s.mu.Lock()
			if strings.HasPrefix(arg, "<") {
				if a, ok := s.byID[arg]; ok {
					cp := a
					found = &cp
				}
			} else if currentGroup != "" {
				num, _ := strconv.ParseUint(arg, 10, 64)
				for _, a := range s.groups[currentGroup] {
					if a.Num == num {
						cp := a
						found = &cp
						break
					}
				}
			}
			s.mu.Unlock()
			if found == nil {
				writeLine("430 no such article")
				continue
			}
			writeLine(fmt.Sprintf("220 %d %s article follows", found.Num, found.MessageID))
			for _, l := range strings.Split(strings.TrimSuffix(found.Raw, "\r\n"), "\r\n") {
				if strings.HasPrefix(l, ".") {
					_, _ = w.WriteString("." + l + "\r\n")
				} else {
					_, _ = w.WriteString(l + "\r\n")
				}
			}
			writeLine(".")
		case "POST":
			if !s.allowPost {
				writeLine("440 posting not permitted")
				continue
			}
			writeLine("340 send article")
			var buf bytes.Buffer
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				l = strings.TrimRight(l, "\r\n")
				if l == "." {
					break
				}
				if strings.HasPrefix(l, "..") {
					l = l[1:]
				}
				buf.WriteString(l + "\r\n")
			}
			s.mu.Lock()
			s.postedRaw = append(s.postedRaw, buf.String())
			mid := fmt.Sprintf("<posted-%d@fake.tcpreset.net>", s.nextPostNum)
			s.nextPostNum++
			s.mu.Unlock()
			writeLine("240 article received ok " + mid)
		default:
			writeLine("500 unknown command")
		}
	}
}

type pipeConn struct {
	in  <-chan []byte
	out chan<- []byte
}

func newPipePair() (Conn, Conn) {
	a2b := make(chan []byte, 4)
	b2a := make(chan []byte, 4)
	return &pipeConn{in: b2a, out: a2b}, &pipeConn{in: a2b, out: b2a}
}

func (p *pipeConn) Recv(ctx context.Context) ([]byte, error) {
	select {
	case msg := <-p.in:
		return msg, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *pipeConn) Send(ctx context.Context, msg []byte) error {
	select {
	case p.out <- append([]byte(nil), msg...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestNNTPBackendReadCommandsAndDotUnstuffing(t *testing.T) {
	srv := startFakeNNTPServer(t, true, false)
	backend := &NNTPBackend{Addr: srv.addr(), Plaintext: true, Timeout: 5 * time.Second}
	ctx := context.Background()

	// LIST with wildmat
	resp, err := backend.Execute(ctx, &Request{Cmd: CmdList, Pattern: "free.*"})
	require.NoError(t, err)
	require.Equal(t, 215, resp.Status)
	var listRes ListResult
	require.NoError(t, common.Unmarshal(resp.Payload, &listRes))
	require.Len(t, listRes.Groups, 1)
	require.Equal(t, "free.katzenpost-messages", listRes.Groups[0].Name)

	// GROUP
	resp, err = backend.Execute(ctx, &Request{Cmd: CmdGroup, Group: "free.katzenpost-messages"})
	require.NoError(t, err)
	require.Equal(t, 211, resp.Status)
	var grpRes GroupResult
	require.NoError(t, common.Unmarshal(resp.Payload, &grpRes))
	require.Equal(t, uint64(2), grpRes.Group.Count)
	require.Equal(t, uint64(10), grpRes.Group.Low)
	require.Equal(t, uint64(11), grpRes.Group.High)

	// OVER
	resp, err = backend.Execute(ctx, &Request{Cmd: CmdOver, Group: "free.katzenpost-messages", From: 10, To: 11})
	require.NoError(t, err)
	require.Equal(t, 224, resp.Status)
	var overRes OverResult
	require.NoError(t, common.Unmarshal(resp.Payload, &overRes))
	require.Len(t, overRes.Entries, 2)
	require.Equal(t, "<a1@news.tcpreset.net>", overRes.Entries[0].MessageID)
	require.Equal(t, "<a1@news.tcpreset.net>", overRes.Entries[1].References)

	// ARTICLE by number with dot-stuffed line
	resp, err = backend.Execute(ctx, &Request{Cmd: CmdArticle, Group: "free.katzenpost-messages", ArticleNumber: 10})
	require.NoError(t, err)
	require.Equal(t, 220, resp.Status)
	var artRes ArticleResult
	require.NoError(t, common.Unmarshal(resp.Payload, &artRes))
	require.Contains(t, string(artRes.Raw), "\r\n.dot-stuffed line test\r\n")

	// ARTICLE by Message-ID
	resp, err = backend.Execute(ctx, &Request{Cmd: CmdArticle, ArticleID: "<a1@news.tcpreset.net>"})
	require.NoError(t, err)
	require.Equal(t, 220, resp.Status)
}

func TestNNTPBackendXOVERFallback(t *testing.T) {
	srv := startFakeNNTPServer(t, false, true)
	backend := &NNTPBackend{Addr: srv.addr(), Plaintext: true, Timeout: 5 * time.Second}
	resp, err := backend.Execute(context.Background(), &Request{
		Cmd:   CmdOver,
		Group: "free.katzenpost-messages",
	})
	require.NoError(t, err)
	require.Equal(t, 224, resp.Status)
	var overRes OverResult
	require.NoError(t, common.Unmarshal(resp.Payload, &overRes))
	require.Len(t, overRes.Entries, 2)
}

func TestNNTPBackendInputValidationRejectsInjection(t *testing.T) {
	backend := &NNTPBackend{Addr: "127.0.0.1:1"}
	ctx := context.Background()

	_, err := backend.Execute(ctx, &Request{Cmd: CmdGroup, Group: "misc.test\r\nQUIT"})
	require.ErrorIs(t, err, errInvalidRequest)

	_, err = backend.Execute(ctx, &Request{Cmd: CmdArticle, ArticleID: "<id@x>\r\nPOST"})
	require.ErrorIs(t, err, errInvalidRequest)

	_, err = backend.Execute(ctx, &Request{Cmd: CmdList, Pattern: "free.* evil"})
	require.ErrorIs(t, err, errInvalidRequest)
}

func TestNNTPBackendPostPolicyAndRateLimit(t *testing.T) {
	srv := startFakeNNTPServer(t, true, false)
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	limiter := NewPostLimiter(1, 15*time.Minute)
	limiter.now = func() time.Time { return now }

	validArt := []byte(strings.Join([]string{
		"From: Anon <anon@example.invalid>",
		"Newsgroups: free.katzenpost-messages",
		"Subject: Test post",
		"",
		"Hello from Katzenpost.",
		".leading dot survives round-trip",
	}, "\n") + "\n")

	// Disabled by default
	disabledBackend := &NNTPBackend{Addr: srv.addr(), Plaintext: true, AllowPost: false}
	resp, err := disabledBackend.Execute(context.Background(), &Request{Cmd: CmdPost, Article: validArt})
	require.NoError(t, err)
	require.Equal(t, 440, resp.Status)

	backend := &NNTPBackend{
		Addr:              srv.addr(),
		Plaintext:         true,
		AllowPost:         true,
		AllowedPostGroups: []string{"free.katzenpost-messages"},
		PostLimiter:       limiter,
	}

	// Disallowed newsgroup rejected before touching upstream
	badGroupArt := []byte("From: a@b\nNewsgroups: misc.test\nSubject: x\n\nbody\n")
	_, err = backend.Execute(context.Background(), &Request{Cmd: CmdPost, Article: badGroupArt})
	require.ErrorIs(t, err, errPostNotAllowed)

	// Forbidden header rejected
	badHeaderArt := []byte("From: a@b\nNewsgroups: free.katzenpost-messages\nSubject: x\nControl: cancel <x@y>\n\nbody\n")
	_, err = backend.Execute(context.Background(), &Request{Cmd: CmdPost, Article: badHeaderArt})
	require.ErrorIs(t, err, errPostNotAllowed)

	// Binary yEnc rejected
	yencArt := []byte("From: a@b\nNewsgroups: free.katzenpost-messages\nSubject: x\n\n=ybegin line=128 size=10 name=foo.bin\n")
	_, err = backend.Execute(context.Background(), &Request{Cmd: CmdPost, Article: yencArt})
	require.ErrorIs(t, err, errPostNotAllowed)

	// First valid POST succeeds
	resp, err = backend.Execute(context.Background(), &Request{Cmd: CmdPost, Article: validArt})
	require.NoError(t, err)
	require.Equal(t, 240, resp.Status)
	var postRes PostResult
	require.NoError(t, common.Unmarshal(resp.Payload, &postRes))
	require.True(t, postRes.Accepted)
	require.Contains(t, postRes.MessageID, "@fake.tcpreset.net>")

	srv.mu.Lock()
	require.Len(t, srv.postedRaw, 1)
	require.Contains(t, srv.postedRaw[0], "\r\n.leading dot survives round-trip\r\n")
	srv.mu.Unlock()

	// Second POST within window hits rate limit
	_, err = backend.Execute(context.Background(), &Request{Cmd: CmdPost, Article: validArt})
	require.ErrorIs(t, err, errRateLimited)

	// Advancing clock past window permits posting again
	now = now.Add(16 * time.Minute)
	resp, err = backend.Execute(context.Background(), &Request{Cmd: CmdPost, Article: validArt})
	require.NoError(t, err)
	require.Equal(t, 240, resp.Status)
}

func TestServeStreamLargeArticleAndStreamedPost(t *testing.T) {
	srv := startFakeNNTPServer(t, true, false)
	backend := &NNTPBackend{Addr: srv.addr(), Plaintext: true, AllowPost: true}

	ph := phtest.NewNetwork()
	ph.MaxBox = 256
	tuning := &stream.Tuning{Window: 4, Poll: time.Millisecond}

	clientConn, serverConn := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = ServeStream(ctx, serverConn, ph, backend, tuning)
	}()

	// 1. Fetch large article (#11) -> offloaded to PayloadStream
	reqBytes, err := common.Marshal(&Request{
		Cmd:           CmdArticle,
		Group:         "free.katzenpost-messages",
		ArticleNumber: 11,
	})
	require.NoError(t, err)
	require.NoError(t, clientConn.Send(ctx, reqBytes))

	rawResp, err := clientConn.Recv(ctx)
	require.NoError(t, err)
	var resp Response
	require.NoError(t, common.Unmarshal(rawResp, &resp))
	require.Empty(t, resp.Error)
	require.Equal(t, 220, resp.Status)
	require.Empty(t, resp.Payload)
	require.NotEmpty(t, resp.PayloadStream)

	rc, err := bacap.ReadCapFromBytes(resp.PayloadStream)
	require.NoError(t, err)
	var payloadBuf bytes.Buffer
	require.NoError(t, stream.Fetch(ctx, ph, rc, &payloadBuf, DefaultMaxResponseBytes, tuning))

	var artRes ArticleResult
	require.NoError(t, common.Unmarshal(payloadBuf.Bytes(), &artRes))
	require.Equal(t, "<a2@news.tcpreset.net>", artRes.MessageID)
	require.Greater(t, len(artRes.Raw), 5000)

	// 2. Submit large POST via ArticleStream -> service fetches from stream and posts
	largePost := []byte("From: Alice <a@example.invalid>\r\nNewsgroups: free.katzenpost-messages\r\nSubject: Large post\r\n\r\n" +
		strings.Repeat("Encrypted or long Usenet paragraph line.\r\n", 80))
	postRC, err := stream.Publish(ctx, ph, bytes.NewReader(largePost), tuning)
	require.NoError(t, err)
	postRCBytes, err := postRC.MarshalBinary()
	require.NoError(t, err)

	postReqBytes, err := common.Marshal(&Request{
		Cmd:           CmdPost,
		ArticleStream: postRCBytes,
	})
	require.NoError(t, err)
	require.NoError(t, clientConn.Send(ctx, postReqBytes))

	rawPostResp, err := clientConn.Recv(ctx)
	require.NoError(t, err)
	var postResp Response
	require.NoError(t, common.Unmarshal(rawPostResp, &postResp))
	require.Empty(t, postResp.Error)
	require.Equal(t, 240, postResp.Status)
}

func generateLoopbackTLSConfig(t *testing.T) (serverCfg, clientCfg *tls.Config) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	serverCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	clientCfg = &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	return serverCfg, clientCfg
}

func TestNNTPBackendImplicitTLSDefault(t *testing.T) {
	serverTLS, clientTLS := generateLoopbackTLSConfig(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	srv := &fakeNNTPServer{
		ln: ln,
		groups: map[string][]fakeArticle{
			"free.katzenpost-messages": {{Num: 1, MessageID: "<tls1@tcpreset.net>"}},
		},
		byID:      map[string]fakeArticle{},
		allowPost: false,
	}
	go srv.acceptLoop()

	// Implicit TLS is active by default (Plaintext=false, StartTLS=false).
	backend := &NNTPBackend{
		Addr:      ln.Addr().String(),
		TLSConfig: clientTLS,
		Timeout:   5 * time.Second,
	}
	resp, err := backend.Execute(context.Background(), &Request{Cmd: CmdGroup, Group: "free.katzenpost-messages"})
	require.NoError(t, err)
	require.Equal(t, 211, resp.Status)

	// Calling a plaintext server without Plaintext=true must fail the TLS handshake.
	plainSrv := startFakeNNTPServer(t, false, false)
	_, err = (&NNTPBackend{Addr: plainSrv.addr(), TLSConfig: clientTLS, Timeout: 2 * time.Second}).
		Execute(context.Background(), &Request{Cmd: CmdGroup, Group: "free.katzenpost-messages"})
	require.ErrorIs(t, err, errUpstreamConnect)
}

func TestNNTPBackendStartTLSAndRefusesDowngrade(t *testing.T) {
	serverTLS, clientTLS := generateLoopbackTLSConfig(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				defer raw.Close()
				r := bufio.NewReader(raw)
				w := bufio.NewWriter(raw)
				_, _ = w.WriteString("201 starttls-test ready\r\n")
				_ = w.Flush()
				line, err := r.ReadString('\n')
				if err != nil || strings.TrimSpace(line) != "STARTTLS" {
					return
				}
				_, _ = w.WriteString("382 continue with TLS negotiation\r\n")
				_ = w.Flush()
				tlsConn := tls.Server(raw, serverTLS)
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				tr := bufio.NewReader(tlsConn)
				tw := bufio.NewWriter(tlsConn)
				for {
					l, err := tr.ReadString('\n')
					if err != nil {
						return
					}
					l = strings.TrimSpace(l)
					if strings.HasPrefix(l, "GROUP ") {
						_, _ = tw.WriteString("211 1 1 1 free.katzenpost-messages\r\n")
						_ = tw.Flush()
					} else if l == "QUIT" {
						_, _ = tw.WriteString("205 bye\r\n")
						_ = tw.Flush()
						return
					}
				}
			}(c)
		}
	}()

	backend := &NNTPBackend{
		Addr:      ln.Addr().String(),
		StartTLS:  true,
		TLSConfig: clientTLS,
		Timeout:   5 * time.Second,
	}
	resp, err := backend.Execute(context.Background(), &Request{Cmd: CmdGroup, Group: "free.katzenpost-messages"})
	require.NoError(t, err)
	require.Equal(t, 211, resp.Status)

	// Server that refuses STARTTLS must fail hard (no plaintext downgrade).
	noTLSSrv := startFakeNNTPServer(t, false, false)
	_, err = (&NNTPBackend{Addr: noTLSSrv.addr(), StartTLS: true, TLSConfig: clientTLS, Timeout: 2 * time.Second}).
		Execute(context.Background(), &Request{Cmd: CmdGroup, Group: "free.katzenpost-messages"})
	require.ErrorIs(t, err, errUpstreamConnect)
}
