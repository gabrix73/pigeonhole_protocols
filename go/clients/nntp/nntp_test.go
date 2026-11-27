// SPDX-License-Identifier: AGPL-3.0-only

package nntp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
	"github.com/katzenpost/katzenpost/pigeonservice/common/phtest"
	"github.com/katzenpost/pigeonhole_protocols/go/protocols/stream"
	svc "github.com/katzenpost/pigeonhole_protocols/go/services/nntp"
)

type memBackend struct {
	mu        sync.Mutex
	groups    []svc.GroupInfo
	over      map[string][]svc.OverviewEntry
	articles  map[string]*svc.ArticleResult
	byNum     map[string]*svc.ArticleResult
	posted    [][]byte
	allowPost bool
}

func (m *memBackend) Execute(_ context.Context, req *svc.Request) (*svc.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch req.Cmd {
	case svc.CmdList:
		p, err := common.Marshal(&svc.ListResult{Groups: m.groups})
		if err != nil {
			return nil, err
		}
		return &svc.Response{Status: 215, Message: "list follows", Payload: p}, nil
	case svc.CmdGroup:
		for _, g := range m.groups {
			if g.Name == req.Group {
				p, err := common.Marshal(&svc.GroupResult{Group: g})
				if err != nil {
					return nil, err
				}
				return &svc.Response{Status: 211, Message: "group selected", Payload: p}, nil
			}
		}
		return &svc.Response{Status: 411, Message: "no such group"}, nil
	case svc.CmdOver:
		p, err := common.Marshal(&svc.OverResult{Group: req.Group, Entries: m.over[req.Group]})
		if err != nil {
			return nil, err
		}
		return &svc.Response{Status: 224, Message: "overview follows", Payload: p}, nil
	case svc.CmdArticle:
		var art *svc.ArticleResult
		if req.ArticleID != "" {
			art = m.articles[req.ArticleID]
		} else {
			art = m.byNum[fmt.Sprintf("%s:%d", req.Group, req.ArticleNumber)]
		}
		if art == nil {
			return &svc.Response{Status: 430, Message: "no such article"}, nil
		}
		p, err := common.Marshal(art)
		if err != nil {
			return nil, err
		}
		return &svc.Response{Status: 220, Message: "article follows", Payload: p}, nil
	case svc.CmdPost:
		if !m.allowPost {
			return &svc.Response{Status: 440, Message: "posting disabled"}, nil
		}
		norm, _, err := svc.ValidatePostArticle(req.Article, svc.DefaultMaxPostBytes, nil)
		if err != nil {
			return nil, err
		}
		m.posted = append(m.posted, norm)
		p, err := common.Marshal(&svc.PostResult{Accepted: true, MessageID: "<posted@mem.invalid>"})
		if err != nil {
			return nil, err
		}
		return &svc.Response{Status: 240, Message: "article received", Payload: p}, nil
	default:
		return &svc.Response{Status: 500, Message: "unknown"}, nil
	}
}

type pipeConn struct {
	in  <-chan []byte
	out chan<- []byte
}

func newPipePair() (svc.Conn, svc.Conn) {
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

func TestArmorHPQCRoundTripAndDetection(t *testing.T) {
	// Fast X25519 keypair + persistence test
	kp, err := GenerateKeypair("X25519")
	require.NoError(t, err)
	require.NotEmpty(t, kp.Fingerprint())

	dir := t.TempDir()
	require.NoError(t, SaveKeypair(dir, kp))
	info, err := os.Stat(filepath.Join(dir, "private.asc"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	loaded, err := LoadKeypair(dir)
	require.NoError(t, err)
	require.Equal(t, kp.Fingerprint(), loaded.Fingerprint())

	armored, err := SealArmored(loaded.Scheme, loaded.Public, []byte("secret post-quantum note"))
	require.NoError(t, err)
	require.Equal(t, CipherHPQC, DetectCiphertextKind(armored))

	// Works even when embedded inside quoted Usenet text
	wrapped := "Intro line\n\n" + armored + "\n-- \nsig\n"
	out := InspectBody(wrapped, loaded)
	require.True(t, out.Decrypted)
	require.False(t, out.Undecryptable)
	require.Equal(t, "secret post-quantum note", out.Plaintext)

	// Wrong key cannot decrypt -> Undecryptable
	other, err := GenerateKeypair("X25519")
	require.NoError(t, err)
	outWrong := InspectBody(armored, other)
	require.False(t, outWrong.Decrypted)
	require.True(t, outWrong.Undecryptable)
	require.Equal(t, CipherHPQC, outWrong.CipherKind)

	// Default post-quantum hybrid scheme (X25519-CTIDH1024) round-trip
	pqKP, err := GenerateKeypair("")
	require.NoError(t, err)
	pqArmored, err := SealArmored(pqKP.Scheme, pqKP.Public, []byte("ctidh1024 + x25519 sealedbox"))
	require.NoError(t, err)
	pt, err := OpenArmored(pqKP, pqArmored)
	require.NoError(t, err)
	require.Equal(t, "ctidh1024 + x25519 sealedbox", string(pt))

	// Free-form ciphertext detection (PGP, pqpg, age)
	require.Equal(t, CipherPGP, DetectCiphertextKind("-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----"))
	require.Equal(t, CipherPQPG, DetectCiphertextKind("-----BEGIN PQPG MESSAGE-----\nabc\n-----END PQPG MESSAGE-----"))
	require.Equal(t, CipherAge, DetectCiphertextKind("-----BEGIN AGE ENCRYPTED FILE-----\nabc\n-----END AGE ENCRYPTED FILE-----"))
	require.Equal(t, CipherNone, DetectCiphertextKind("plain text article"))
}

func TestKillfileAndThreadTree(t *testing.T) {
	kf := DefaultKillfile()
	kf.BlockedFrom = []string{"troll@evil.invalid"}
	kf.BlockedThreads = []string{"<muted-root@example>"}

	kfPath := filepath.Join(t.TempDir(), "killfile.json")
	require.NoError(t, SaveKillfile(kfPath, kf))
	loaded, err := LoadKillfile(kfPath)
	require.NoError(t, err)
	require.True(t, loaded.HideUndecryptable)
	require.Equal(t, 4, loaded.MaxCrossposts)

	entries := []svc.OverviewEntry{
		{Number: 1, Subject: "Root topic", From: "Alice <a@ex>", MessageID: "<r1@ex>", Lines: 10},
		{Number: 2, Subject: "Re: Root topic", From: "Bob <b@ex>", MessageID: "<r2@ex>", References: "<r1@ex>", Lines: 8},
		{Number: 3, Subject: "Re: Root topic", From: "Carol <c@ex>", MessageID: "<r3@ex>", References: "<r1@ex> <r2@ex>", Lines: 5},
		{Number: 4, Subject: "Spam crosspost", From: "Spammer <s@ex>", MessageID: "<s1@ex>", Xref: "news g1:1 g2:2 g3:3 g4:4 g5:5", Lines: 4},
		{Number: 5, Subject: "Muted reply", From: "Dan <d@ex>", MessageID: "<m1@ex>", References: "<muted-root@example>", Lines: 4},
		{Number: 6, Subject: "Troll post", From: "Big Troll <troll@evil.invalid>", MessageID: "<t1@ex>", Lines: 4},
	}

	roots := BuildThreads(entries, loaded)
	require.Len(t, roots, 4) // r1 (with child r2 -> r3), s1, m1, t1
	require.Equal(t, "<r1@ex>", roots[0].Entry.MessageID)
	require.Len(t, roots[0].Children, 1)
	require.Equal(t, "<r2@ex>", roots[0].Children[0].Entry.MessageID)
	require.Len(t, roots[0].Children[0].Children, 1)
	require.Equal(t, "<r3@ex>", roots[0].Children[0].Children[0].Entry.MessageID)

	// Spam, muted thread, and troll are flagged hidden
	require.True(t, roots[1].Hidden)
	require.True(t, roots[2].Hidden)
	require.True(t, roots[3].Hidden)

	// Undecryptable PGP article hidden by default
	pgpOutcome := InspectBody("-----BEGIN PGP MESSAGE-----\nxyz\n-----END PGP MESSAGE-----", nil)
	hidden, reason := loaded.EvaluateArticle(map[string]string{
		"from":       "Alice <a@ex>",
		"subject":    "Encrypted",
		"newsgroups": "free.katzenpost-messages",
	}, pgpOutcome)
	require.True(t, hidden)
	require.Contains(t, reason, "pgp")
}

func TestPigeonholeTransportStreamRoundTrip(t *testing.T) {
	largeBody := strings.Repeat("Large streamed Usenet article line.\r\n", 120)
	rawArt := "From: Alice <a@ex>\r\nNewsgroups: free.katzenpost-messages\r\nSubject: Streamed\r\nMessage-ID: <big@ex>\r\n\r\n" + largeBody

	be := &memBackend{
		allowPost: true,
		groups:    []svc.GroupInfo{{Name: "free.katzenpost-messages", Low: 1, High: 1, Count: 1, Status: "y"}},
		articles: map[string]*svc.ArticleResult{
			"<big@ex>": {Number: 1, MessageID: "<big@ex>", Raw: []byte(rawArt)},
		},
		byNum: map[string]*svc.ArticleResult{
			"free.katzenpost-messages:1": {Number: 1, MessageID: "<big@ex>", Raw: []byte(rawArt)},
		},
	}

	ph := phtest.NewNetwork()
	ph.MaxBox = 256
	tuning := &stream.Tuning{Window: 4, Poll: time.Millisecond}

	clientConn, serverConn := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = svc.ServeStream(ctx, serverConn, ph, be, tuning)
	}()

	cli := NewClient(&PigeonholeTransport{Conn: clientConn, PH: ph, Tuning: tuning})

	art, err := cli.ArticleByNum(ctx, "free.katzenpost-messages", 1)
	require.NoError(t, err)
	require.Equal(t, rawArt, string(art.Raw))

	// Oversized POST automatically offloads to ArticleStream
	postRaw, err := BuildArticle("free.katzenpost-messages", "Bob <b@ex>", "Big post", "", strings.Repeat("Encrypted line\n", 60))
	require.NoError(t, err)
	postRes, err := cli.Post(ctx, postRaw)
	require.NoError(t, err)
	require.True(t, postRes.Accepted)
	require.Len(t, be.posted, 1)
}

func TestLocalBridgeNNTPCommandsAndTransparentDecrypt(t *testing.T) {
	kp, err := GenerateKeypair("X25519")
	require.NoError(t, err)
	sealed, err := SealArmored(kp.Scheme, kp.Public, []byte("Decrypted inside local bridge!"))
	require.NoError(t, err)

	rawArt := "From: Alice <a@ex>\r\nNewsgroups: free.katzenpost-messages\r\nSubject: Sealed\r\nMessage-ID: <s1@ex>\r\n\r\n" + sealed
	be := &memBackend{
		allowPost: true,
		groups:    []svc.GroupInfo{{Name: "free.katzenpost-messages", Low: 1, High: 1, Count: 1, Status: "y"}},
		over: map[string][]svc.OverviewEntry{
			"free.katzenpost-messages": {
				{Number: 1, Subject: "Sealed", From: "Alice <a@ex>", Date: "Sat, 21 Nov 2026 10:00:00 +0000", MessageID: "<s1@ex>", Lines: 10},
			},
		},
		articles: map[string]*svc.ArticleResult{"<s1@ex>": {Number: 1, MessageID: "<s1@ex>", Raw: []byte(rawArt)}},
		byNum:    map[string]*svc.ArticleResult{"free.katzenpost-messages:1": {Number: 1, MessageID: "<s1@ex>", Raw: []byte(rawArt)}},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bridge := &LocalBridge{
		Client:        NewClient(&DirectTransport{Backend: be}),
		AllowPost:     true,
		Keypair:       kp,
		DecryptOnRead: true,
	}
	go func() { _ = bridge.Serve(ctx, ln) }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	readLine := func() string {
		s, err := r.ReadString('\n')
		require.NoError(t, err)
		return strings.TrimRight(s, "\r\n")
	}
	send := func(s string) {
		_, err := w.WriteString(s + "\r\n")
		require.NoError(t, err)
		require.NoError(t, w.Flush())
	}

	require.True(t, strings.HasPrefix(readLine(), "200 "))

	send("GROUP free.katzenpost-messages")
	require.True(t, strings.HasPrefix(readLine(), "211 1 1 1 free.katzenpost-messages"))

	send("ARTICLE 1")
	require.True(t, strings.HasPrefix(readLine(), "220 1 <s1@ex>"))
	var lines []string
	for {
		l := readLine()
		if l == "." {
			break
		}
		lines = append(lines, l)
	}
	joined := strings.Join(lines, "\n")
	require.Contains(t, joined, "X-Pigeonhole-HPQC: decrypted")
	require.Contains(t, joined, "Decrypted inside local bridge!")

	send("QUIT")
	require.True(t, strings.HasPrefix(readLine(), "205 "))
}

func TestWebUIZeroJSThreadsKillfileAndInlinePost(t *testing.T) {
	kp, err := GenerateKeypair("X25519")
	require.NoError(t, err)
	sealed, err := SealArmored(kp.Scheme, kp.Public, []byte("Secret HPQC body for WebUI"))
	require.NoError(t, err)

	art1 := "From: Alice <a@ex>\r\nNewsgroups: free.katzenpost-messages\r\nSubject: First thread\r\nMessage-ID: <w1@ex>\r\n\r\n" + sealed
	art2 := "From: Bob <b@ex>\r\nNewsgroups: free.katzenpost-messages\r\nSubject: PGP opaque\r\nMessage-ID: <w2@ex>\r\nReferences: <w1@ex>\r\n\r\n-----BEGIN PGP MESSAGE-----\nabcdef\n-----END PGP MESSAGE-----\r\n"

	be := &memBackend{
		allowPost: true,
		groups:    []svc.GroupInfo{{Name: "free.katzenpost-messages", Low: 1, High: 2, Count: 2, Status: "y"}},
		over: map[string][]svc.OverviewEntry{
			"free.katzenpost-messages": {
				{Number: 1, Subject: "First thread", From: "Alice <a@ex>", MessageID: "<w1@ex>", Lines: 10},
				{Number: 2, Subject: "PGP opaque", From: "Bob <b@ex>", MessageID: "<w2@ex>", References: "<w1@ex>", Lines: 6},
			},
		},
		articles: map[string]*svc.ArticleResult{
			"<w1@ex>": {Number: 1, MessageID: "<w1@ex>", Raw: []byte(art1)},
			"<w2@ex>": {Number: 2, MessageID: "<w2@ex>", Raw: []byte(art2)},
		},
		byNum: map[string]*svc.ArticleResult{
			"free.katzenpost-messages:1": {Number: 1, MessageID: "<w1@ex>", Raw: []byte(art1)},
			"free.katzenpost-messages:2": {Number: 2, MessageID: "<w2@ex>", Raw: []byte(art2)},
		},
	}

	kfPath := filepath.Join(t.TempDir(), "killfile.json")
	ui, err := NewWebUI(NewClient(&DirectTransport{Backend: be}), kfPath, kp, true)
	require.NoError(t, err)
	h := ui.Handler()

	// 1. Index enforces strict 0%-JS CSP and no <script> tags
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Security-Policy"), "default-src 'none'")
	require.NotContains(t, strings.ToLower(rec.Body.String()), "<script")
	require.Contains(t, rec.Body.String(), "free.katzenpost-messages")

	// 2. Group view renders <details open> References tree
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/group?name=free.katzenpost-messages", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "<details open>")
	require.Contains(t, rec.Body.String(), "First thread")
	require.Contains(t, rec.Body.String(), "PGP opaque")

	// 3. Article 1 automatically decrypts HPQC message
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/article?group=free.katzenpost-messages&num=1", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "HPQC decrypted")
	require.Contains(t, rec.Body.String(), "Secret HPQC body for WebUI")

	// 4. Article 2 (undecryptable PGP) hidden by default, shown with show_hidden=1
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/article?group=free.katzenpost-messages&num=2", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "Hidden by local killfile")
	require.NotContains(t, rec.Body.String(), "BEGIN PGP MESSAGE")

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/article?group=free.katzenpost-messages&num=2&show_hidden=1", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), "BEGIN PGP MESSAGE")

	// 5. Inline POST with HPQC encryption & CSRF protection
	form := url.Values{
		"csrf":             {ui.csrfToken},
		"group":            {"free.katzenpost-messages"},
		"from":             {"Tester <t@ex>"},
		"subject":          {"Re: First thread"},
		"references":       {"<w1@ex>"},
		"recipient_pubkey": {kp.ArmorPublicKey()},
		"body":             {"Encrypted reply via Web UI"},
	}
	req := httptest.NewRequest(http.MethodPost, "/post", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusSeeOther, rec.Code)
	require.Len(t, be.posted, 1)
	require.Contains(t, string(be.posted[0]), "-----BEGIN KATZENPOST HPQC MESSAGE-----")

	pt, err := OpenArmored(kp, string(be.posted[0]))
	require.NoError(t, err)
	require.Equal(t, "Encrypted reply via Web UI", string(pt))

	// 6. Killfile edit persists to disk
	kfForm := url.Values{
		"csrf":                 {ui.csrfToken},
		"hide_undecryptable":   {"on"},
		"max_crossposts":       {"3"},
		"max_lines":            {"1500"},
		"max_posts_per_author": {"10"},
		"blocked_from":         {"spam@bad.example"},
	}
	req = httptest.NewRequest(http.MethodPost, "/killfile", strings.NewReader(kfForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	savedKF, err := LoadKillfile(kfPath)
	require.NoError(t, err)
	require.Equal(t, 3, savedKF.MaxCrossposts)
	require.Equal(t, []string{"spam@bad.example"}, savedKF.BlockedFrom)
}
