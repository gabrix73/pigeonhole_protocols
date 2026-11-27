// SPDX-License-Identifier: AGPL-3.0-only

package nntp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	svc "github.com/katzenpost/pigeonhole_protocols/go/services/nntp"
)

// DefaultWebAddr is the loopback-only listen address for the 0%-JS local Web UI.
const DefaultWebAddr = "127.0.0.1:8119"

// WebUI serves a minimal Gemini-inspired, 0%-JavaScript Usenet interface over
// loopback using Go's html/template, <details open> References trees, inline
// replies, editable local killfile, and optional HPQC encryption.
type WebUI struct {
	Client       *Client
	DefaultGroup string
	KillfilePath string
	Keypair      *Keypair
	AllowPost    bool

	mu        sync.RWMutex
	killfile  *Killfile
	csrfToken string
	templates *template.Template
}

// NewWebUI initializes a WebUI with loaded killfile rules and a per-process CSRF token.
func NewWebUI(client *Client, killfilePath string, kp *Keypair, allowPost bool) (*WebUI, error) {
	kf, err := LoadKillfile(killfilePath)
	if err != nil {
		return nil, err
	}
	var tok [24]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return nil, err
	}
	tmpl, err := template.New("base").Funcs(template.FuncMap{
		"urlquery": url.QueryEscape,
		"join":     strings.Join,
	}).Parse(webTemplates)
	if err != nil {
		return nil, err
	}
	return &WebUI{
		Client:       client,
		DefaultGroup: svc.DefaultNewsgroup,
		KillfilePath: killfilePath,
		Keypair:      kp,
		AllowPost:    allowPost,
		killfile:     kf,
		csrfToken:    hex.EncodeToString(tok[:]),
		templates:    tmpl,
	}, nil
}

// Handler returns the HTTP handler enforcing a strict 0%-JS Content-Security-Policy.
func (u *WebUI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", u.handleIndex)
	mux.HandleFunc("/group", u.handleGroup)
	mux.HandleFunc("/article", u.handleArticle)
	mux.HandleFunc("/post", u.handlePost)
	mux.HandleFunc("/killfile", u.handleKillfile)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, r)
	})
}

func (u *WebUI) currentKillfile() *Killfile {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.killfile
}

func (u *WebUI) verifyCSRF(r *http.Request) bool {
	got := r.FormValue("csrf")
	return len(got) == len(u.csrfToken) && subtle.ConstantTimeCompare([]byte(got), []byte(u.csrfToken)) == 1
}

type indexData struct {
	DefaultGroup string
	Pattern      string
	Groups       []svc.GroupInfo
	Error        string
	Fingerprint  string
	PublicKey    string
	AllowPost    bool
}

func (u *WebUI) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	pattern := strings.TrimSpace(r.URL.Query().Get("pattern"))
	data := indexData{
		DefaultGroup: u.DefaultGroup,
		Pattern:      pattern,
		AllowPost:    u.AllowPost,
	}
	if u.Keypair != nil {
		data.Fingerprint = u.Keypair.Fingerprint()
		data.PublicKey = u.Keypair.ArmorPublicKey()
	}
	res, err := u.Client.List(r.Context(), pattern)
	if err != nil {
		data.Error = err.Error()
	} else {
		data.Groups = res.Groups
	}
	u.render(w, "index", data)
}

type groupData struct {
	Group       string
	Info        *svc.GroupInfo
	Roots       []*ThreadNode
	HiddenCount int
	ShowHidden  bool
	AllowPost   bool
	CSRF        string
	Notice      string
	Error       string
}

func (u *WebUI) handleGroup(w http.ResponseWriter, r *http.Request) {
	group := strings.TrimSpace(r.URL.Query().Get("name"))
	if group == "" {
		group = u.DefaultGroup
	}
	showHidden := r.URL.Query().Get("show_hidden") == "1"
	data := groupData{
		Group:      group,
		ShowHidden: showHidden,
		AllowPost:  u.AllowPost,
		CSRF:       u.csrfToken,
		Notice:     r.URL.Query().Get("notice"),
	}
	if err := svc.ValidateGroupName(group); err != nil {
		data.Error = "invalid newsgroup name"
		u.render(w, "group", data)
		return
	}

	info, err := u.Client.Group(r.Context(), group)
	if err != nil {
		data.Error = err.Error()
		u.render(w, "group", data)
		return
	}
	data.Info = info

	over, err := u.Client.Over(r.Context(), group, 0, 0)
	if err != nil {
		data.Error = err.Error()
		u.render(w, "group", data)
		return
	}

	kf := u.currentKillfile()
	roots := BuildThreads(over.Entries, kf)
	data.HiddenCount = countHiddenNodes(roots)
	if !showHidden {
		roots = pruneHiddenNodes(roots)
	}
	data.Roots = roots
	u.render(w, "group", data)
}

func countHiddenNodes(nodes []*ThreadNode) int {
	total := 0
	for _, n := range nodes {
		if n.Hidden {
			total++
		}
		total += countHiddenNodes(n.Children)
	}
	return total
}

func pruneHiddenNodes(nodes []*ThreadNode) []*ThreadNode {
	var out []*ThreadNode
	for _, n := range nodes {
		children := pruneHiddenNodes(n.Children)
		if n.Hidden {
			out = append(out, children...)
			continue
		}
		cp := *n
		cp.Children = children
		out = append(out, &cp)
	}
	return out
}

type articleData struct {
	Group           string
	Number          uint64
	MessageID       string
	Subject         string
	From            string
	Date            string
	References      string
	ReplySubject    string
	ReplyReferences string
	Body            string
	CipherKind      CipherKind
	Decrypted       bool
	Hidden          bool
	HideReason      string
	ShowHidden      bool
	AllowPost       bool
	CSRF            string
	Error           string
}

func (u *WebUI) handleArticle(w http.ResponseWriter, r *http.Request) {
	group := strings.TrimSpace(r.URL.Query().Get("group"))
	numStr := strings.TrimSpace(r.URL.Query().Get("num"))
	msgID := strings.TrimSpace(r.URL.Query().Get("id"))
	showHidden := r.URL.Query().Get("show_hidden") == "1"

	data := articleData{
		Group:      group,
		MessageID:  msgID,
		ShowHidden: showHidden,
		AllowPost:  u.AllowPost,
		CSRF:       u.csrfToken,
	}

	var (
		art *svc.ArticleResult
		err error
	)
	if msgID != "" {
		art, err = u.Client.ArticleByID(r.Context(), msgID)
	} else {
		num, parseErr := strconv.ParseUint(numStr, 10, 64)
		if parseErr != nil || num == 0 {
			data.Error = "missing article number or message-id"
			u.render(w, "article", data)
			return
		}
		data.Number = num
		art, err = u.Client.ArticleByNum(r.Context(), group, num)
	}
	if err != nil {
		data.Error = err.Error()
		u.render(w, "article", data)
		return
	}

	headers, bodyBytes, err := svc.SplitHeadersAndBody(art.Raw)
	if err != nil {
		data.Error = "failed to parse article headers"
		u.render(w, "article", data)
		return
	}
	bodyText := strings.ReplaceAll(string(bodyBytes), "\r\n", "\n")
	outcome := InspectBody(bodyText, u.Keypair)
	hidden, reason := u.currentKillfile().EvaluateArticle(headers, outcome)

	data.Number = art.Number
	data.MessageID = headers["message-id"]
	if data.MessageID == "" {
		data.MessageID = art.MessageID
	}
	data.Subject = headers["subject"]
	data.From = headers["from"]
	data.Date = headers["date"]
	data.References = headers["references"]
	if data.Group == "" {
		if first, _, _ := strings.Cut(headers["newsgroups"], ","); first != "" {
			data.Group = strings.TrimSpace(first)
		}
	}
	data.CipherKind = outcome.CipherKind
	data.Decrypted = outcome.Decrypted
	data.Hidden = hidden
	data.HideReason = reason

	if outcome.Decrypted {
		data.Body = outcome.Plaintext
	} else if !hidden || showHidden {
		data.Body = bodyText
	}

	if strings.HasPrefix(strings.ToLower(data.Subject), "re:") {
		data.ReplySubject = data.Subject
	} else if data.Subject != "" {
		data.ReplySubject = "Re: " + data.Subject
	}
	if data.References != "" && data.MessageID != "" {
		data.ReplyReferences = data.References + " " + data.MessageID
	} else {
		data.ReplyReferences = data.MessageID
	}

	u.render(w, "article", data)
}

func (u *WebUI) handlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !u.AllowPost {
		http.Error(w, "posting disabled", http.StatusForbidden)
		return
	}
	if !u.verifyCSRF(r) {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return
	}

	group := strings.TrimSpace(r.FormValue("group"))
	from := strings.TrimSpace(r.FormValue("from"))
	subject := strings.TrimSpace(r.FormValue("subject"))
	references := strings.TrimSpace(r.FormValue("references"))
	body := r.FormValue("body")
	recipientPub := strings.TrimSpace(r.FormValue("recipient_pubkey"))

	if recipientPub != "" {
		sch, pub, err := ParseArmoredPublicKey(recipientPub)
		if err != nil {
			http.Error(w, "invalid HPQC recipient public key", http.StatusBadRequest)
			return
		}
		armored, err := SealArmored(sch, pub, []byte(body))
		if err != nil {
			http.Error(w, "HPQC encryption failed", http.StatusInternalServerError)
			return
		}
		body = armored
	}

	raw, err := BuildArticle(group, from, subject, references, body)
	if err != nil {
		http.Error(w, "invalid article: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := u.Client.Post(r.Context(), raw); err != nil {
		http.Error(w, "post failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/group?name="+url.QueryEscape(group)+"&notice="+url.QueryEscape("Article posted"), http.StatusSeeOther)
}

type killfileData struct {
	Killfile *Killfile
	CSRF     string
	Notice   string
	Error    string
}

func (u *WebUI) handleKillfile(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !u.verifyCSRF(r) {
			http.Error(w, "invalid csrf token", http.StatusForbidden)
			return
		}
		if r.FormValue("reset") == "1" {
			kf := DefaultKillfile()
			u.mu.Lock()
			u.killfile = kf
			u.mu.Unlock()
			if u.KillfilePath != "" {
				_ = SaveKillfile(u.KillfilePath, kf)
			}
			u.render(w, "killfile", killfileData{Killfile: kf, CSRF: u.csrfToken, Notice: "Restored strong anti-troll defaults"})
			return
		}
		maxCross, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("max_crossposts")))
		maxLines, _ := strconv.ParseUint(strings.TrimSpace(r.FormValue("max_lines")), 10, 64)
		maxPerAuth, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("max_posts_per_author")))
		kf := &Killfile{
			HideUndecryptable: r.FormValue("hide_undecryptable") == "on",
			MaxCrossposts:     maxCross,
			MaxLines:          maxLines,
			MaxPostsPerAuthor: maxPerAuth,
			BlockedFrom:       splitLines(r.FormValue("blocked_from")),
			BlockedSubjects:   splitLines(r.FormValue("blocked_subjects")),
			BlockedMessageIDs: splitLines(r.FormValue("blocked_message_ids")),
			BlockedThreads:    splitLines(r.FormValue("blocked_threads")),
		}
		u.mu.Lock()
		u.killfile = kf
		u.mu.Unlock()
		var errMsg string
		if u.KillfilePath != "" {
			if err := SaveKillfile(u.KillfilePath, kf); err != nil {
				errMsg = err.Error()
			}
		}
		u.render(w, "killfile", killfileData{Killfile: kf, CSRF: u.csrfToken, Notice: "Killfile saved", Error: errMsg})
		return
	}
	u.render(w, "killfile", killfileData{Killfile: u.currentKillfile(), CSRF: u.csrfToken})
}

func splitLines(raw string) []string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (u *WebUI) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := u.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, fmt.Sprintf("template error: %v", err), http.StatusInternalServerError)
	}
}

const webTemplates = `
{{define "head"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>pigeonhole-nntp</title>
<style>
  body { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; max-width: 78ch; margin: 1.5rem auto; padding: 0 1rem; line-height: 1.45; background: #111417; color: #e6edf3; }
  a { color: #79c0ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  header { border-bottom: 1px solid #30363d; padding-bottom: .6rem; margin-bottom: 1.2rem; display: flex; flex-wrap: wrap; gap: 1rem; align-items: baseline; }
  h1, h2, h3 { font-weight: 600; margin: .8rem 0 .4rem; }
  pre { white-space: pre-wrap; word-wrap: break-word; background: #161b22; border: 1px solid #30363d; padding: .9rem; }
  details { margin: .35rem 0 .35rem .9rem; border-left: 1px solid #30363d; padding-left: .7rem; }
  summary { cursor: pointer; }
  .meta { color: #8b949e; font-size: .9em; }
  .badge { display: inline-block; padding: .05rem .35rem; border: 1px solid #388bfd; color: #79c0ff; font-size: .8em; }
  .warn { border: 1px solid #d29922; padding: .6rem; color: #f2cc60; margin: .8rem 0; }
  .err { border: 1px solid #f85149; padding: .6rem; color: #ff7b72; margin: .8rem 0; }
  .ok { border: 1px solid #3fb950; padding: .6rem; color: #7ee787; margin: .8rem 0; }
  input, textarea, button { font: inherit; background: #0d1117; color: #e6edf3; border: 1px solid #30363d; padding: .35rem .5rem; }
  textarea { width: 100%; box-sizing: border-box; }
  label { display: block; margin-top: .6rem; }
  button { cursor: pointer; margin-top: .6rem; }
</style>
</head>
<body>
<header>
  <strong><a href="/">pigeonhole-nntp</a></strong>
  <a href="/group?name=free.katzenpost-messages">free.katzenpost-messages</a>
  <a href="/killfile">killfile</a>
</header>
{{end}}

{{define "foot"}}</body></html>{{end}}

{{define "index"}}
{{template "head" .}}
<h1>Usenet over Katzenpost Pigeonhole</h1>
<p class="meta">0% JavaScript local reader. Dedicated group: <a href="/group?name={{urlquery .DefaultGroup}}">{{.DefaultGroup}}</a></p>

<form method="GET" action="/">
  <label>Filter groups (wildmat, e.g. <code>free.*</code>):
    <input type="text" name="pattern" value="{{.Pattern}}" placeholder="free.*">
    <button type="submit">List</button>
  </label>
</form>

{{if .Error}}<div class="err">{{.Error}}</div>{{end}}

{{if .Groups}}
<h2>Newsgroups</h2>
<ul>
  {{range .Groups}}
  <li><a href="/group?name={{urlquery .Name}}">{{.Name}}</a> <span class="meta">({{.Count}} articles, {{.Low}}..{{.High}}, {{.Status}})</span></li>
  {{end}}
</ul>
{{end}}

{{if .Fingerprint}}
<details>
  <summary>Local HPQC Identity ({{.Fingerprint}})</summary>
  <pre>{{.PublicKey}}</pre>
</details>
{{end}}
{{template "foot" .}}
{{end}}

{{define "group"}}
{{template "head" .}}
<h1>{{.Group}}</h1>
{{if .Info}}<p class="meta">{{.Info.Count}} articles ({{.Info.Low}}..{{.Info.High}}){{if .HiddenCount}} | {{.HiddenCount}} hidden by killfile ({{if .ShowHidden}}<a href="/group?name={{urlquery .Group}}">hide filtered</a>{{else}}<a href="/group?name={{urlquery .Group}}&amp;show_hidden=1">show hidden</a>{{end}}){{end}}</p>{{end}}
{{if .Notice}}<div class="ok">{{.Notice}}</div>{{end}}
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}

{{if .AllowPost}}
<details>
  <summary>New post to {{.Group}}</summary>
  <form method="POST" action="/post">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input type="hidden" name="group" value="{{.Group}}">
    <label>From: <input type="text" name="from" value="Anonymous &lt;anon@pigeonhole.invalid&gt;" size="44"></label>
    <label>Subject: <input type="text" name="subject" required size="54"></label>
    <label>Optional HPQC Recipient Public Key (leave empty for plaintext or free-form PGP/pqpg/age):
      <textarea name="recipient_pubkey" rows="4" placeholder="-----BEGIN KATZENPOST HPQC PUBLIC KEY-----"></textarea>
    </label>
    <label>Body:
      <textarea name="body" rows="8" required></textarea>
    </label>
    <button type="submit">Post article</button>
  </form>
</details>
{{end}}

<h2>Threads</h2>
{{if .Roots}}
  {{range .Roots}}
    {{template "threadNode" .}}
  {{end}}
{{else}}
  <p class="meta">No visible articles in this window.</p>
{{end}}
{{template "foot" .}}
{{end}}

{{define "threadNode"}}
<details open>
  <summary>
    <a href="/article?id={{urlquery .Entry.MessageID}}">{{.Entry.Subject}}</a>
    <span class="meta">by {{.Entry.From}} | {{.Entry.Date}} (#{{.Entry.Number}})</span>
    {{if .Hidden}}<span class="badge">hidden: {{.HideReason}}</span>{{end}}
  </summary>
  {{range .Children}}
    {{template "threadNode" .}}
  {{end}}
</details>
{{end}}

{{define "article"}}
{{template "head" .}}
{{if .Group}}<p class="meta"><a href="/group?name={{urlquery .Group}}">&larr; {{.Group}}</a></p>{{end}}
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<h1>{{.Subject}}</h1>
<p class="meta">
  From: {{.From}}<br>
  Date: {{.Date}}<br>
  Message-ID: <code>{{.MessageID}}</code>
  {{if .References}}<br>References: <code>{{.References}}</code>{{end}}
  {{if .Decrypted}}<br><span class="badge">HPQC decrypted</span>{{else if .CipherKind}}<br><span class="badge">encrypted: {{.CipherKind}}</span>{{end}}
</p>

{{if and .Hidden (not .ShowHidden)}}
  <div class="warn">
    Hidden by local killfile ({{.HideReason}}).
    <a href="/article?group={{urlquery .Group}}&amp;num={{.Number}}&amp;id={{urlquery .MessageID}}&amp;show_hidden=1">Show raw content anyway</a>
  </div>
{{else}}
  <pre>{{.Body}}</pre>
{{end}}

{{if .AllowPost}}
<details>
  <summary>Inline reply</summary>
  <form method="POST" action="/post">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <input type="hidden" name="group" value="{{.Group}}">
    <input type="hidden" name="references" value="{{.ReplyReferences}}">
    <label>From: <input type="text" name="from" value="Anonymous &lt;anon@pigeonhole.invalid&gt;" size="44"></label>
    <label>Subject: <input type="text" name="subject" value="{{.ReplySubject}}" required size="54"></label>
    <label>Optional HPQC Recipient Public Key (or paste PGP/pqpg/age ciphertext directly into Body):
      <textarea name="recipient_pubkey" rows="4" placeholder="-----BEGIN KATZENPOST HPQC PUBLIC KEY-----"></textarea>
    </label>
    <label>Reply body:
      <textarea name="body" rows="8" required></textarea>
    </label>
    <button type="submit">Send reply</button>
  </form>
</details>
{{end}}
{{template "foot" .}}
{{end}}

{{define "killfile"}}
{{template "head" .}}
<h1>Local Killfile</h1>
<p class="meta">Strong anti-troll, anti-flood, and undecryptable-message filtering. Substrings or <code>/regex/</code> one per line.</p>
{{if .Notice}}<div class="ok">{{.Notice}}</div>{{end}}
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}

<form method="POST" action="/killfile">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <label><input type="checkbox" name="hide_undecryptable" {{if .Killfile.HideUndecryptable}}checked{{end}}> Automatically hide undecryptable encrypted messages (HPQC / PGP / pqpg / age)</label>
  <label>Max crossposts (0 = unlimited): <input type="number" name="max_crossposts" value="{{.Killfile.MaxCrossposts}}" min="0"></label>
  <label>Max lines per article (0 = unlimited): <input type="number" name="max_lines" value="{{.Killfile.MaxLines}}" min="0"></label>
  <label>Max posts per author in overview window (0 = unlimited): <input type="number" name="max_posts_per_author" value="{{.Killfile.MaxPostsPerAuthor}}" min="0"></label>
  <label>Blocked From (one per line):
    <textarea name="blocked_from" rows="4">{{join .Killfile.BlockedFrom "\n"}}</textarea>
  </label>
  <label>Blocked Subjects (one per line):
    <textarea name="blocked_subjects" rows="4">{{join .Killfile.BlockedSubjects "\n"}}</textarea>
  </label>
  <label>Blocked Message-IDs (one per line):
    <textarea name="blocked_message_ids" rows="3">{{join .Killfile.BlockedMessageIDs "\n"}}</textarea>
  </label>
  <label>Muted Threads / References IDs (one per line):
    <textarea name="blocked_threads" rows="3">{{join .Killfile.BlockedThreads "\n"}}</textarea>
  </label>
  <button type="submit">Save killfile</button>
</form>

<form method="POST" action="/killfile">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="reset" value="1">
  <button type="submit">Reset to strong defaults</button>
</form>
{{template "foot" .}}
{{end}}
`
