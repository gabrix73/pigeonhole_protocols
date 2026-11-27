# Pigeonhole NNTP (Usenet over Katzenpost)

`pigeonhole-nntp` bridges Usenet (NNTP, RFC 3977 / RFC 5536) over Katzenpost
Pigeonhole mixnet mailboxes. It enables metadata-resistant reading and optional
anonymous posting against unauthenticated text-only NNTP servers (such as
`news.tcpreset.net` or Paganini) and pairs with the dedicated Usenet group
**`free.katzenpost-messages`**.

## Architecture

- **Service (`go/services/nntp`, `go/cmd/pigeonhole-nntp-service`)**:
  - Registers as a standard `pigeonservice.Service` over `kpclientd`.
  - Connects only to a single operator-configured upstream NNTPS/NNTP server
    (`--nntp_addr`, default `news.tcpreset.net:563` over implicit TLS 1.2+),
    so clients can never pivot the gateway into an SSRF or port-scanning
    oracle. Plaintext port 119 is disabled by default (`--nntp_starttls` for
    mandatory RFC 4642 STARTTLS; `--nntp_insecure_plaintext` only as explicit
    opt-in for local testing).
  - Supports `LIST`, `GROUP`, `OVER` (with automatic `XOVER` fallback),
    `ARTICLE`, and opt-in `POST` (`--allow_post`, disabled by default).
  - Enforces Cleanfeed-NG / Postfilter-NG friendly posting rules: required
    RFC 5536 headers, text-only UTF-8 (rejects NUL/yEnc/uuencode), forbidden
    control/tracking header rejection (`Control`, `Supersedes`, `Approved`,
    `X-Trace`, `Injection-Info`, `NNTP-Posting-Host`, `Path`, `Received`),
    optional `--allowed_post_groups` allowlist, and a sliding-window rate
    limiter (`--post_rate_limit`, `--post_rate_window`).
  - Offloads large responses (`Response.PayloadStream`) and large POST articles
    (`Request.ArticleStream`) over `go/protocols/stream`.

- **Client (`go/clients/nntp`, `go/cmd/pigeonhole-nntp`)**:
  - **CLI**: `list`, `group`, `over`, `article`, `post`, `keygen`, `seal`, `open`.
  - **Local NNTP Bridge (`pigeonhole-nntp bridge`)**: listens on loopback
    (`127.0.0.1:1119`) speaking RFC 3977 to standard newsreaders (Thunderbird,
    NeoMutt, slrn, tin, Aegis), with in-memory TTL caching, local killfile
    filtering, and optional transparent HPQC decryption.
  - **Local Web UI (`pigeonhole-nntp web`)**: minimal Gemini-inspired reader on
    `127.0.0.1:8119` built with Go `html/template` and **0% JavaScript**
    (enforced via `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'`),
    `References` thread trees rendered with `<details open>`, inline replies,
    per-process CSRF protection, and an editable local killfile.
  - **Encryption**:
    - Integrated anonymous post-quantum hybrid encryption using
      `hpqc/protocols/sealedbox` (`X25519-CTIDH1024` by default) wrapped in
      Cleanfeed-safe ASCII armor (`-----BEGIN KATZENPOST HPQC MESSAGE-----`).
    - Full pass-through support and detection for free-form encrypted bodies
      (`PGP`, `pqpg`, `age`).
  - **Editable Local Killfile**:
    - Strong anti-troll and anti-flood defaults (`MaxCrossposts: 4`,
      `MaxLines: 2000`, `MaxPostsPerAuthor: 15`, `HideUndecryptable: true`).
    - Automatically hides undecryptable encrypted messages while offering an
      explicit per-view reveal toggle.

## Quick Start

### Service daemon

```sh
pigeonhole-nntp-service \
  --thinclient_config thinclient.toml \
  --datadir /var/lib/pigeonhole-nntp \
  --nntp_addr news.tcpreset.net:563 \
  --allow_post \
  --allowed_post_groups free.katzenpost-messages
```

### Local identity (optional HPQC encryption)

```sh
pigeonhole-nntp keygen
```

### Local 0%-JS Web UI

```sh
# Over Katzenpost mixnet:
pigeonhole-nntp web \
  --thinclient_config thinclient.toml \
  --service_id <64-HEX-SERVICE-ID> \
  --listen 127.0.0.1:8119

# Direct local test over NNTPS (TLS 563) against news.tcpreset.net:
pigeonhole-nntp web --direct --nntp_addr news.tcpreset.net:563
```

### Local NNTP bridge for standard newsreaders

```sh
pigeonhole-nntp bridge \
  --thinclient_config thinclient.toml \
  --service_id <64-HEX-SERVICE-ID> \
  --listen 127.0.0.1:1119
```
