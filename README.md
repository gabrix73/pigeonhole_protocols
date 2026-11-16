# pigeonhole_protocols

Libraries for building clients and services on Katzenpost's Pigeonhole storage, in Go, Rust and
Python: the katzenqt1 group chat, the Pigeonhole service framework, and command line tools that
use them. It is for developers writing katzenqt1 clients, as hushphone, katzenrns and the T-Deck
firmware do, and for people implementing or reviewing these protocols; mixnet users and operators
can run its tools. The mixnet itself, the client daemon and the replicas are in
[katzenpost](https://github.com/katzenpost/katzenpost); the Reticulum replicas are in
[pigeonhole_rns](https://github.com/katzenpost/pigeonhole_rns).

## Getting started

```
go get github.com/katzenpost/pigeonhole_protocols/go@main
cargo add pigeonhole_protocols --git https://github.com/katzenpost/pigeonhole_protocols
pip install "pigeonhole-protocols @ git+https://github.com/katzenpost/pigeonhole_protocols#subdirectory=py"
```

A group chat on one machine, with an in-memory Pigeonhole in place of the mixnet:

```
cd go && go run ./cmd/pigeonhole-sim -socket ../pigeonhole.sock &
cd go && go run ./examples/chat -name alice -state alice -sim ../pigeonhole.sock
```

[`examples/`](examples/README.md) explains the client, adds a Rust member and runs over the
mixnet. The [Pigeonhole Protocols How-to Guide](https://katzenpost.network/docs/pigeonhole_protocols_howto/)
builds something new with the library.

## What is here

[`go/`](go) is the Go module, [`rust/`](rust) the `pigeonhole_protocols` crate and
[`py/`](py/README.md) the Python package; [code layout](docs/layout.md) maps their packages.
[`examples/`](examples/README.md) walks through the chat example, [`testdata/`](testdata) holds
the shared test vectors with their sources, and [`docs/`](docs) the tool pages and design notes.

## Tools

Each runs through a Katzenpost client daemon.

| tool | does | smallest command |
|---|---|---|
| [pigeonhole-cp](docs/pigeonhole-cp.md) | copies a file over a channel | `pigeonhole-cp genkey -c thinclient.toml` |
| [kp-fa](docs/kp-fa.md) | broadcasts Ogg/Opus audio | `kp-fa -c thinclient.toml broadcast < show.opus` |
| [ph](docs/ph.md) | a byte stream for ssh and mosh | `ph link new server.json` |
| [zulip-bridge](rust/src/services/zulip/README.md) | joins a group to a Zulip stream | see its README |
| [status-bot](docs/status-bot.md) | reports on the mixnet | `status-bot --data-dir status-bot` |
| [pigeonhole-gemini](go/cmd/pigeonhole-gemini) | fetches Gemini capsules through a [Pigeonhole gateway](go/cmd/pigeonhole-gemini-service) | `pigeonhole-gemini SERVICE_ID gemini://example.org/` |

The Gemini gateway pins a capsule's TLS public key (`SubjectPublicKeyInfo`) on first contact,
keyed by `host:port` as typed (reaching the same host by name and by IP creates separate pins), in
`gemini-known-hosts.json` under its private data directory. Certificate renewals that keep the
same public key are accepted; key changes fail until the operator reviews and updates the pin.
TOFU trust belongs to the service: whoever is on the path at the service's first fetch is pinned
for all clients. Redirect responses (`3x`) are returned to the client as received (neither the
service nor the CLI follows redirects automatically). The public gateway rejects loopback,
private and reserved network addresses; direct mode permits local addresses and keeps its own
pins in the user's configuration directory.

## Protocols and compatibility

katzenqt1 is katzenqt's group chat ([design](https://katzenpost.network/docs/specs/groupchat/),
[contact voucher](https://katzenpost.network/docs/specs/contactvoucher/),
[over Reticulum](https://katzenpost.network/docs/specs/katzenqt1-reticulum/)). The Go and Rust
clients write wire version 5 and the Python client 4 unless told otherwise; all read 3 to 5, and
they share a group with katzenqt. The service framework speaks
[Pigeonhole services](https://katzenpost.network/docs/specs/pigeonhole_services/), as katzenpost's
voucher router and service directory do. The Go, Rust and Python implementations check against
the vectors in [`testdata/katzenqt1`](testdata/katzenqt1), and the Go member's traces replay in
cryptlib's [Lean model](https://github.com/katzenpost/cryptlib/tree/main/Cryptlib/Protocols/GroupComm/GroupChatKatzenqt1).

How it works: [code layout](docs/layout.md), [box sizes](docs/box-sizes.md),
[push on the mesh](docs/push.md), [packing and receipts](docs/packing-and-receipts.md),
[Reticulum from Rust](docs/reticulum-from-rust.md).

## Testing and contributing

`make test rust-test py-test` runs the tests; `py-test` wants `pip install -e "py[test]"` first.
`make test` also builds a localnet for the interop suite, which takes minutes;
`cd go && go test -short ./...` leaves it out. [docs/testing.md](docs/testing.md) covers
conformance, the interop suite and the end to end runs. Issues and pull requests are
welcome on GitHub.

## Licence

[AGPL-3.0-only](LICENSE).
