# How the code is laid out

Each language is a directory of its own: `go/` is the Go module
`github.com/katzenpost/pigeonhole_protocols/go`; `rust/` is one crate, `pigeonhole_protocols`;
`py/` is the package `pigeonhole-protocols` (see [`py/README.md`](../py/README.md)). Within each,
group communication among peers is under `protocols/`, and mixnet services (responders) and their
clients (initiators) under `services/` and `clients/`.

## Protocols

Each protocol under `protocols/` has a sans-IO state machine, an engine that is a whole client
without IO, and a client that carries the engine's work out over a transport and keeps its state
on disk. Every step's changes are saved, synced, before any of the work it asks for starts.

`protocols/katzenqt1` is katzenqt's group chat as of October 2026:

- `wire`: message fields, GroupChatMessage CBOR, box framing, the reply to a new member, files.
- `member`: one member of a group, as a state machine; its trace format, and katzenqt's scenario
  simulator.
- `engine`: the client without IO.
- `store`: its state, in bbolt; in Rust, redb, as a module of the client crate.
- `client`: the client, over a transport.

In Rust, the sans-IO core (`protocols::katzenqt1::{engine, member, wire}`) builds `no_std` with
`alloc` when the default `std` feature is off. Rust also has `protocols::stream` and
`protocols::datagram`, which [`ph`](ph.md) carries over.

## Transports

`transport` is what a client asks of Pigeonhole: over the client daemon's thin client, in memory
for tests, and served from one process to others (`remote`, JSON-RPC). Rust also reaches a
Reticulum mesh; see [Reticulum from Rust](reticulum-from-rust.md).

## Services and clients

`pigeonservice` holds the service frameworks, in Rust (`rust/src/pigeonservice`) and in Go
(`go/pigeonservice`), wire compatible with each other and with katzenpost's voucher router and
service directory plugins, whose protocol is katzenpost's `pigeonservice/common`, `voucher_router`
and `discovery`. The services built on them:

- `zulip-bridge` bridges a group with a Zulip stream (`rust/src/bin/zulip_bridge.rs`, with the
  `zulip` cargo feature; [`rust/src/services/zulip/README.md`](../rust/src/services/zulip/README.md)
  says how to run it and join).
- [`status-bot`](status-bot.md) reports on the mixnet.
- `motd`, the message of the day service in Go (`go/services/motd`, `go/cmd/motd-service`), and
  its client (`go/clients/motd`, `go/cmd/motd`).
- `gemini`, a Gemini gateway in Go (`go/services/gemini`, `go/cmd/pigeonhole-gemini-service`),
  and its client (`go/clients/gemini`, `go/cmd/pigeonhole-gemini`).
- `go/cmd/pigeonhole-echo`, an echo service, and `go/cmd/pigeonhole-voucher`, which lists the
  directory and routes a voucher to a service.

## Commands

- `go/cmd/katzenqt1` and `rust/src/bin/katzenqt1.rs` (`katzenqt1-rs`): katzenqt1 clients without
  a user interface, for scripts and interop tests.
- `go/cmd/pigeonhole-sim`: an in-memory Pigeonhole served on a unix socket.
- [`pigeonhole-cp`](pigeonhole-cp.md), [`kp-fa`](kp-fa.md) and [`ph`](ph.md): files, audio and
  byte streams over Pigeonhole.
