# pigeonhole

Protocols over Katzenpost's Pigeonhole storage, in Go, Rust and Python: group communication among peers under `protocols/`, and mixnet services (responders) and their clients (initiators) under `services/` and `clients/`.

Each protocol under `protocols/` has a sans-IO state machine, an engine that is a whole client
without IO, and a client that carries the engine's work out over a transport and keeps its state
on disk. Every step's changes are saved, synced, before any of the work it asks for starts.

- `protocols/katzenqt1`: katzenqt's group chat as of October 2026.
  - `wire`: message fields, GroupChatMessage CBOR, box framing, the reply to a new member, files.
  - `member`: one member of a group, as a state machine; its trace format, and katzenqt's
    scenario simulator.
  - `engine`: the client without IO.
  - `store`: its state, in bbolt; in Rust, redb, as a module of the client crate.
  - `client`: the client, over a transport.
- `transport`: what a client asks of Pigeonhole; over the client daemon's thin client, in memory
  for tests, and served from one process to others (`remote`, JSON-RPC).
- `cmd/katzenqt1` (Go) and `src/bin/katzenqt1.rs` (`katzenqt1-rs`): clients without a user
  interface, for scripts and interop tests; `cmd/pigeonhole-sim` serves an in-memory Pigeonhole.

- `services`: the service frameworks, in Rust (`src/services`) and in Go (`pigeonservice`), wire
  compatible with each other and with katzenpost's voucher router and service directory plugins,
  whose protocol is katzenpost's `pigeonservice/common`, `voucher_router` and `discovery`;
  `eliza`, an ELIZA bot katzenqt users talk to by pasting one of its vouchers (`src/bin/eliza.rs`);
  `zulip-bridge`, which bridges a group with a Zulip stream (`src/bin/zulip_bridge.rs`, with the
  `zulip` cargo feature; `services/zulip/README.md` says how to run it and join);
  `motd`, the message of the day service in Go (`services/motd`, `cmd/motd-service`);
  `cmd/pigeonhole-echo`, an echo service, and `cmd/pigeonhole-voucher`, which lists the directory
  and routes a voucher to a service.
- `clients`: dialling services; `clients/motd` and `cmd/motd` fetch the message of the day.
- `services/interop`: the services, the router and the directory against a real client daemon,
  couriers and replicas, with katzenpost's localnet or a running mixnet (`THIN_CONFIG`);
  `ELIZA_BIN` adds the Rust bot.
  `cmd/pigeonservice-vectors` writes `testdata/services/vectors.json`, which the Rust framework
  checks itself against. `TestZulipBridge` runs the bridge when `ZULIP_BRIDGE_BIN`, `ZULIPRC` (the bot's)
  and `ZULIPRC_USER` (a member's) are set.

`examples/` has a minimal group chat in Go and in Rust, as an introduction to the client.

Go is at the root; Rust is one crate, `pigeonhole_protocols`, with `Cargo.toml` at the top and its source in `src/`; Python is the package `pigeonhole-protocols` under `py/` (see `py/README.md`), which katzenrns builds its Reticulum client on. `testdata/` holds vectors shared with cryptlib, katzenqt and
group_chat_client; `SOURCES` names the commits they were copied from.
`protocols/katzenqt1/client/testdata/scenarios` holds this repository's own client scenarios,
which the Go and Rust clients both run.

## Testing

```
make test rust-test        # unit tests, scenarios, crashes at every action, kill -9
make verify-testdata       # the vectors are as copied
make conformance           # against katzenqt and Lean's model: fresh traces both ways
make rust-conformance
make e2e DAEMON=@katzenpost       # two clients over a running client daemon
make interop DAEMON=@katzenpost   # with katzenqt-headless
```

The cross-checks need checkouts of katzenqt (`KATZENQT`) and cryptlib (`CRYPTLIB`). Setting
`RUST_BIN` to `target/release/katzenqt1-rs` runs the process tests with Go and Rust clients
together.
