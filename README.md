# pigeonhole

Protocols over Katzenpost's Pigeonhole storage, in Go (`go/`), Rust (`rust/`) and Python (`py/`): group communication among peers under `protocols/`, and mixnet services (responders) and their clients (initiators) under `services/` and `clients/`.

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
  for tests, and served from one process to others (`remote`, JSON-RPC); in Rust also over a
  Reticulum mesh on Reticulum-rs (`reticulum_rs`, the `reticulum-rs` cargo feature; its end to
  end test against a `pigeonhole_rns` replica is in `rust/tests/reticulum_rs.rs`).
- `go/cmd/katzenqt1` and `rust/src/bin/katzenqt1.rs` (`katzenqt1-rs`): clients without a user
  interface, for scripts and interop tests; `go/cmd/pigeonhole-sim` serves an in-memory Pigeonhole.

- `pigeonservice`: the service frameworks, in Rust (`rust/src/pigeonservice`) and in Go (`go/pigeonservice`), wire
  compatible with each other and with katzenpost's voucher router and service directory plugins,
  whose protocol is katzenpost's `pigeonservice/common`, `voucher_router` and `discovery`;
  `zulip-bridge`, which bridges a group with a Zulip stream (`rust/src/bin/zulip_bridge.rs`, with
  the `zulip` cargo feature; `rust/src/services/zulip/README.md` says how to run it and join);
  `motd`, the message of the day service in Go (`go/services/motd`, `go/cmd/motd-service`);
  `gemini`, an offline Gemini (`gemini://`) gateway service in Go (`go/services/gemini`, `go/cmd/pigeonhole-gemini-service`);
  `go/cmd/pigeonhole-echo`, an echo service, and `go/cmd/pigeonhole-voucher`, which lists the
  directory and routes a voucher to a service.
- `clients`: dialling services; `go/clients/motd` and `go/cmd/motd` fetch the message of the day;
  `go/clients/gemini` and `go/cmd/pigeonhole-gemini` fetch Gemini capsules offline over Pigeonhole.
- `services/interop`: the services, the router and the directory against a real client daemon,
  couriers and replicas, with katzenpost's localnet or a running mixnet (`THIN_CONFIG`);
  `STATUS_BOT_BIN` adds the Rust status bot.
  `zulip-bridge`, which bridges a group with a Zulip stream (`rust/src/bin/zulip_bridge.rs`, with
  the `zulip` cargo feature; `rust/src/services/zulip/README.md` says how to run it and join);
  `motd`, the message of the day service in Go (`go/services/motd`, `go/cmd/motd-service`);
  `go/cmd/pigeonhole-echo`, an echo service, and `go/cmd/pigeonhole-voucher`, which lists the
  directory and routes a voucher to a service.

`examples/` has a minimal group chat in Go and in Rust, as an introduction to the client.

Each language is a directory of its own: `go/` is the Go module `github.com/katzenpost/pigeonhole_protocols/go`; `rust/` is one crate, `pigeonhole_protocols`; `py/` is the package `pigeonhole-protocols` (see `py/README.md`), which katzenrns builds its Reticulum client on. `testdata/` holds vectors shared with cryptlib, katzenqt and
group_chat_client; `SOURCES` names the commits they were copied from.
`go/protocols/katzenqt1/client/testdata/scenarios` holds this repository's own client scenarios,
which the Go and Rust clients both run.

## Reticulum from Rust

The `reticulum-py` cargo feature adds `transport::reticulum_py::ReticulumPyBackend`, which puts
Pigeonhole boxes on a Reticulum mesh by embedding CPython and calling the Python mesh transport,
`py/pigeonhole_protocols/transport/reticulum.py`. Rust clients such as hushphone then join a mesh
as the Python ones do; `katzenqt1-rs --mesh CONFIG_DIR [--box-size N]` does from the command line.

At run time the Python the crate was built against (`PYO3_PYTHON`) must import
`pigeonhole_protocols` with its `reticulum` extra, `pigeonhole_rns` and `hpqc`; a virtual
environment is found through `VIRTUAL_ENV`:

```
pip install -e "py[reticulum]" "pigeonhole-rns @ git+https://github.com/katzenpost/pigeonhole_rns" \
  "hpqc @ git+https://github.com/katzenpost/hpqc@katzenqt1-v4#subdirectory=py"
cargo test --features reticulum-py --test transport_reticulum_py
```

This suits desktops. Android needs the native path through Reticulum-rs.

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
