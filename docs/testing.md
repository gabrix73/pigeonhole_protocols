# Testing

```
make test rust-test        # unit tests, scenarios, crashes at every action, kill -9
make py-test               # the Python package
make verify-testdata       # the vectors are as copied
make conformance           # against katzenqt and Lean's model: fresh traces both ways
make rust-conformance
make e2e DAEMON=@katzenpost       # two clients over a running client daemon
make interop DAEMON=@katzenpost   # with katzenqt-headless
```

The cross-checks need checkouts of katzenqt (`KATZENQT`) and cryptlib (`CRYPTLIB`). Setting
`RUST_BIN` to `target/release/katzenqt1-rs` runs the process tests with Go and Rust clients
together.

`go/services/interop` runs the services, the voucher router and the service directory against a
real client daemon, couriers and replicas: katzenpost's localnet by default, or a running mixnet
whose thin client config `THIN_CONFIG` names. It also runs [kp-fa](kp-fa.md); `STATUS_BOT_BIN`
adds the Rust [status bot](status-bot.md), and `PIGEONHOLE_CP_BIN` [pigeonhole-cp](pigeonhole-cp.md).
Each test makes real CTIDH replicas of its own, so give it a long timeout:

```
cd go && go test -v -timeout 75m ./services/interop/
```

[`testdata/`](../testdata) holds vectors shared with cryptlib, katzenqt and group_chat_client;
`testdata/SOURCES` names the commits they were copied from.
`go/protocols/katzenqt1/client/testdata/scenarios` holds this repository's own client scenarios,
which the Go and Rust clients both run.
