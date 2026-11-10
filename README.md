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
  Reticulum mesh on [berlinmesh/reticulum](https://git.emcomm.cc/berlinmesh/reticulum)
  (`reticulum_rs`, the `reticulum-rs` cargo feature; its end to end tests against the Python and
  Rust `pigeonhole_rns` replicas are in `rust/tests/reticulum_rs.rs`).
- `go/cmd/katzenqt1` and `rust/src/bin/katzenqt1.rs` (`katzenqt1-rs`): clients without a user
  interface, for scripts and interop tests; `go/cmd/pigeonhole-sim` serves an in-memory Pigeonhole.
- `rust/src/bin/pigeonhole_cp.rs` (`pigeonhole-cp`): copies a file to and from a Pigeonhole
  channel through the client daemon, like scp: `genkey` prints a channel's caps, `send` writes a
  file (through the courier's copy command, or a box at a time with `--no-copy`), and `receive`
  reads it into a directory.

- `pigeonservice`: the service frameworks, in Rust (`rust/src/pigeonservice`) and in Go (`go/pigeonservice`), wire
  compatible with each other and with katzenpost's voucher router and service directory plugins,
  whose protocol is katzenpost's `pigeonservice/common`, `voucher_router` and `discovery`;
  `zulip-bridge`, which bridges a group with a Zulip stream (`rust/src/bin/zulip_bridge.rs`, with
  the `zulip` cargo feature; `rust/src/services/zulip/README.md` says how to run it and join);
  `motd`, the message of the day service in Go (`go/services/motd`, `go/cmd/motd-service`);
  `go/cmd/pigeonhole-echo`, an echo service, and `go/cmd/pigeonhole-voucher`, which lists the
  directory and routes a voucher to a service.
  and routes a voucher to a service.
- `clients`: dialling services; `go/clients/motd` and `go/cmd/motd` fetch the message of the day.
- `services/interop`: the services, the router and the directory against a real client daemon,
  couriers and replicas, with katzenpost's localnet or a running mixnet (`THIN_CONFIG`);
  `STATUS_BOT_BIN` adds the Rust status bot, and `PIGEONHOLE_CP_BIN` pigeonhole-cp.
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

## Box sizes

A box's size is the most plaintext it holds. The transport chooses the size a client writes at:
the Reticulum transports write at `mesh`, and the mixnet transport writes at the size the client
daemon reports (Katzenpost's geometry). Apps need no setting for this. A group can span meshes and
mixnets joined by bridges, so every reader and transport accepts a box of any allowed size. Only
the payload changes with the size: box IDs (32 bytes) and signatures (64) stay the same.

| size | plaintext | padded | ciphertext | mesh write query | as a Channel message | as a Link request |
|---|---|---|---|---|---|---|
| `mesh`, written on Reticulum | 256 | 260 | 276 | 373 | 383 | 404 |
| `mixnet`, Katzenpost's | 1549 | 1553 | 1569 | 1666 | 1676 | 1697 |

- **Padding.** The padded plaintext is a big-endian u32 length, the plaintext, then zeros. BACAP
  seals it with a 16-byte tag.
- **Write query.** A mesh replica's write query is a type byte, the box ID, the signature and the
  ciphertext, so it is the plaintext size plus 117 bytes.
- **The `mesh` size.** It is computed from Reticulum's constants
  (`transport.reticulum.mesh_box_size()` in Python, `reticulum_rs::mesh_box_size` in Rust). It is
  the largest multiple of 16 for which a write fits one Link packet (431-byte MDU at the 500-byte
  MTU) with 16 bytes to spare, both as a Channel message (6-byte envelope, 4-byte frame header) and
  as a Link request (31 bytes of msgpack around the query). A read's reply is smaller.
- **Allowed sizes.** These are the two above, the size an app gives a Reticulum transport (its
  replicas' size, 1549 by default, as before), and any configured extra. Each is between 141 bytes
  (an `I` box, the smallest a substream needs) and 16384. A box of any other size is refused on
  reading. `MeshBackend(write_size=...)` writes at another size.
- **Larger boxes.** A box too long for its writer's size is written at the smallest allowed size
  that holds it. Only a voucher's first box, which is never split, does this: its payload is 373
  bytes or more.
- **Substreams.** Readers bound a substream by the 141-byte floor, so they take substreams cut to
  any size.

`testdata/box_sizes.json` (from `scripts/gen_box_sizes.py`) holds these numbers, substreams cut to
each size, and one sealed stream whose boxes are of mixed sizes. Python, Rust and Go all read it.

## Push on the mesh

On Reticulum the katzenqt1 clients wait for a box instead of polling for it, when the replica
announces push (flag bit 4 of `pigeonhole_rns`, whose README gives the wire format under Push). A
read that finds no box subscribes to it on the open Link (mode 2 op 6), and the replica pushes the
box down that Link once it is written; the client then reads it from what was pushed, with no
query. A stream waiting for a push still reads again every 5 minutes (`PUSHED_POLL_MS`), in case
the push was lost, which also renews the subscription. Against a replica that does not announce
push, and on the mixnet, the client polls as before. Both mesh transports do this (Python
`MeshBackend.watch`, Rust `Backend::watch`); applications need no change.

## Fewer boxes: packing and receipts

On a slow link such as a LoRa mesh every box costs, so the katzenqt1 engine sends fewer:

- A text message sent while the one before it still waits to be written goes into that box, as
  many as fit in the box size the transport writes (256 bytes on a mesh, 1549 on the mixnet;
  `pack_box_sizes.txt` shows both). Such a box is msg_type 12, new in version 5 of the wire,
  `[5, membership_hash, 12, [text, ...], acks, numbers, introduced_at]` with trailing nulls left
  out; version 5 is otherwise version 4, and what this client writes. A reader of version 4
  refuses msg_type 12 as a type it does not know, and with it the messages and
  acknowledgements in the box; it tells the user "~alice sent a message this app cannot show
  (type 12, version 5): update the app". A reader of version 5 does the same for any version
  above 5 or type it does not know. There is no negotiation.
  `testdata/katzenqt1/groupchat_wire_vectors_v5.json` holds the vectors.
- What a member has read is acknowledged in its next message, as before. When it has sent
  nothing 30 seconds after reading something (`ReceiptDelay`), a control message carries the
  acknowledgements alone. Boxes that carry no content, such as these, are not acknowledged on
  their own, so receipts do not answer receipts.

`Pack` and `ReceiptDelay` on the engine turn either off (`pack`, `receipt_delay` in Rust and
Python); a client writing wire version 3 or 4 never packs.

## Reticulum from Rust

The `reticulum-py` cargo feature adds `transport::reticulum_py::ReticulumPyBackend`, which puts
Pigeonhole boxes on a Reticulum mesh by embedding CPython and calling the Python mesh transport,
`py/pigeonhole_protocols/transport/reticulum.py`. Rust clients such as hushphone then join a mesh
as the Python ones do; `katzenqt1-rs --mesh CONFIG_DIR [--box-size mesh|mixnet|N]` does from the command line.

At run time the Python the crate was built against (`PYO3_PYTHON`) must import
`pigeonhole_protocols` with its `reticulum` extra, `pigeonhole_rns` and `hpqc`; a virtual
environment is found through `VIRTUAL_ENV`:

```
pip install -e "py[reticulum]" "pigeonhole-rns @ git+https://github.com/katzenpost/pigeonhole_rns" \
  "hpqc @ git+https://github.com/katzenpost/hpqc@katzenqt1-v4#subdirectory=py"
cargo test --features reticulum-py --test transport_reticulum_py
```

This suits desktops. Android needs the native Rust path, `reticulum_rs`.

## A byte stream: `ph`

`ph` (`rust/src/bin/ph.rs`, on `protocols::stream`) carries a byte stream both ways over a link:
two Pigeonhole streams, one per direction. The same code runs on the mixnet through the client
daemon (`--daemon`, `@katzenpost` by default) and on Reticulum through berlinmesh/reticulum
(`--rns HOST:PORT`, the `reticulum-rs` feature). Each box carries a flags byte, whose bit 0
ends the stream, then the bytes. A box goes out when it is full or when the input has been idle
for a few milliseconds. Several boxes are written and read ahead at once, and they are delivered
in index order. Polls stay fast while bytes are moving and back off when the link is idle.

```
cargo build --release --features reticulum-rs --bin ph
ph link new server.json              # prints a code; give it to the peer over a safe channel
ph link accept client.json CODE
ph serve --to localhost:22 server.json                        # on the server
ssh -o ProxyCommand="ph pipe client.json" host                # on the client
```

A link's state file holds both caps and the position on each stream. A link runs one session at
a time, and a session ends when both sides have closed their end. An agent holding caps and
petnames could replace the state file later.

SSH through `ph` to an sshd on the server's localhost, measured on 2026-11-05:

| | Reticulum, local replica | Reticulum, namenlos bridge | namenlos mixnet |
|---|---|---|---|
| `ssh host true` | 9.7 s | 322-498 s | 862 s |
| one keystroke, echoed | 0.31 s | 55 s | 86 s |
| scp | 100 KB in 16 s | 100 KB in 1553 s | 20 KB in 1741 s |

The scp times include the session setup. On the local replica, most of the setup is spent
waiting for the replica's announce (every 10 s there). That evening the bridge took about 10 s
to answer a query, whichever client sent it; earlier in the day it took 0.15 s. On the mixnet
the sshd needs `LoginGraceTime 0`, because setup takes longer than its 120 s default.

### Datagrams, and mosh

`ph udp` carries UDP datagrams over a link (`protocols::datagram`). Each datagram travels as a
record, a 2-byte length then the datagram, and the stream batches records into boxes. When the
link falls behind, at most 8 datagrams wait, and the oldest are dropped first. `ph mosh` runs
[mosh](https://mosh.org) over it. Mosh copes with loss and shows what you type at once (local
echo), so typing does not wait for a round trip of boxes.

```
ph udp --to 127.0.0.1:PORT server.json        # on the server, a session at a time
ph udp --listen 127.0.0.1:PORT client.json    # on the client, until interrupted
ph mosh --serve server.json                   # on the server
ph mosh client.json                           # on the client
```

For each session, `ph mosh --serve` starts `mosh-server new -i 127.0.0.1` and sends its key back
over the link. The client then runs `mosh-client` against its end of the tunnel. No SSH is
involved, so **holding the client end of the link is enough to get a shell** on the server.
Hand out the link code accordingly.

mosh through `ph mosh`, measured on 2026-11-05 (mosh 1.4.0, the default prediction mode):

| | Reticulum, local replica | Reticulum, namenlos bridge | namenlos mixnet |
|---|---|---|---|
| launch to a shell prompt | 7.7-11.5 s | 23-132 s | 449 s |
| a keystroke shows (local echo) | 0.002-0.29 s | 0.002-0.013 s | 0.01-0.02 s |
| one keystroke per line, which mosh does not predict | none slower | 12-23 s | 49 min |
| `echo word` output appears | 0.37-0.58 s | 28-32 s | not within 70 min |

In each line, mosh waits until the server has confirmed one prediction before it echoes keys
locally, so one key per line waits for a round trip. On the mixnet, mosh
sends datagrams faster than boxes are carried, so they queue and are dropped, and round trips
take minutes. Mosh suits the local replica and the bridge, but not the mixnet.

mosh-client gives up after 15 s without a reply, and mosh-server after 60 s without a client.
Over a slow link, `ph mosh` keeps the server stopped until the client's first datagram reaches
it. The first mosh-client only sends that datagram. A second one starts once the server's reply
has arrived, and it is handed that reply.

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
