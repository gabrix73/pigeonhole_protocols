# ph: a byte stream over Pigeonhole

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

## Datagrams, and mosh

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
