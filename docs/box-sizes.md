# Box sizes

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
  replicas' size, 1549 by default), and any configured extra. Each is between 141 bytes (an `I`
  box, the smallest a substream needs) and 16384. A box of any other size is refused on reading.
  `MeshBackend(write_size=...)` writes at another size.
- **Larger boxes.** A box too long for its writer's size is written at the smallest allowed size
  that holds it. Only a voucher's first box, which is never split, does this: its payload is 373
  bytes or more.
- **Substreams.** Readers bound a substream by the 141-byte floor, so they take substreams cut to
  any size.

[`testdata/box_sizes.json`](../testdata/box_sizes.json) (from `scripts/gen_box_sizes.py`) holds
these numbers, substreams cut to each size, and one sealed stream whose boxes are of mixed sizes.
Python, Rust and Go all read it.
