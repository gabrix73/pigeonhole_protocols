# pigeonhole-protocols

The Python implementation of the protocols in this repository, beside Go and Rust: the
katzenqt1 group chat as a sans-IO member, an engine that is a whole client without IO, and a
client that carries the engine's work out over a transport and keeps its state in SQLite.

- `pigeonhole_protocols/katzenqt1/member`: katzenqt's own group chat state machine, copied
  unchanged from `src/katzenqt/groupchat` (`member/SOURCES` names the commit), so cryptlib's
  proofs and trace replay are about this code.
- `katzenqt1/wire.py`: the GroupChatMessage CBOR, box framing, membership hash and the reply
  to a new member, byte for byte as katzenqt writes them.
- `katzenqt1/engine.py`: the client without IO, after the Go `engine` package: `step` takes one
  input and returns files to keep, what changed and the network work to start.
- `katzenqt1/store.py`, `katzenqt1/client.py`: state on disk, and the engine run over a
  transport on threads, or in virtual time for tests (`SyncClient`).
- `transport/base.py`: what a client asks of Pigeonhole; `transport/sim.py` an in-memory
  Pigeonhole with real BACAP. A transport does the BACAP encryption with hpqc; the engine never
  sees a ciphertext. katzenrns adds the Reticulum transport.
- `katzenqt1/tracejson.py`, `katzenqt1/scenario.py`: replay of recorded member traces, and
  the client scenario runner.

Messages larger than one box, which katzenqt writes to a substream, are not sent yet.

## Install and test

    pip install -e py[test]
    cd py && pytest

The tests run the shared `testdata/katzenqt1`: the wire and acks vectors, the 14 member
scenarios through the member's simulator, the 21 recorded traces through the member, and the
client scenarios (`go/protocols/katzenqt1/client/testdata/scenarios` and
`testdata/katzenqt1/client_scenarios`) over the in-memory Pigeonhole in virtual time.

`scripts/verify-member.sh KATZENQT` checks the copied member against a katzenqt checkout at the
commit `member/SOURCES` names.
