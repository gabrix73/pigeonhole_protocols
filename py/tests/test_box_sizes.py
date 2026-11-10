# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Box sizes against testdata/box_sizes.json: the mesh size's fit in one Link packet, a stream
of boxes of mixed sizes read through the mesh transport, and a group whose members write boxes
of different sizes, as one spanning a mesh and the mixnet does."""
import json
import os

import pytest

from pigeonhole_protocols.katzenqt1 import engine as eng
from pigeonhole_protocols.katzenqt1 import wire
from pigeonhole_protocols.katzenqt1.client import SyncClient
from pigeonhole_protocols.transport.base import BOX_SIZES, MAX_BOX_SIZE, MIN_BOX_SIZE, allowed_sizes, box_size, fit_size
from pigeonhole_protocols.transport.sim import SimBackend

from test_client import settle, texts

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "..", "..", "testdata", "box_sizes.json")) as f:
    V = json.load(f)


def test_sizes_match_vectors():
    assert {s["name"]: s["plaintext"] for s in V["sizes"]} == BOX_SIZES
    assert (V["min"], V["max"]) == (MIN_BOX_SIZE, MAX_BOX_SIZE) and MIN_BOX_SIZE == wire.MIN_BOX
    assert box_size("mesh") == 256 and box_size("mixnet") == 1549 and box_size("1000") == 1000 and box_size(141) == 141
    for bad in ("huge", 140, MAX_BOX_SIZE + 1, "0"):
        with pytest.raises(ValueError):
            box_size(bad)
    assert allowed_sizes(512, 256) == (256, 512, 1549)
    assert fit_size((256, 1549), 256, 200) == 256 and fit_size((256, 1549), 256, 373) == 1549
    with pytest.raises(ValueError):
        fit_size((256, 1549), 256, 1550)


def test_substreams_match_vectors():
    for c in V["substreams"]:
        size, blob = BOX_SIZES[c["size"]], bytes.fromhex(c["message"])
        boxes = [bytes.fromhex(b) for b in c["boxes"]]
        assert [wire.substream_box(blob, size, i) for i in range(wire.chunk_count(len(blob), size))] == boxes
        assert wire.assemble(boxes) == blob


def test_sealed_sizes_match_vectors():
    """Only the payload differs: a box sealed at any size has the same box ID and signature sizes."""
    pytest.importorskip("pigeonhole_rns")
    from hpqc.bacap.stateless import WriteCap
    from pigeonhole_rns import PIGEONHOLE_CTX
    from pigeonhole_rns import wire as rw
    from pigeonhole_rns.client import pad, unpad

    wc = WriteCap.generate()
    for s in V["sizes"]:
        padded = pad(bytes.fromhex(s["pad"]["plaintext"]), s["plaintext"])
        assert padded.hex() == s["pad"]["padded"] and len(padded) == s["padded"]
        box_id, ct, sig = wc.start().encrypt(PIGEONHOLE_CTX, padded)
        assert (len(box_id), len(sig), len(ct)) == (s["box_id"], s["signature"], s["ciphertext"])
        assert len(rw.encode_write(box_id, sig, ct)) == s["write_query"]
        assert unpad(wc.read_cap().start().open(PIGEONHOLE_CTX, box_id, ct, sig)) == bytes.fromhex(s["pad"]["plaintext"])


def test_mesh_size_fits_one_link_packet():
    """A write, and a read's reply, of the mesh size is one Link packet with headroom to spare,
    as a Channel message or a Link request; 16 bytes more would not be."""
    pytest.importorskip("pigeonhole_rns")
    import RNS
    from pigeonhole_rns import wire as rw

    from pigeonhole_protocols.transport.reticulum import HEADROOM, mesh_box_size

    assert mesh_box_size() == BOX_SIZES["mesh"]
    assert (V["link_mdu"], V["headroom"]) == (RNS.Link.MDU, HEADROOM)
    mesh = next(s for s in V["sizes"] if s["name"] == "mesh")
    room = RNS.Link.MDU - HEADROOM
    assert mesh["channel_message"] <= room and mesh["link_request"] <= room
    assert mesh["link_request"] + 16 > room
    reply = len(rw.encode_reply(rw.SUCCESS, bytes(mesh["signature"]), bytes(mesh["ciphertext"])))
    assert reply < mesh["write_query"]


class StoredBoxes:
    """A replica holding the vectors' boxes, as the mesh transport's box client sees it."""

    def __init__(self, boxes, size):
        from pigeonhole_rns import wire as rw

        self.box_plaintext_size = size
        self.held = {bytes.fromhex(b["box_id"]): (bytes.fromhex(b["signature"]), bytes.fromhex(b["ciphertext"])) for b in boxes}
        self.written = []
        self.rw = rw

    def read_box(self, box_id):
        sig, ct = self.held[box_id]
        return self.rw.Reply(self.rw.SUCCESS, sig, ct)

    def write_box(self, box_id, signature, ciphertext):
        self.written.append(ciphertext)
        return self.rw.SUCCESS


def test_mixed_stream_reads_every_allowed_size():
    pytest.importorskip("pigeonhole_rns")
    from pigeonhole_protocols.transport.base import TransportError, next_index
    from pigeonhole_protocols.transport.reticulum import MeshBackend

    m = V["mixed_stream"]
    rc = bytes.fromhex(m["read_cap"])
    for writer in BOX_SIZES.values():
        mesh = MeshBackend(StoredBoxes(m["boxes"], writer), m["extra_sizes"])
        index, got = rc[32:], []
        for b in m["boxes"]:
            assert index.hex() == b["index"]
            r = mesh.read_box(rc, index)
            assert r.kind == eng.DATA
            got.append(r.plaintext)
            index = r.next
        assert [g.hex() for g in got] == m["plaintexts"] and wire.assemble(got).hex() == m["message"]
    # Without the extra size its box is refused, the others still read.
    mesh = MeshBackend(StoredBoxes(m["boxes"], BOX_SIZES["mesh"]))
    index = rc[32:]
    for b in m["boxes"]:
        if b["size"] in m["extra_sizes"]:
            with pytest.raises(TransportError):
                mesh.read_box(rc, index)
        else:
            assert mesh.read_box(rc, index).kind == eng.DATA
        index = next_index(index)


def test_box_too_long_for_the_writer_goes_at_a_larger_size():
    """A voucher's box, never split, outgrows the mesh size: it is written at the smallest allowed
    size that holds it; every other box at the writer's."""
    pytest.importorskip("pigeonhole_rns")
    from hpqc.bacap.stateless import WriteCap

    from pigeonhole_protocols.transport.reticulum import MeshBackend

    boxes = StoredBoxes([], BOX_SIZES["mesh"])
    mesh = MeshBackend(boxes, (512,))
    wc = WriteCap.generate()
    index = wc.read_cap().to_bytes()[32:]
    for n in (10, 256, 257, 373, 600):
        mesh.write_box(wc.to_bytes(), index, bytes(n))
    assert [len(c) - 20 for c in boxes.written] == [256, 256, 512, 512, 1549]


def test_mesh_transport_writes_one_packet_boxes_by_default():
    """An app that names its replicas' size, as katzenrns and hushphone name 1549, writes boxes of
    the mesh size and reads both; write_size chooses another."""
    pytest.importorskip("pigeonhole_rns")
    from hpqc.bacap.stateless import WriteCap

    from pigeonhole_protocols.transport.reticulum import MeshBackend

    wc = WriteCap.generate()
    index = wc.read_cap().to_bytes()[32:]
    for kw, want in (({}, 256), ({"write_size": "mixnet"}, 1549)):
        boxes = StoredBoxes([], 1549)
        mesh = MeshBackend(boxes, **kw)
        mesh.write_box(wc.to_bytes(), index, b"hi")
        assert mesh.max_plaintext() == want and len(boxes.written[0]) - 20 == want and mesh.sizes == (256, 1549)


def mixed_group(tmp_path, alice_size, bob_size):
    """alice writing boxes of alice_size and bob of bob_size join a group and send each other
    a long text and a file; returns the sizes of the boxes each wrote after joining."""
    sim = SimBackend(max_plaintext=alice_size)
    clock = [0]
    backends = {"alice": sim, "bob": sim.view(bob_size)}

    def make(name):
        return SyncClient(str(tmp_path / name), name, backends[name], clock=clock)

    alice, bob = make("alice"), make("bob")
    alice.start()
    bob.start()
    alice.feed(eng.Create("g", "g"))
    bob.feed(eng.Join("g", "g"))
    settle([alice, bob], 10_000)
    code = open(os.path.join(bob.store.dir, "voucher-g.txt")).read().strip()
    alice.feed(eng.Induct("g", code))
    settle([alice, bob], 60_000)
    joined = set(sim.boxes)
    text = "a long message " * 100
    data = bytes(i % 251 for i in range(5000))
    for c, name in ((alice, "alice"), (bob, "bob")):
        c.feed(eng.Send("g", text))
        c.feed(eng.SendFile("g", name + ".bin", data))
        settle([alice, bob], 120_000)
    for c, other in ((alice, "bob"), (bob, "alice")):
        assert "%s: %s" % (other, text) in texts(c, "g")
        got = [l.attachment for l in c.lines("g") if l.attachment is not None and l.attachment.name == other + ".bin"][0]
        assert open(os.path.join(c.store.dir, got.file), "rb").read() == data
    new = [p for k, (_, p) in sim.boxes.items() if k not in joined]
    for c in (alice, bob):
        c.close()
    return [len(p) for p in new]


def test_group_across_box_sizes(tmp_path):
    """A member on a mesh writes boxes of the mesh size, one on the mixnet of the mixnet's, and
    each reads the other's messages and files: substreams cut to either size."""
    sizes = mixed_group(tmp_path, BOX_SIZES["mesh"], BOX_SIZES["mixnet"])
    assert max(sizes) > BOX_SIZES["mesh"] and sum(1 for n in sizes if n == BOX_SIZES["mesh"]) > 15
