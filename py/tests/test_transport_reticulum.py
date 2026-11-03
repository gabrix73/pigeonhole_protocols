# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The mesh transport over a stand-in for the Reticulum box client: BACAP is done here, and
each replica result code maps to the outcome the engine expects."""
import pytest

pytest.importorskip("pigeonhole_rns")

from pigeonhole_rns import wire as rw  # noqa: E402
from hpqc.bacap.stateless import WriteCap  # noqa: E402

from pigeonhole_protocols.katzenqt1.engine import DATA, NOT_FOUND, TOMBSTONE  # noqa: E402
from pigeonhole_protocols.transport.base import BoxExists, TransportError  # noqa: E402
from pigeonhole_protocols.transport.reticulum import MeshBackend  # noqa: E402


class FakeBoxes:
    """Stores boxes by Box ID as a replica would, verifying nothing; the transport verifies."""

    def __init__(self, size=200):
        self.box_plaintext_size = size
        self.boxes = {}
        self.answer = True
        self.closed = False

    def write_box(self, box_id, signature, ciphertext):
        if not self.answer:
            return None
        if box_id in self.boxes:
            return rw.SUCCESS if self.boxes[box_id] == (signature, ciphertext) else rw.ALREADY_EXISTS
        self.boxes[box_id] = (signature, ciphertext)
        return rw.SUCCESS

    def read_box(self, box_id):
        if not self.answer:
            return None
        if box_id not in self.boxes:
            return rw.Reply(rw.NOT_FOUND)
        sig, ct = self.boxes[box_id]
        if not ct:
            return rw.Reply(rw.TOMBSTONE)
        return rw.Reply(rw.SUCCESS, sig, ct)

    def close(self):
        self.closed = True

    def entry(self):
        return None

    def wait_for_replica(self, timeout):
        return self.answer


def test_write_read_tombstone():
    boxes = FakeBoxes()
    be = MeshBackend(boxes)
    kp = be.new_keypair()
    assert be.max_plaintext() == 200
    assert be.read_box(kp.read_cap, kp.first).kind == NOT_FOUND
    be.write_box(kp.write_cap, kp.first, b"hello")
    (sig, ct), = boxes.boxes.values()
    assert len(ct) == 200 + 4 + 16 and len(sig) == 64, "padded to the box size, then sealed"
    out = be.read_box(kp.read_cap, kp.first)
    assert out.kind == DATA and out.plaintext == b"hello" and out.next is not None
    be.write_box(kp.write_cap, kp.first, b"hello")  # the same bytes again: fine
    with pytest.raises(BoxExists):
        be.write_box(kp.write_cap, kp.first, b"other")
    be.write_box(kp.write_cap, out.next, b"")
    assert be.read_box(kp.read_cap, out.next).kind == TOMBSTONE
    assert 400 < be.replica_epoch() < 10000, "weeks since the Katzenpost epoch"
    be.close()
    assert boxes.closed


def test_silence_and_errors_are_transport_errors():
    boxes = FakeBoxes()
    be = MeshBackend(boxes)
    kp = be.new_keypair()
    boxes.answer = False
    with pytest.raises(TransportError):
        be.write_box(kp.write_cap, kp.first, b"x")
    with pytest.raises(TransportError):
        be.read_box(kp.read_cap, kp.first)
    boxes.answer = True
    be.write_box(kp.write_cap, kp.first, b"x")
    box_id = next(iter(boxes.boxes))
    sig, ct = boxes.boxes[box_id]
    boxes.boxes[box_id] = (sig, ct[:-1] + bytes([ct[-1] ^ 1]))
    with pytest.raises(TransportError):
        be.read_box(kp.read_cap, kp.first)
    other = WriteCap.generate()
    assert be.read_box(other.read_cap().to_bytes(), other.read_cap().to_bytes()[32:]).kind == NOT_FOUND


def test_wait_for_and_where():
    boxes = FakeBoxes()
    be = MeshBackend.wait_for(boxes, wait=1)
    assert be.where() == "no replica reachable"
    silent = FakeBoxes()
    silent.answer = False
    with pytest.raises(TransportError):
        MeshBackend.wait_for(silent, wait=1)
    assert silent.closed
