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


# Query modes: requests first, Channel for a replica announcing it when requests go unanswered.
from pigeonhole_protocols.transport.reticulum import Boxes  # noqa: E402
import threading  # noqa: E402

A, B = b"a" * 16, b"b" * 16


class Links:
    def __init__(self, request_ok, channel_ok):
        self.ok = {"request": request_ok, "channel": channel_ok}
        self.asked = []

    def request(self, dest, path, data):
        self.asked.append((dest, "request"))
        return b"r" if dest in self.ok["request"] else None

    def channel_request(self, dest, data):
        self.asked.append((dest, "channel"))
        return b"c" if dest in self.ok["channel"] else None


def boxes(mode, links, channel_replicas):
    b = Boxes.__new__(Boxes)
    b.mode = "request" if mode == "auto" else mode
    b.auto = mode == "auto"
    b.modes = {}
    b._mu = threading.Lock()
    b.channel_replicas = set(channel_replicas)
    b.links = links
    return b


def test_auto_prefers_requests():
    links = Links({A}, {A})
    assert boxes("auto", links, {A})._query(A, "read", b"q") == b"r"
    assert links.asked == [(A, "request")]


def test_auto_falls_back_to_channel_and_keeps_it():
    links = Links(set(), {A})
    b = boxes("auto", links, {A})
    assert b._query(A, "write", b"q") == b"c"
    assert b._query(A, "read", b"q") == b"c"
    assert links.asked == [(A, "request"), (A, "channel"), (A, "channel")]
    assert b.mode_of(A) == "channel"


def test_auto_keeps_mode_per_replica():
    links = Links({B}, {A})
    b = boxes("auto", links, {A, B})
    assert b._query(A, "read", b"q") == b"c"
    assert b._query(B, "read", b"q") == b"r"
    assert b.mode_of(B) == "request"


def test_auto_never_channels_to_a_replica_not_announcing_it():
    links = Links(set(), {B})
    assert boxes("auto", links, set())._query(B, "read", b"q") is None
    assert links.asked == [(B, "request")]


def test_fixed_modes():
    links = Links({A}, {A})
    assert boxes("channel", links, {A})._query(A, "read", b"q") == b"c"
    assert boxes("request", links, {A})._query(A, "read", b"q") == b"r"


def test_bad_mode():
    with pytest.raises(ValueError):
        Boxes(None, 100, mode="resource")


# Push: a box not yet written is subscribed to on a replica announcing bit 4, and handed over
# when pushed; elsewhere the client polls.
from pigeonhole_protocols.katzenqt1 import client as kc  # noqa: E402
from pigeonhole_protocols.katzenqt1 import engine as eng  # noqa: E402
from pigeonhole_protocols.transport.reticulum import PUSH_FLAG  # noqa: E402


class PushLinks:
    def __init__(self, flags, taken=1):
        self.flags = {A: flags}
        self.taken = taken
        self.sent = []
        self.on_push = None

    def channel_request(self, dest, data):
        self.sent.append(data)
        return bytes([rw.SUCCESS]) + self.taken.to_bytes(2, "big") + (3600).to_bytes(2, "big")


def push_boxes(flags, taken=1):
    b = boxes("auto", PushLinks(flags, taken), {A})
    b.can_push = True
    b._waiting, b._pushed = {}, {}
    b.entry = lambda: A
    return b


def test_subscribe_and_push():
    b = push_boxes(2 | PUSH_FLAG)
    box_id = b"i" * 32
    got = []
    assert b.subscribe(box_id, lambda: got.append(1))
    assert b.links.sent == [bytes([6, 0, 0]) + box_id], "op 6, ttl 0 for the longest, the Box ID"
    b._on_push(None, b"j" * 32 + bytes([rw.SUCCESS]) + b"s" * 64 + b"c")
    assert got == [], "a box not waited for"
    b._on_push(None, box_id + bytes([rw.SUCCESS]) + b"s" * 64 + b"c")
    assert got == [1]
    r = b.read_box(box_id)
    assert (r.code, r.signature, r.ciphertext) == (rw.SUCCESS, b"s" * 64, b"c"), "read with no query"
    b._on_push(None, box_id + bytes([rw.SUCCESS]) + b"s" * 64 + b"c")
    assert got == [1], "a push is taken once"


def test_no_subscribe_without_push():
    b = push_boxes(2)
    assert not b.subscribe(b"i" * 32, lambda: None)
    assert b.links.sent == []
    refused = push_boxes(2 | PUSH_FLAG, taken=0)
    assert not refused.subscribe(b"i" * 32, lambda: None)
    assert refused._waiting == {}
    assert not MeshBackend(FakeBoxes()).watch(b"", b"", lambda: None), "a box client without subscribe"


class Watching(MeshBackend):
    def __init__(self, push):
        super().__init__(FakeBoxes())
        self.push, self.on_box = push, None

    def watch(self, read_cap, index, on_box):
        self.on_box = on_box
        return self.push


def test_wake_comes_with_the_push():
    for push in (False, True):
        be = Watching(push)
        kp = be.new_keypair()
        x = kc.Executor(be, remove=lambda f: None, sleep=lambda ms: None)
        r = x.perform(eng.DoRead("c", b"s", kp.read_cap, kp.first))
        assert r.input.outcome.kind == NOT_FOUND
        w = x.perform(eng.DoWake("c", b"s", 4000))
        if not push:
            assert (w.after_ms, w.until) == (4000, None), "polls as the engine says"
            continue
        assert w.after_ms == kc.PUSHED_POLL_MS and not w.until.is_set(), "a slow poll in case the push is lost"
        be.on_box()
        assert w.until.is_set()
        assert x.perform(eng.DoWake("c", b"s", 4000)).until is None, "one wake per miss"
