# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The mesh transport: Pigeonhole boxes over Reticulum, through the box client of
``pigeonhole_rns``. BACAP is done here with hpqc: the engine hands over a write capability, an
index and plaintext, and a sealed, signed box goes to the nearest replica heard announcing. On an
open mesh nothing else stands between the client and the replica. Needs the ``reticulum`` extra:
``pip install pigeonhole-protocols[reticulum]``."""

from __future__ import annotations

from pigeonhole_rns import PIGEONHOLE_CTX
from pigeonhole_rns import wire as replica_wire
from pigeonhole_rns.client import pad, unpad
from pigeonhole_rns.engine import epoch_now

from ..katzenqt1.engine import DATA, NOT_FOUND, TOMBSTONE, Outcome
from .base import Backend, BoxExists, TransportError, next_index, read_position, write_position


class MeshBackend(Backend):
    """``boxes`` is a ``pigeonhole_rns.client.Client``, or anything with its ``write_box``,
    ``read_box``, ``box_plaintext_size``, ``entry``, ``wait_for_replica`` and ``close``."""

    def __init__(self, boxes):
        self.boxes = boxes

    @classmethod
    def connect(cls, configdir, box_plaintext_size: int, loglevel=None, wait: float = 60.0) -> "MeshBackend":
        """Attach to the Reticulum instance ``configdir`` describes (a running shared instance,
        or one started here) and wait for a replica."""
        import RNS
        from pigeonhole_rns.client import Client as BoxClient

        return cls.wait_for(BoxClient(configdir, box_plaintext_size, loglevel=RNS.LOG_ERROR if loglevel is None else loglevel), wait)

    @classmethod
    def wait_for(cls, boxes, wait: float = 60.0) -> "MeshBackend":
        """Wait for a replica on an attached client. Starting Reticulum installs signal
        handlers, which only the main thread may do; this part may run on any thread."""
        if not boxes.wait_for_replica(timeout=wait):
            boxes.close()
            raise TransportError("no Pigeonhole replica heard on the mesh")
        return cls(boxes)

    def write_box(self, write_cap: bytes, index: bytes, plaintext: bytes) -> None:
        pos = write_position(write_cap, index)
        if plaintext:
            box_id, ciphertext, signature = pos.encrypt(PIGEONHOLE_CTX, pad(plaintext, self.boxes.box_plaintext_size))
        else:
            box_id, signature = pos.tombstone(PIGEONHOLE_CTX)
            ciphertext = b""
        code = self.boxes.write_box(box_id, signature, ciphertext)
        if code is None:
            raise TransportError("no replica answered")
        if code == replica_wire.SUCCESS:
            return
        if code in (replica_wire.ALREADY_EXISTS, replica_wire.TOMBSTONE):
            # The replica holds other bytes, or a tombstone where data was written.
            raise BoxExists()
        raise TransportError("replica error %d" % code)

    def read_box(self, read_cap: bytes, index: bytes) -> Outcome:
        pos = read_position(read_cap, index)
        box_id = pos.box_id(PIGEONHOLE_CTX)
        r = self.boxes.read_box(box_id)
        if r is None:
            raise TransportError("no replica answered")
        if r.code == replica_wire.NOT_FOUND:
            return Outcome(NOT_FOUND)
        if r.code == replica_wire.TOMBSTONE:
            return Outcome(TOMBSTONE, b"", next_index(index))
        if r.code != replica_wire.SUCCESS:
            raise TransportError("replica error %d" % r.code)
        try:
            plaintext = unpad(pos.open(PIGEONHOLE_CTX, box_id, r.ciphertext or b"", r.signature or b""))
        except Exception as e:
            raise TransportError("box did not open: %s" % e)
        return Outcome(DATA, plaintext, next_index(index))

    def replica_epoch(self) -> int:
        """Mesh replicas keep the Katzenpost replica epoch: a week, counted from the Katzenpost
        epoch, so a bridged box is in the same epoch on both sides."""
        return epoch_now()

    def max_plaintext(self) -> int:
        return self.boxes.box_plaintext_size

    def where(self) -> str:
        """The entry replica, for a log line."""
        from pigeonhole_rns import rnsio

        d = self.boxes.entry()
        return "replica %s, %d hops" % (d.hex(), rnsio.hops(d)) if d else "no replica reachable"

    def close(self) -> None:
        self.boxes.close()
