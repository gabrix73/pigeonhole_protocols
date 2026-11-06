# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The mesh transport: Pigeonhole boxes over Reticulum, through the box client of
``pigeonhole_rns``. BACAP is done here with hpqc: the engine hands over a write capability, an
index and plaintext, and a sealed, signed box goes to the nearest replica heard announcing. On an
open mesh nothing else stands between the client and the replica. A box not yet written is
subscribed to on a replica serving push, which sends it down the Link once it is. Needs the
``reticulum`` extra: ``pip install pigeonhole-protocols[reticulum]``."""

from __future__ import annotations

import struct
from typing import Callable, Dict, Optional

import RNS
from pigeonhole_rns import PIGEONHOLE_CTX
from pigeonhole_rns import wire as replica_wire
from pigeonhole_rns.client import Client, pad, unpad
from pigeonhole_rns.engine import epoch_now

from ..katzenqt1.engine import DATA, NOT_FOUND, TOMBSTONE, Outcome
from .base import Backend, BoxExists, TransportError, next_index, read_position, write_position


QUERY_MODES = ("auto", "request", "channel")
# pigeonhole_rns push: announce bit 4, and mode 2 op 6, subscribe (see its README, under Push).
PUSH_FLAG = 16
SUBSCRIBE = 6


class Boxes(Client):
    """The box client with a query mode of "request" (Link requests and Resources), "channel"
    (Channel messages, only to replicas announcing it) or "auto": requests first, Channel when a
    replica announcing it does not answer them, and the mode that answered kept per replica."""

    # shortcut: overrides pigeonhole_rns's private _query; move "auto" into its Client when it grows one.
    def __init__(self, configdir: Optional[str], box_plaintext_size: int, loglevel=None, mode: str = "auto"):
        if mode not in QUERY_MODES:
            raise ValueError("mode must be one of %s" % ", ".join(QUERY_MODES))
        super().__init__(configdir, box_plaintext_size, loglevel=RNS.LOG_ERROR if loglevel is None else loglevel,
                         mode="request" if mode == "auto" else mode)
        self.auto = mode == "auto"
        self.modes: Dict[bytes, str] = {}
        # A pigeonhole_rns too old to hand pushes over has no on_push.
        self.can_push = hasattr(self.links, "on_push")
        self.links.on_push = self._on_push
        self._waiting: Dict[bytes, Callable[[], None]] = {}
        self._pushed: Dict[bytes, replica_wire.Reply] = {}

    def subscribe(self, box_id: bytes, on_box: Callable[[], None]) -> bool:
        """Subscribes to box_id on the entry replica, when it serves push, over Channel, since
        pushes come only there. on_box runs once the box is pushed, on Reticulum's thread."""
        dest = self.entry()
        if not self.can_push or dest is None or not self.links.flags.get(dest, 0) & PUSH_FLAG:
            return False
        with self._mu:
            self._waiting[box_id] = on_box
        # ttl 0 asks for the longest a replica keeps a subscription; a poll renews it.
        raw = self.links.channel_request(dest, bytes([SUBSCRIBE]) + struct.pack(">H", 0) + box_id)
        if raw is not None and len(raw) == 5 and raw[0] == replica_wire.SUCCESS and raw[1:3] != b"\0\0":
            return True
        with self._mu:
            if self._waiting.get(box_id) is on_box:
                del self._waiting[box_id]
        return False

    def _on_push(self, _ep, data: bytes) -> None:
        box_id = bytes(data[: replica_wire.BOX_ID_SIZE])
        try:
            r = replica_wire.decode_reply(bytes(data[replica_wire.BOX_ID_SIZE :]))
        except replica_wire.WireError:
            return
        with self._mu:
            on_box = self._waiting.pop(box_id, None)
            if on_box is None:
                return
            self._pushed[box_id] = r
        on_box()

    def read_box(self, box_id: bytes, dest: Optional[bytes] = None, path: str = "read") -> Optional[replica_wire.Reply]:
        with self._mu:
            r = self._pushed.pop(box_id, None)
        return r if r is not None else super().read_box(box_id, dest, path)

    def mode_of(self, dest: bytes) -> str:
        if not self.auto:
            return self.mode
        with self._mu:
            channel = dest in self.channel_replicas
        return self.modes.get(dest, "request") if channel else "request"

    def _ask(self, dest: bytes, mode: str, path: str, data: bytes) -> Optional[bytes]:
        if mode == "channel":
            return self.links.channel_request(dest, data)
        return self.links.request(dest, path, data)

    def _query(self, dest: bytes, path: str, data: bytes) -> Optional[bytes]:
        if not self.auto or path == "peek":
            return super()._query(dest, path, data)
        first = self.mode_of(dest)
        raw = self._ask(dest, first, path, data)
        if raw is not None:
            return raw
        with self._mu:
            if dest not in self.channel_replicas:
                return None
        other = "channel" if first == "request" else "request"
        raw = self._ask(dest, other, path, data)
        if raw is not None:
            RNS.log("replica %s answers in %s mode" % (dest.hex(), other), RNS.LOG_NOTICE)
            self.modes[dest] = other
        return raw


class MeshBackend(Backend):
    """``boxes`` is a ``pigeonhole_rns.client.Client``, or anything with its ``write_box``,
    ``read_box``, ``box_plaintext_size``, ``entry``, ``wait_for_replica`` and ``close``, and
    ``subscribe`` as ``Boxes`` has it for push."""

    def __init__(self, boxes):
        self.boxes = boxes

    @classmethod
    def connect(cls, configdir, box_plaintext_size: int, loglevel=None, wait: float = 60.0, mode: str = "auto") -> "MeshBackend":
        """Attach to the Reticulum instance ``configdir`` describes (a running shared instance,
        or one started here) and wait for a replica. ``mode`` is a query mode of ``Boxes``."""
        return cls.wait_for(Boxes(configdir, box_plaintext_size, loglevel=loglevel, mode=mode), wait)

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

    def watch(self, read_cap: bytes, index: bytes, on_box) -> bool:
        subscribe = getattr(self.boxes, "subscribe", None)
        if subscribe is None:
            return False
        return subscribe(read_position(read_cap, index).box_id(PIGEONHOLE_CTX), on_box)

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
