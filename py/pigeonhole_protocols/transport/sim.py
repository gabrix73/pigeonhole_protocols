# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""An in-memory Pigeonhole with real BACAP, for tests: boxes by Box ID,
each the epoch it was stored in and its plaintext, empty for a tombstone.
The rules are the Go simulator's: a box is kept through the epoch after
the one it was written in, and a matching write stores nothing."""

from __future__ import annotations

import threading
from typing import Dict, List, Optional, Tuple

from hpqc.bacap.stateless import MessageBoxIndex, ReadCap, WriteCap

from ..katzenqt1.engine import DATA, NOT_FOUND, TOMBSTONE, Outcome
from .base import Backend, BoxExists, TransportError, next_index

CTX = b"pigeonhole context"


def _box_id(cap: type, cap_bytes: bytes, index: bytes) -> bytes:
    # The engine's indexes are on the stream, so the check that walks the ratchet there from
    # the cap's start is skipped: over a long substream it is quadratic.
    return cap.from_bytes(cap_bytes).with_message_box_index(MessageBoxIndex.from_bytes(index)).start().box_id(CTX)


class SimBackend(Backend):
    """``fail_next`` holds kinds ("read", "write") whose next call fails,
    once each."""

    def __init__(self, max_plaintext: int = 1000, epoch: int = 1):
        self.boxes: Dict[bytes, Tuple[int, bytes]] = {}
        self.epoch = epoch
        self._max = max_plaintext
        self.fail_next: set = set()
        self.failing_writes = 0
        self.writes = 0
        self.reads = 0
        self.refused: List[Tuple[bytes, int]] = []
        """Each write refused for its box holding other bytes: the stream's
        key and the box's Idx64."""
        self._mu = threading.Lock()

    def fail_writes(self, n: int) -> None:
        """The next n writes fail."""
        self.failing_writes = n

    def _maybe_fail(self, what: str) -> None:
        if what in self.fail_next:
            self.fail_next.discard(what)
            raise TransportError("injected")
        if what == "write" and self.failing_writes > 0:
            self.failing_writes -= 1
            raise TransportError("injected")

    def _kept(self, epoch: int) -> bool:
        """A box lives through the epoch it was written in and the next, as
        on the replicas."""
        return epoch + 1 >= self.epoch

    def write_box(self, write_cap: bytes, index: bytes, plaintext: bytes) -> None:
        with self._mu:
            self._maybe_fail("write")
            if len(plaintext) > self._max:
                raise TransportError("box too large")
            self.writes += 1
            box_id = _box_id(WriteCap, write_cap, index)
            old = self.boxes.get(box_id)
            if old is not None and self._kept(old[0]) and plaintext:
                if old[1] == plaintext:
                    # A matching write stores nothing: the box keeps the epoch it was first stored in.
                    return
                self.refused.append((WriteCap.from_bytes(write_cap).read_cap().to_bytes()[:32], MessageBoxIndex.from_bytes(index).idx_64))
                raise BoxExists()
            self.boxes[box_id] = (self.epoch, plaintext)

    def clobber(self, write_cap: bytes, index: bytes, plaintext: bytes) -> None:
        """Fill a box with other bytes, as another client writing the stream would."""
        with self._mu:
            self.boxes[_box_id(WriteCap, write_cap, index)] = (self.epoch, plaintext)

    def read_box(self, read_cap: bytes, index: bytes) -> Outcome:
        with self._mu:
            self._maybe_fail("read")
            self.reads += 1
            box_id = _box_id(ReadCap, read_cap, index)
            b = self.boxes.get(box_id)
            if b is None or not self._kept(b[0]):
                return Outcome(NOT_FOUND)
            if not b[1]:
                return Outcome(TOMBSTONE, b"", next_index(index))
            return Outcome(DATA, b[1], next_index(index))

    def replica_epoch(self) -> int:
        return self.epoch

    def max_plaintext(self) -> int:
        return self._max
