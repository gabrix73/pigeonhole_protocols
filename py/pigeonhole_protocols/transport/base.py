# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""What a group protocol's client asks of Pigeonhole: boxes on streams, and
the contact vouchers a new member joins through. Caps and indexes are
BACAP's binary forms; a client steps from one index to the next itself, by
BACAP. The Go and Rust transport packages define the same interface."""

from __future__ import annotations

from typing import Callable, Tuple

from hpqc.bacap.stateless import MessageBoxIndex, ReadCap, WriteCap
from hpqc.voucher import api as voucher

from ..katzenqt1.engine import Inducted, Keypair, Minted, Opened, Outcome

INDEX_SIZE = 104


class BoxExists(Exception):
    """A write to a box that holds something else."""


class TransportError(Exception):
    """A call that may succeed if tried again."""


def next_index(index: bytes) -> bytes:
    return MessageBoxIndex.from_bytes(index).next_index().to_bytes()


def derive(start: bytes, count: int) -> Tuple[bytes, ...]:
    """The count indexes after start."""
    i = MessageBoxIndex.from_bytes(start)
    out = []
    for _ in range(count):
        i = i.next_index()
        out.append(i.to_bytes())
    return tuple(out)


def write_position(write_cap: bytes, index: bytes):
    return WriteCap.from_bytes(write_cap).position_at(MessageBoxIndex.from_bytes(index))


def read_position(read_cap: bytes, index: bytes):
    return ReadCap.from_bytes(read_cap).position_at(MessageBoxIndex.from_bytes(index))


class Backend:
    """Boxes and vouchers. Every call may fail with TransportError; a caller
    that must succeed retries. Vouchers are pure computation, the same over
    any transport, so they are implemented here once."""

    def new_keypair(self) -> Keypair:
        wc = WriteCap.generate()
        rc = wc.read_cap()
        return Keypair(wc.to_bytes(), rc.to_bytes(), rc.to_bytes()[32:])

    def write_box(self, write_cap: bytes, index: bytes, plaintext: bytes) -> None:
        """An empty plaintext is a tombstone. Writing again what a box holds
        succeeds; writing anything else raises BoxExists."""
        raise NotImplementedError

    def read_box(self, read_cap: bytes, index: bytes) -> Outcome:
        """What the box holds, reporting at once a box not written."""
        raise NotImplementedError

    def watch(self, read_cap: bytes, index: bytes, on_box: Callable[[], None]) -> bool:
        """Asks to be told when the box at index is written: on_box runs once, on any thread,
        and reading the box after it needs no query. False when this transport cannot push,
        and the caller polls."""
        return False

    def replica_epoch(self) -> int:
        """The storage replicas' current epoch."""
        raise NotImplementedError

    def max_plaintext(self) -> int:
        """The most a box holds."""
        raise NotImplementedError

    def voucher_mint(self, write_cap: bytes, name: str, version: int = 2) -> Minted:
        """``version`` is the payload's form: 2 the compact array, 1 the signed map."""
        # An hpqc without the compact form takes no version and mints the map form.
        m = voucher.voucher_mint(write_cap, name, version=1) if version == 1 else voucher.voucher_mint(write_cap, name)
        return Minted(m.voucher, m.voucher_payload, m.voucher_write_cap, m.voucher_read_cap, m.voucher_secret_key, getattr(m, "version", 1))

    def voucher_derive_stream(self, v: bytes) -> Tuple[bytes, bytes]:
        s = voucher.derive_voucher_stream(v)
        return s.voucher_write_cap, s.voucher_read_cap

    def voucher_induct(self, v: bytes, payload: bytes, who_reply: bytes) -> Inducted:
        r = voucher.voucher_induct(v, payload, who_reply)
        return Inducted(r.display_name, r.mutated_message_read_cap, r.sealed_reply, getattr(r, "version", 1))

    def voucher_open(self, secret_key: bytes, sealed_reply: bytes, write_cap: bytes) -> Opened:
        r = voucher.voucher_open_reply(secret_key, sealed_reply, write_cap)
        return Opened(r.who_reply, r.mutated_message_write_cap)
