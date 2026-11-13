# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""A chat joining keeps the vouchers it minted before, and one saved before there were any has none."""
import cbor2

from pigeonhole_protocols.katzenqt1 import engine, store


def test_joining_keeps_earlier_vouchers():
    first = engine.Joining("a", b"\x01", b"\x01", b"1", 2)
    c = engine.Chat("g", "g", joining=engine.Joining("b", b"\x02", b"\x02", b"2", 2, [first]))
    assert store.decode_chat(store.encode_chat(c)).joining == c.joining
    d = cbor2.loads(store.encode_chat(c))
    d["joining"] = d["joining"][:5]
    assert store.decode_chat(cbor2.dumps(d)).joining.earlier == []
