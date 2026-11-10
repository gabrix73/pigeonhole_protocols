# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""A job keeps the lines packed into it, and one saved before packing has none."""
import cbor2

from pigeonhole_protocols.katzenqt1 import engine, store


def test_job_keeps_packed_lines():
    c = engine.Chat("g", "g", jobs=[engine.Job(1, 1, None, b"F", 2, packed=[3, 5])])
    assert store.decode_chat(store.encode_chat(c)).jobs[0].packed == [3, 5]
    d = cbor2.loads(store.encode_chat(c))
    d["jobs"] = [j[:6] for j in d["jobs"]]
    assert store.decode_chat(cbor2.dumps(d)).jobs[0].packed == []
