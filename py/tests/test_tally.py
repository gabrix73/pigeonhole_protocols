# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Tally messages: against the shared vectors, and as lines a client sends, reads and keeps."""
import pytest

from pigeonhole_protocols.katzenqt1 import engine as eng
from pigeonhole_protocols.katzenqt1 import wire
from pigeonhole_protocols.katzenqt1.store import Store
from test_client import join, settle, texts, world  # noqa: F401
from test_wire_vectors import load, unhex

V = load("tally_vectors.json")


def tally_of_json(j):
    if j is None:
        return None
    choice = None if j["choice"] is None else dict(j["choice"])
    return wire.Tally(j["msg_type"], unhex(j["survey_id"]), j["version"], choice, unhex(j["crdt"]))


@pytest.mark.parametrize("e", V["tallies"], ids=[e["name"] for e in V["tallies"]])
def test_tallies(e):
    t, cbor = tally_of_json(e["tally"]), unhex(e["cbor"])
    assert wire.tally_content(bytes(32), t, e["wire_version"]) == cbor
    back = wire.tally_of(wire.decode_gcm(cbor))
    assert back == t and list((back.choice or {}).items()) == [tuple(p) for p in e["tally"]["choice"] or []]


@pytest.mark.parametrize("e", V["read"], ids=[e["name"] for e in V["read"]])
def test_read(e):
    assert wire.tally_of(wire.decode_gcm(unhex(e["cbor"]))) == tally_of_json(e["tally"])


def test_tally_lines_are_sent_read_and_kept(world):  # noqa: F811
    sim, clock, make = world
    alice, bob = join(make, sim)
    create = wire.Tally(wire.MSG_TALLY_CREATE, bytes(16), 0, crdt=bytes(range(256)) * 12)
    vote = wire.Tally(wire.MSG_TALLY_VOTE, bytes(16), 2, {"s1": "yes", "s0": "no"})
    alice.feed(eng.SendTally("g", create))
    alice.feed(eng.SendTally("g", vote))
    alice.feed(eng.Send("g", "after"))
    settle([alice, bob], 60_000)
    assert texts(bob, "g") == ["alice: [a poll]", "alice: [a vote]", "alice: after"]
    me = alice.state.chat("g").group.me
    for c in (alice, bob):
        assert [(l.sender, l.tally) for l in c.lines("g") if l.tally is not None] == [(me, create), (me, vote)]
    alice.close()
    bob.close()
    lines = [l for l in Store(bob.store.dir).load("bob").chat("g").log if l.tally is not None]
    assert [l.tally for l in lines] == [create, vote] and list(lines[1].tally.choice) == ["s1", "s0"]
