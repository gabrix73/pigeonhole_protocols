# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""A ping, and a message of a type a reader does not know: each is a notice, and what follows
is read."""

from pigeonhole_protocols.katzenqt1 import engine as eng
from pigeonhole_protocols.katzenqt1 import wire

from test_client import join, settle, texts, world  # noqa: F401


def write_raw(client, chat, cbor):
    """The client writes cbor as its next box, past its engine's own sending."""
    c = client.state.chat(chat)
    for o in c.group.compose(cbor):
        c.jobs.append(eng.Job(c.fresh(), o.token, None, wire.frame(cbor)))


def plain_notices(c, chat):
    return [eng.plain(l.notice) for l in c.lines(chat) if l.notice is not None]


def test_unknown_type_is_noticed(world):  # noqa: F811
    sim, clock, make = world
    alice, bob = join(make, sim)
    g = alice.state.chat("g").group
    write_raw(alice, "g", wire.Gcm(membership_hash=eng.membership(g), msg_type=13).encode())
    alice.feed(eng.Send("g", "after"))
    settle([alice, bob], 30_000)
    assert texts(bob, "g") == ["alice: after"]
    assert "~alice sent a message this app cannot show (type 13, version 5): update the app" in plain_notices(bob, "g")
    alice.close()
    bob.close()


def test_ping(world):  # noqa: F811
    sim, clock, make = world
    alice, bob = join(make, sim)
    alice.feed(eng.Ping("g"))
    alice.feed(eng.Send("g", "after"))
    settle([alice, bob], 30_000)
    assert texts(bob, "g") == ["alice: after"]
    assert "~alice pinged" in plain_notices(bob, "g")
    alice.close()
    bob.close()
