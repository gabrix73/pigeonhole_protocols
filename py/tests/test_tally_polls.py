# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Polls, katzenqt's tally protocol without IO: what katzenqt.tally's tests ask of it, and two
members' Polls exchanging tally messages over the wire."""
import pytest

pytest.importorskip("pycrdt")

from pigeonhole_protocols.katzenqt1 import tally as ty  # noqa: E402
from pigeonhole_protocols.katzenqt1 import wire  # noqa: E402

SID = bytes(range(16))
ALICE, BOB, CAROL = bytes([1]) * 16, bytes([2]) * 16, bytes([3]) * 16


def over_wire(t):
    """t as a member reads it."""
    return wire.tally_of(wire.decode_gcm(wire.tally_content(bytes(32), t)))


def test_document():
    doc = ty.new_survey(SID, "Lunch", ty.Mode.AVAILABILITY, ["Mon", "Tue"], creator=ALICE)
    assert ty.slots_of(doc) == [("s0", "Mon"), ("s1", "Tue")]
    assert (ty.survey_id_of(doc), ty.topic_of(doc), ty.mode_of(doc), ty.status_of(doc), ty.creator_of(doc)) == (SID, "Lunch", ty.Mode.AVAILABILITY, "open", ALICE)
    assert ty._meta(doc)["n_slots"] == 2
    back = ty.load_doc(ty.full_state(doc))
    assert ty.slots_of(back) == ty.slots_of(doc) and ty.creator_of(back) == ALICE
    assert ty.creator_of(ty.new_survey(SID, "L", ty.Mode.APPROVAL, ["a"])) is None
    with pytest.raises(ValueError):
        ty.new_survey(SID, "L", ty.Mode.APPROVAL, [])


def test_votes_counts_and_outcome():
    doc = ty.new_survey(SID, "Lunch", ty.Mode.APPROVAL, ["Mon", "Tue", "Wed"])
    with pytest.raises(ValueError, match="unknown slot id"):
        ty.apply_vote(doc, ALICE, {"s9": "yes"})
    with pytest.raises(ValueError, match="not allowed in approval mode"):
        ty.apply_vote(doc, ALICE, {"s0": "maybe"})
    ty.apply_vote(doc, ALICE, {"s0": "yes"}, 5)
    ty.apply_vote(doc, ALICE, {"s1": "yes"}, 4)  # older: kept out
    ty.apply_vote(doc, BOB, {"s0": "yes", "s1": "yes"})
    ty.apply_vote(doc, CAROL, {})
    assert ty.stored_choice(doc, ALICE) == (5, {"s0": "yes"}) and ty.current_version(doc, BOB) == 0 and ty.current_version(doc, bytes(16)) == -1
    assert [v.voter for v in ty.per_voter(doc)] == [ALICE, BOB, CAROL]
    r = ty.tally(doc)
    assert r.n_voters == 3 and [(s.slot_id, s.yes, s.maybe, s.no) for s in r.slots] == [("s0", 2, 0, 1), ("s1", 1, 0, 2), ("s2", 0, 0, 3)]
    o = ty.outcome(r)
    assert (o.kind, [s.slot_id for s in o.winners], o.top_yes) == ("winner", ["s0"], 2)
    ty.apply_vote(doc, ALICE, {"s0": "yes", "s1": "yes"}, 6)
    assert ty.outcome(ty.tally(doc)).kind == "tie"
    assert ty.outcome(ty.tally(ty.new_survey(SID, "L", ty.Mode.AVAILABILITY, ["a"]))).kind == "no_winner"
    avail = ty.new_survey(SID, "L", ty.Mode.AVAILABILITY, ["a"])
    ty.apply_vote(avail, ALICE, {"s0": "maybe"})
    assert ty.tally(avail).slots[0].maybe == 1
    ty.close_survey(doc)
    assert ty.tally(doc).status == "closed"


def test_voter_id():
    cap = bytes(range(32)) + bytes(104)
    assert ty.voter_id(cap).hex() == "f39a2cad58411cd49f577e5086b8031f"
    assert ty.voter_id(cap) == ty.voter_id(bytes(range(32)) + bytes(103) + b"\x07")


def test_two_members_over_the_wire():
    alice, bob = ty.Polls(ALICE), ty.Polls(BOB)
    create = alice.create(SID, "Lunch", ty.Mode.AVAILABILITY, ["Mon", "Tue"])
    v1 = bob.vote(SID, {"s0": "yes"})
    assert v1 is None, "bob does not hold the survey yet"
    assert bob.handle(ALICE, over_wire(create)).status == "applied"
    v1 = bob.vote(SID, {"s0": "yes"})
    v2 = bob.vote(SID, {"s0": "no", "s1": "maybe"})
    assert (v1.version, v2.version) == (0, 1)
    # Newest wins whichever arrives first.
    assert alice.handle(BOB, over_wire(v2)).status == "applied"
    assert alice.handle(BOB, over_wire(v1)).status == "applied"
    assert ty.stored_choice(alice.docs[SID], BOB) == (1, {"s0": "no", "s1": "maybe"})
    alice.vote(SID, {"s0": "yes"})
    # A vote is the sender's whoever it names, and only the creator closes.
    assert alice.handle(BOB, over_wire(wire.Tally(wire.MSG_TALLY_VOTE, SID, 0, {"s9": "yes"}))).status == "rejected"
    assert bob.close(SID) is None
    assert alice.handle(BOB, over_wire(wire.Tally(wire.MSG_TALLY_CLOSE, SID))).status == "rejected"
    close = alice.close(SID)
    assert bob.handle(ALICE, over_wire(close)).status == "applied" and ty.status_of(bob.docs[SID]) == "closed"
    # Bob catches up on alice's vote by a sync request.
    req = bob.sync_request(SID)
    a = alice.handle(BOB, over_wire(req))
    assert a.status == "applied" and a.reply.kind == wire.MSG_TALLY_SYNC_RESP
    assert bob.handle(ALICE, over_wire(a.reply)).status == "applied"
    assert ty.tally(bob.docs[SID]) == ty.tally(alice.docs[SID])
    assert [(s.yes, s.maybe, s.no) for s in ty.tally(bob.docs[SID]).slots] == [(1, 0, 1), (0, 1, 1)]
    # A newcomer with nothing asks for all of it.
    carol = ty.Polls(CAROL)
    assert carol.handle(ALICE, over_wire(alice.handle(CAROL, over_wire(carol.sync_request(SID))).reply)).status == "applied"
    assert ty.tally(carol.docs[SID]) == ty.tally(alice.docs[SID])
    # Kept and loaded.
    again = ty.Polls.load(ALICE, alice.saved())
    assert ty.tally(again.docs[SID]) == ty.tally(alice.docs[SID]) and again.vote(SID, {}).version == 1


def test_vote_and_close_before_their_survey_wait_for_it():
    alice, bob = ty.Polls(ALICE), ty.Polls(BOB)
    create = alice.create(SID, "Lunch", ty.Mode.APPROVAL, ["Mon"])
    carol = ty.Polls(CAROL)
    carol.handle(ALICE, create)
    vote = carol.vote(SID, {"s0": "yes"})
    assert bob.handle(CAROL, vote).status == "duplicate"
    assert bob.handle(CAROL, vote).status == "duplicate" and len(bob.pending[SID]) == 1
    assert bob.handle(CAROL, wire.Tally(wire.MSG_TALLY_CLOSE, SID)).status == "duplicate"  # not the creator
    assert bob.handle(ALICE, alice.close(SID)).status == "duplicate"
    assert bob.handle(ALICE, create).status == "applied" and not bob.pending
    assert ty.tally(bob.docs[SID]).slots[0].yes == 1 and ty.status_of(bob.docs[SID]) == "closed"


def test_refusals():
    p = ty.Polls(ALICE)
    assert p.handle(BOB, wire.Tally(wire.MSG_TALLY_CREATE, bytes(65), crdt=b"")).status == "rejected"
    assert p.handle(BOB, wire.Tally(wire.MSG_TALLY_CREATE, SID, crdt=bytes(ty.MAX_CRDT + 1))).status == "rejected"
    assert p.handle(BOB, wire.Tally(wire.MSG_TALLY_CREATE, SID)).status == "rejected"
    assert p.handle(BOB, wire.Tally(wire.MSG_TALLY_CREATE, SID, crdt=b"\xff\xff")).status == "rejected"
    other = ty.full_state(ty.new_survey(bytes(16), "L", ty.Mode.APPROVAL, ["a"]))
    assert p.handle(BOB, wire.Tally(wire.MSG_TALLY_CREATE, SID, crdt=other)).detail == "crdt of another survey"
    assert p.handle(BOB, wire.Tally(wire.MSG_TALLY_SYNC_REQ, SID, crdt=b"")).status == "duplicate"
    assert not p.docs
