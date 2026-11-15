#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Polls, katzenqt's tally protocol, between katzenqt and this repository's languages, both ways,
with katzenqt's own tally code and pycrdt 0.13.1.

    KATZENQT=~/katzenqt $KATZENQT/.venv/bin/python scripts/gen_tally_poll_vectors.py [--write]

testdata/katzenqt1/tally/katzenqt.json is what katzenqt sends, as group chat messages (hex): for
each mode, approval and availability, a poll's create, its members' votes in the order sent,
including a newer vote that replaces an older one and one that comes late with an older version,
a close from a member who did not make it, which counts for nothing, and its maker's close; the
poll's document with the votes in it, as a sync response; and the counts katzenqt makes, open and
closed. sync_req is katzenqt asking for the approval poll, as a member holding nothing would.
--write, or its absence, writes it anew.

testdata/katzenqt1/tally/rust.json, which the Rust test writes, is read as katzenqt would read it:
each of its polls, votes and closes, counted as the Rust counted them; its answer to sync_req,
counted as the approval poll; and its sync request for katzenqt's approval poll, which katzenqt
answers into katzenqt.json as sync_resp_for_rust.

A voter is the member's key, the 32 bytes their read cap starts with, as katzenqt names voters:
BLAKE2b-128 of it."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.expanduser(os.environ.get("KATZENQT", "~/katzenqt")), "src"))

from importlib.metadata import version  # noqa: E402

from pycrdt import Doc  # noqa: E402

from katzenqt.models import GroupChatMessage, GroupChatTypeEnum  # noqa: E402
from katzenqt.tally import engine, events, schema, sync  # noqa: E402
from katzenqt.tally.controller import voter_id_from_read_cap  # noqa: E402

TALLY = os.path.join(HERE, "..", "testdata", "katzenqt1", "tally")
SURVEYS = {
    "approval": bytes.fromhex("00112233445566778899aabbccddeeff"),
    "availability": bytes.fromhex("ffeeddccbbaa99887766554433221100"),
}


def key(n):
    return bytes([n]) * 32


def voter(k):
    return voter_id_from_read_cap(k + bytes(104))


def gcm(m):
    return m.to_cbor().hex()


def read(h):
    return GroupChatMessage.from_cbor(bytes.fromhex(h))


def counts(doc):
    t = engine.tally(doc)
    o = engine.outcome(t)
    return {
        "topic": schema.topic_of(doc),
        "mode": t.mode.value,
        "options": [s.text for s in t.slots],
        "yes": [s.yes for s in t.slots],
        "maybe": [s.maybe for s in t.slots],
        "no": [s.no for s in t.slots],
        "voters": t.n_voters,
        "closed": t.status == "closed",
        "outcome": {"kind": o.kind, "winners": [s.text for s in o.winners]},
    }


POLLS = {
    "approval": ("Lunch: which day?", ["Monday", "Tuesday", "Wednesday"], [
        (2, {"s0": "yes", "s2": "yes"}, 0),
        (3, {"s1": "yes"}, 0),
        (2, {"s2": "yes"}, 2),
        (1, {"s2": "yes", "s1": "yes"}, 0),
        (2, {"s0": "yes"}, 1),
    ]),
    "availability": ("Café ☕ at 10?", ["yes please", "später", "never"], [
        (2, {"s0": "maybe", "s1": "yes", "s2": "no"}, 0),
        (3, {"s0": "yes"}, 3),
        (1, {"s1": "maybe"}, 0),
    ]),
}


def katzenqt_poll(name):
    """A poll katzenqt makes, voted on and closed, and the document it holds."""
    topic, slots, ballots = POLLS[name]
    survey, creator = SURVEYS[name], key(1)
    doc = schema.new_survey_doc(survey, topic, schema.Mode(name), slots, creator=voter(creator))
    out = {"creator": creator.hex(), "create": gcm(events.build_create(survey, sync.full_state(doc))), "votes": []}
    for member, choice, v in ballots:
        engine.apply_vote(doc, voter(key(member)), choice, v)
        out["votes"].append({"sender": key(member).hex(), "gcm": gcm(events.build_vote(survey, choice, v))})
    out["voted"] = gcm(events.build_sync_response(survey, sync.full_state(doc)))
    out["want_open"] = counts(doc)
    out["closes"] = [
        {"sender": key(2).hex(), "gcm": gcm(events.build_close(survey))},
        {"sender": creator.hex(), "gcm": gcm(events.build_close(survey))},
    ]
    engine.close_survey(doc)
    out["want_closed"] = counts(doc)
    return out, doc


def apply(doc, sender, m):
    """A received vote or close, as katzenqt's controller applies one."""
    who = voter(bytes.fromhex(sender))
    if m.msg_type == GroupChatTypeEnum.TALLY_VOTE:
        engine.apply_vote(doc, who, m.tally.choice or {}, m.tally.version)
    elif m.msg_type == GroupChatTypeEnum.TALLY_CLOSE:
        creator = schema.creator_of(doc)
        if creator is None or creator == who:
            engine.close_survey(doc)


def check(rust, docs, vector):
    """The Rust's polls and answers, read as katzenqt reads them."""
    for name in ("approval", "availability"):
        p = rust[name]
        m = read(p["create"])
        assert m.msg_type == GroupChatTypeEnum.TALLY_CREATE, m.msg_type
        doc = sync.load_doc(m.tally.crdt)
        assert schema.survey_id_of(doc) == m.tally.survey_id
        assert schema.creator_of(doc) == voter(bytes.fromhex(p["creator"]))
        for v in p["votes"]:
            apply(doc, v["sender"], read(v["gcm"]))
        assert counts(doc) == p["want_open"], (name, counts(doc), p["want_open"])
        for c in p["closes"]:
            apply(doc, c["sender"], read(c["gcm"]))
        assert counts(doc) == p["want_closed"], (name, counts(doc), p["want_closed"])
    m = read(rust["sync_resp"])
    assert m.msg_type == GroupChatTypeEnum.TALLY_SYNC_RESP, m.msg_type
    assert counts(sync.load_doc(m.tally.crdt)) == vector["approval"]["want_open"]
    req = read(rust["sync_req"])
    assert req.msg_type == GroupChatTypeEnum.TALLY_SYNC_REQ, req.msg_type
    held = docs.get(req.tally.survey_id.hex())
    if held is None:
        held = sync.load_doc(read(vector["approval"]["voted"]).tally.crdt)
    diff = sync.diff_since(held, req.tally.crdt)
    vector["sync_resp_for_rust"] = gcm(events.build_sync_response(req.tally.survey_id, diff))
    print("katzenqt counts the Rust's polls as the Rust does, and answers its sync request")


def main():
    os.makedirs(TALLY, exist_ok=True)
    path = os.path.join(TALLY, "katzenqt.json")
    docs = {}
    if "--write" in sys.argv or not os.path.exists(path):
        vector = {"pycrdt": version("pycrdt")}
        for name in ("approval", "availability"):
            vector[name], doc = katzenqt_poll(name)
            docs[SURVEYS[name].hex()] = doc
        empty = Doc()
        vector["sync_req"] = gcm(events.build_sync_request(SURVEYS["approval"], sync.state_vector(empty)))
    else:
        with open(path) as f:
            vector = json.load(f)
    rust = os.path.join(TALLY, "rust.json")
    if os.path.exists(rust):
        with open(rust) as f:
            check(json.load(f), docs, vector)
    with open(path, "w") as f:
        json.dump(vector, f, indent=1, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
