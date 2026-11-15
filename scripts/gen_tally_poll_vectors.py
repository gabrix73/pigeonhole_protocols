#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Writes testdata/katzenqt1/tally_poll_vectors.json: polls as katzenqt's tally code keeps them,
so that each language's poll logic is checked against it.

Run with katzenqt's environment, its src on the path:

    PYTHONPATH=katzenqt/src katzenqt/.venv/bin/python scripts/gen_tally_poll_vectors.py

voter_ids: a member's key (its read cap's first 32 bytes) and its voter id. scenarios: tally
messages read in order, each from a sender's key, with whether it is refused and whether it is
answered (a sync request); then the poll each survey is, as katzenqt's engine reads its Doc. The
replay here is katzenqt's TallyController.handle_event without its database. A Doc's updates are
pycrdt's, so a reader is checked against pycrdt's bytes; what a writer makes is checked by reading
it back."""
import json
import os

from katzenqt.tally import engine, schema, sync
from katzenqt.tally.controller import _MAX_CRDT_BLOB, _MAX_SURVEY_ID_LEN, voter_id_from_read_cap

TESTDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "testdata", "katzenqt1")
CREATE, VOTE, CLOSE, SYNC_REQ, SYNC_RESP = 5, 6, 7, 8, 9

ALICE, BOB, CAROL, DAVE = (bytes([i]) * 32 for i in (0xa1, 0xb0, 0xc4, 0xd0))


def voter(key):
    return voter_id_from_read_cap(key)


class Replay:
    """katzenqt's TallyController.handle_event, one conversation, no database."""

    def __init__(self):
        self.docs, self.pending = {}, {}

    def load(self, sid, crdt):
        doc = self.docs.get(sid)
        if doc is None:
            doc = self.docs[sid] = sync.load_doc(crdt)
            for kind, v, choice, version in self.pending.pop(sid, []):
                if kind == VOTE:
                    stored = engine.stored_choice(doc, v)
                    if stored is not None and (version < stored[0] or version == stored[0] and stored[1] == choice):
                        continue
                    try:
                        engine.apply_vote(doc, v, choice, version)
                    except ValueError:
                        pass
                elif schema.creator_of(doc) in (None, v) and schema.status_of(doc) != "closed":
                    engine.close_survey(doc)
        else:
            sync.apply_update(doc, crdt)

    def handle(self, sender, kind, t):
        """(refused, reply)"""
        sid = t["survey_id"]
        if len(sid) > _MAX_SURVEY_ID_LEN or t.get("crdt") is not None and len(t["crdt"]) > _MAX_CRDT_BLOB:
            return True, None
        doc = self.docs.get(sid)
        v = voter(sender)
        if kind in (CREATE, SYNC_RESP):
            if t.get("crdt") is None:
                return False, None
            self.load(sid, t["crdt"])
            return False, None
        if kind == VOTE:
            choice = dict(t.get("choice") or {})
            if doc is None:
                self.pending.setdefault(sid, []).append((VOTE, v, choice, t.get("version", 0)))
                return False, None
            try:
                engine.apply_vote(doc, v, choice, t.get("version", 0))
            except ValueError:
                return True, None
            return False, None
        if kind == CLOSE:
            if doc is None:
                self.pending.setdefault(sid, []).append((CLOSE, v, None, t.get("version", 0)))
                return False, None
            if schema.creator_of(doc) not in (None, v):
                return True, None
            engine.close_survey(doc)
            return False, None
        if kind == SYNC_REQ:
            if doc is None:
                return False, None
            return False, sync.diff_since(doc, t.get("crdt") or b"")
        return True, None


def poll_json(doc):
    r = engine.tally(doc)
    o = engine.outcome(r)
    creator = schema.creator_of(doc)
    return {
        "survey_id": r.survey_id.hex(),
        "topic": schema.topic_of(doc),
        "mode": r.mode.value,
        "closed": r.status == "closed",
        "creator": None if creator is None else creator.hex(),
        "options": [[s.slot_id, s.text, s.yes, s.maybe, s.no] for s in r.slots],
        "ballots": [[b.voter_id.hex(), b.version, sorted([k, v] for k, v in b.choices.items())] for b in engine.per_voter(doc)],
        "winners": [s.slot_id for s in o.winners],
    }


def survey(sid, topic, mode, options, creator):
    return sync.full_state(schema.new_survey_doc(sid, topic, mode, options, creator=voter(creator)))


def step(sender, kind, **t):
    return (sender, kind, t)


def body(t):
    out = {"survey_id": t["survey_id"].hex(), "version": t.get("version", 0)}
    if "choice" in t:
        out["choice"] = [[k, v] for k, v in t["choice"].items()]
    if "crdt" in t:
        out["crdt"] = t["crdt"].hex()
    return out


def scenarios():
    s1 = bytes(range(16))
    lunch = survey(s1, "Lunch: which day?", schema.Mode.AVAILABILITY, ["Mon", "Tue", "Wed"], ALICE)
    yield "availability", [
        step(ALICE, CREATE, survey_id=s1, crdt=lunch),
        step(BOB, VOTE, survey_id=s1, choice={"s0": "yes", "s1": "maybe"}),
        step(CAROL, VOTE, survey_id=s1, choice={"s2": "yes"}),
        step(CAROL, VOTE, survey_id=s1, choice={"s0": "yes", "s2": "no"}, version=1),
        step(CAROL, VOTE, survey_id=s1, choice={"s1": "yes"}),
        step(BOB, VOTE, survey_id=s1, choice={"s0": "no", "s1": "yes"}),
        step(BOB, CLOSE, survey_id=s1),
        step(DAVE, VOTE, survey_id=s1, choice={"s0": "yes"}, version=7),
        step(ALICE, CLOSE, survey_id=s1),
    ]
    s2 = b"approval-survey"
    film = survey(s2, "Film?", schema.Mode.APPROVAL, ["A", "B"], BOB)
    yield "approval-refusals-and-tie", [
        step(BOB, CREATE, survey_id=s2, crdt=film),
        step(ALICE, VOTE, survey_id=s2, choice={"s0": "maybe"}),
        step(ALICE, VOTE, survey_id=s2, choice={"s9": "yes"}),
        step(ALICE, VOTE, survey_id=s2, choice={"s0": "yes"}),
        step(CAROL, VOTE, survey_id=s2, choice={"s1": "yes"}),
        step(DAVE, VOTE, survey_id=s2, choice={}),
        step(BOB, CLOSE, survey_id=s2),
    ]
    s3 = b"\x03" * 16
    early = survey(s3, "Early?", schema.Mode.APPROVAL, ["x", "y"], CAROL)
    yield "before-the-create", [
        step(BOB, VOTE, survey_id=s3, choice={"s1": "yes"}, version=2),
        step(BOB, VOTE, survey_id=s3, choice={"s0": "yes"}, version=1),
        step(ALICE, CLOSE, survey_id=s3),
        step(CAROL, CLOSE, survey_id=s3),
        step(DAVE, CREATE, survey_id=s3, crdt=early),
    ]
    s4 = b"\x04" * 16
    a = schema.new_survey_doc(s4, "Synced", schema.Mode.AVAILABILITY, ["p", "q"], creator=voter(DAVE))
    created = sync.full_state(a)
    sv = sync.state_vector(sync.load_doc(created))
    engine.apply_vote(a, voter(ALICE), {"s1": "maybe"}, 3)
    engine.close_survey(a)
    yield "sync-response", [
        step(DAVE, CREATE, survey_id=s4, crdt=created),
        step(CAROL, SYNC_RESP, survey_id=s4, crdt=sync.diff_since(a, sv)),
        step(BOB, SYNC_REQ, survey_id=b"\x05" * 16, crdt=sv),
    ]
    yield "sync-request", [
        step(DAVE, CREATE, survey_id=s4, crdt=created),
        step(DAVE, SYNC_RESP, survey_id=s4, crdt=sync.diff_since(a, sv)),
        step(BOB, SYNC_REQ, survey_id=s4, crdt=sv),
    ]
    yield "no-winner-and-caps", [
        step(ALICE, CREATE, survey_id=b"\x06" * 65, crdt=survey(b"\x06" * 65, "Too long an id", schema.Mode.APPROVAL, ["a"], ALICE)),
        step(ALICE, CREATE, survey_id=b"\x06" * 64, crdt=survey(b"\x06" * 64, "Nobody?", schema.Mode.APPROVAL, ["a"], ALICE)),
        step(BOB, VOTE, survey_id=b"\x06" * 64, choice={"s0": "no"}),
    ]


def main():
    out = {"about": "Polls as katzenqt's tally code keeps them: one Yjs document a survey, its root map meta {survey_id (hex), topic, mode, n_slots, status open or closed, creator (hex voter id)}, root array slots of maps {id, text}, root map votes of voter id (hex) to a map of slot id to availability with _version. A member's voter id is BLAKE2b-128 of its key. A create or sync response carries an update, merged in; a vote carries the sender's choice, recorded under the sender's voter id when its slots are the survey's and its availabilities the mode's (approval: yes, no; availability: yes, maybe, no), the newest version winning and an equal one replacing; a close counts from the survey's creator only; a sync request is answered with the diff since its state vector. A vote or close for a survey not yet seen waits for it. Survey ids over 64 bytes and updates over 512 KiB are refused (the second is not among the vectors, for size). Counts take a slot not marked as no; the winners are the slots with the most yes, none when no slot has one. Generated by scripts/gen_tally_poll_vectors.py with katzenqt's tally code."}
    out["voter_ids"] = [[k.hex(), voter(k).hex()] for k in (ALICE, BOB, CAROL, DAVE)]
    out["scenarios"] = []
    for name, steps in scenarios():
        r = Replay()
        rows = []
        for sender, kind, t in steps:
            refused, reply = r.handle(sender, kind, t)
            row = {"sender": sender.hex(), "msg_type": kind, "tally": body(t), "refused": refused, "answered": reply is not None}
            if reply is not None:
                fresh = sync.load_doc(steps[0][2]["crdt"])
                sync.apply_update(fresh, reply)
                row["answer_reads_as"] = poll_json(fresh)
            rows.append(row)
        out["scenarios"].append({"name": name, "steps": rows, "polls": [poll_json(d) for _, d in sorted(r.docs.items())]})
    with open(os.path.join(TESTDATA, "tally_poll_vectors.json"), "w") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
