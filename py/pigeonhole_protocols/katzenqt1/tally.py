# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""katzenqt's tally protocol, a poll whose state is a Yjs document, as ``katzenqt.tally`` has
it, without IO: ``Polls`` takes the tally messages of one chat and gives the ones to send.

One document holds one survey, in three roots:

- ``meta`` (map): ``survey_id`` (hex), ``topic``, ``mode``, ``n_slots``, ``status`` (``open``
  or ``closed``), and ``creator`` (hex voter id), who alone may close it;
- ``slots`` (array of maps ``{id, text}``), fixed at creation, ids ``s0``, ``s1``, ...;
- ``votes`` (map): voter id (hex) to a map of slot id to availability, with the vote's
  version under ``_version``. The newest version of a voter's vote wins, whatever the order
  they arrive in.

A voter is a hash of the read cap's public key, the sender a message came from, never an id in
the message. Counts are never stored: ``tally`` derives them. Numbers are Yjs numbers, floats."""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from pycrdt import Array, Doc, Map

from . import wire

MAX_SURVEY_ID = 64
MAX_CRDT = 512 * 1024
VERSION_KEY = "_version"
"""Where a vote's version is kept in its map; never a slot id."""


class Mode(Enum):
    """Approval is availability without ``maybe``."""

    AVAILABILITY = "availability"
    APPROVAL = "approval"


DOMAINS = {Mode.AVAILABILITY: ("yes", "maybe", "no"), Mode.APPROVAL: ("yes", "no")}


def slot_id(i: int) -> str:
    return "s%d" % i


def voter_id(read_cap: bytes) -> bytes:
    """A member's voter id: BLAKE2b-128 of their read cap's 32-byte public key, the same for
    every copy of their cap."""
    return hashlib.blake2b(read_cap[:32], digest_size=16).digest()


# ---- the document ----


def new_survey(survey_id: bytes, topic: str, mode: Mode, slots: List[str], creator: Optional[bytes] = None) -> Doc:
    if not slots:
        raise ValueError("a survey needs at least one slot")
    doc = Doc()
    doc["meta"], doc["slots"], doc["votes"] = Map(), Array(), Map()
    with doc.transaction():
        m = _meta(doc)
        m["survey_id"], m["topic"], m["mode"], m["n_slots"], m["status"] = survey_id.hex(), topic, mode.value, len(slots), "open"
        if creator is not None:
            m["creator"] = creator.hex()
        for i, text in enumerate(slots):
            _slots(doc).append(Map({"id": slot_id(i), "text": text}))
    return doc


# A document read from an update has its roots made by the update: read them by type.
def _meta(doc: Doc) -> Map:
    return doc.get("meta", type=Map)


def _slots(doc: Doc) -> Array:
    return doc.get("slots", type=Array)


def _votes(doc: Doc) -> Map:
    return doc.get("votes", type=Map)


def survey_id_of(doc: Doc) -> bytes:
    return bytes.fromhex(_meta(doc)["survey_id"])


def topic_of(doc: Doc) -> str:
    return _meta(doc)["topic"]


def mode_of(doc: Doc) -> Mode:
    return Mode(_meta(doc)["mode"])


def status_of(doc: Doc) -> str:
    return _meta(doc)["status"]


def creator_of(doc: Doc) -> Optional[bytes]:
    """None for a survey made before katzenqt kept its creator: anyone may close it."""
    m = _meta(doc)
    return bytes.fromhex(m["creator"]) if "creator" in set(m.keys()) else None


def slots_of(doc: Doc) -> List[Tuple[str, str]]:
    a = _slots(doc)
    return [(a[i]["id"], a[i]["text"]) for i in range(len(a))]


def _version(v: Map) -> int:
    raw = v[VERSION_KEY] if VERSION_KEY in set(v.keys()) else 0
    if isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(raw):
        return 0
    return int(raw)


def stored_choice(doc: Doc, voter: bytes) -> Optional[Tuple[int, Dict[str, str]]]:
    """The (version, choice) kept for voter, or None if they have not voted."""
    votes, k = _votes(doc), voter.hex()
    if k not in set(votes.keys()):
        return None
    v = votes[k]
    return _version(v), {s: v[s] for s in v.keys() if s != VERSION_KEY}


def current_version(doc: Doc, voter: bytes) -> int:
    """The version of voter's vote, -1 if none: the next is one more."""
    s = stored_choice(doc, voter)
    return -1 if s is None else s[0]


def apply_vote(doc: Doc, voter: bytes, choice: Dict[str, str], version: int = 0) -> None:
    """Keep voter's choice, slot id to availability, unless a newer version of their vote is
    kept already. Raises ValueError for a slot the survey does not have or an availability its
    mode does not allow."""
    allowed, slots = DOMAINS[mode_of(doc)], {s for s, _ in slots_of(doc)}
    for s, a in choice.items():
        if s not in slots:
            raise ValueError("unknown slot id %r" % s)
        if a not in allowed:
            raise ValueError("availability %r not allowed in %s mode" % (a, mode_of(doc).value))
    with doc.transaction():
        if version < current_version(doc, voter):
            return
        _votes(doc)[voter.hex()] = Map({**choice, VERSION_KEY: version})


def close_survey(doc: Doc) -> None:
    with doc.transaction():
        _meta(doc)["status"] = "closed"


# ---- counts ----


@dataclass(frozen=True)
class VoterChoice:
    voter: bytes
    version: int
    choice: Dict[str, str]


@dataclass(frozen=True)
class SlotTally:
    slot_id: str
    text: str
    yes: int
    maybe: int
    no: int


@dataclass(frozen=True)
class TallyResult:
    survey_id: bytes
    mode: Mode
    status: str
    n_voters: int
    slots: List[SlotTally]


@dataclass(frozen=True)
class Outcome:
    """``winner``, ``tie`` or ``no_winner`` (no slot has a yes), by yes count."""

    kind: str
    winners: List[SlotTally]
    top_yes: int


def per_voter(doc: Doc) -> List[VoterChoice]:
    """Each vote, by voter id in byte order."""
    return [VoterChoice(bytes.fromhex(k), *stored_choice(doc, bytes.fromhex(k))) for k in sorted(_votes(doc).keys())]


def tally(doc: Doc) -> TallyResult:
    """The counts of each slot; a slot a voter left out counts as no."""
    choices = [v.choice for v in per_voter(doc)]
    slots = []
    for s, text in slots_of(doc):
        marks = [c.get(s, "no") for c in choices]
        yes, maybe = marks.count("yes"), marks.count("maybe")
        slots.append(SlotTally(s, text, yes, maybe, len(marks) - yes - maybe))
    return TallyResult(survey_id_of(doc), mode_of(doc), status_of(doc), len(choices), slots)


def outcome(r: TallyResult) -> Outcome:
    top = max((s.yes for s in r.slots), default=0)
    if top == 0:
        return Outcome("no_winner", [], 0)
    winners = [s for s in r.slots if s.yes == top]
    return Outcome("tie" if len(winners) > 1 else "winner", winners, top)


# ---- sync ----


def state_vector(doc: Doc) -> bytes:
    return doc.get_state()


def diff_since(doc: Doc, state: bytes) -> bytes:
    """What doc has that a document of state lacks, as an update."""
    return doc.get_update(state)


def full_state(doc: Doc) -> bytes:
    return doc.get_update()


def load_doc(update: bytes) -> Doc:
    doc = Doc()
    doc.apply_update(update)
    return doc


# ---- a chat's polls ----


@dataclass(frozen=True)
class Applied:
    """What became of a tally message: ``applied``, ``duplicate`` (no effect: a survey not
    held, which a vote or close waits for) or ``rejected``, with why; and a reply to send."""

    status: str
    detail: str = ""
    reply: Optional[wire.Tally] = None


@dataclass
class Polls:
    """The surveys of one chat, by survey id, and the votes and closes read before their
    survey, in the order read. ``me`` is this member's voter id."""

    me: bytes
    docs: Dict[bytes, Doc] = field(default_factory=dict)
    pending: Dict[bytes, List[Tuple[bytes, wire.Tally]]] = field(default_factory=dict)

    def create(self, survey_id: bytes, topic: str, mode: Mode, slots: List[str]) -> wire.Tally:
        """A new survey of ours, and the message that announces it."""
        doc = self.docs[survey_id] = new_survey(survey_id, topic, mode, slots, creator=self.me)
        return wire.Tally(wire.MSG_TALLY_CREATE, survey_id, crdt=full_state(doc))

    def vote(self, survey_id: bytes, choice: Dict[str, str]) -> Optional[wire.Tally]:
        """Our vote, newer than any before; None for a survey not held. Raises ValueError for a
        choice the survey does not allow."""
        doc = self.docs.get(survey_id)
        if doc is None:
            return None
        version = current_version(doc, self.me) + 1
        apply_vote(doc, self.me, choice, version)
        return wire.Tally(wire.MSG_TALLY_VOTE, survey_id, version, dict(choice))

    def close(self, survey_id: bytes) -> Optional[wire.Tally]:
        """Close a survey we made; None for one not held or not ours."""
        doc = self.docs.get(survey_id)
        if doc is None or creator_of(doc) not in (None, self.me):
            return None
        close_survey(doc)
        return wire.Tally(wire.MSG_TALLY_CLOSE, survey_id)

    def sync_request(self, survey_id: bytes) -> wire.Tally:
        """Ask the others for what we lack of a survey, or all of it."""
        doc = self.docs.get(survey_id)
        return wire.Tally(wire.MSG_TALLY_SYNC_REQ, survey_id, crdt=state_vector(doc if doc is not None else Doc()))

    def handle(self, sender: bytes, t: wire.Tally) -> Applied:
        """Apply a tally message from sender, a voter id."""
        sid, doc = t.survey_id, self.docs.get(t.survey_id)
        if len(sid) > MAX_SURVEY_ID:
            return Applied("rejected", "survey id of %d bytes exceeds the %d-byte cap" % (len(sid), MAX_SURVEY_ID))
        if t.crdt is not None and len(t.crdt) > MAX_CRDT:
            return Applied("rejected", "crdt blob of %d bytes exceeds the %d-byte cap" % (len(t.crdt), MAX_CRDT))
        if t.kind in (wire.MSG_TALLY_CREATE, wire.MSG_TALLY_SYNC_RESP):
            if t.crdt is None:
                return Applied("rejected", "no crdt payload")
            try:
                if doc is None:
                    doc = load_doc(t.crdt)
                    if survey_id_of(doc) != sid:
                        return Applied("rejected", "crdt of another survey")
                else:
                    doc.apply_update(t.crdt)
            except Exception as e:
                return Applied("rejected", "undecodable crdt: %s" % e)
            if sid not in self.docs:
                self.docs[sid] = doc
                for s, p in self.pending.pop(sid, []):
                    self._replay(doc, s, p)
            return Applied("applied")
        if t.kind in (wire.MSG_TALLY_VOTE, wire.MSG_TALLY_CLOSE) and doc is None:
            p = self.pending.setdefault(sid, [])
            if (sender, t) not in p:
                p.append((sender, t))
            return Applied("duplicate", "%s for unknown survey" % ("vote" if t.kind == wire.MSG_TALLY_VOTE else "close"))
        if t.kind == wire.MSG_TALLY_VOTE:
            try:
                apply_vote(doc, sender, t.choice or {}, t.version)
            except ValueError as e:
                return Applied("rejected", "invalid vote: %s" % e)
            return Applied("applied")
        if t.kind == wire.MSG_TALLY_CLOSE:
            if creator_of(doc) not in (None, sender):
                return Applied("rejected", "close ignored: not the creator")
            close_survey(doc)
            return Applied("applied")
        if doc is None:
            return Applied("duplicate", "sync request for unknown survey")
        try:
            diff = diff_since(doc, t.crdt or b"")
        except Exception as e:
            return Applied("rejected", "undecodable state vector: %s" % e)
        return Applied("applied", reply=wire.Tally(wire.MSG_TALLY_SYNC_RESP, sid, crdt=diff))

    def _replay(self, doc: Doc, sender: bytes, t: wire.Tally) -> None:
        """A vote or close read before its survey, which may already hold it."""
        if t.kind == wire.MSG_TALLY_CLOSE:
            if creator_of(doc) in (None, sender):
                close_survey(doc)
            return
        stored = stored_choice(doc, sender)
        if stored is not None and (t.version < stored[0] or (t.version, t.choice or {}) == stored):
            return
        try:
            apply_vote(doc, sender, t.choice or {}, t.version)
        except ValueError:
            pass

    def saved(self) -> Dict[bytes, bytes]:
        """Each survey as one update, to keep."""
        return {sid: full_state(d) for sid, d in self.docs.items()}

    @classmethod
    def load(cls, me: bytes, saved: Dict[bytes, bytes]) -> "Polls":
        return cls(me, {sid: load_doc(u) for sid, u in saved.items()})
