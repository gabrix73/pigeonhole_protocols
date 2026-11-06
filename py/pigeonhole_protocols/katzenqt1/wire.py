# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""katzenqt1's wire formats, as pigeonhole_protocols' wire package has them:
the GroupChatMessage CBOR and its box framing, the reply to a new member,
and the membership hash. The member (``.member``) reads a message as a
``Message``; what a box holds is a ``GroupChatMessage`` map behind one
framing byte.

A ping, msg_type 11, is content with a null body: ``[4, membership_hash,
11, null]`` and, as for any message, acks and the rest after it. Its
readers play their ping sound. A reader refuses a type it does not know;
the engine then tells the user who sent it, its type and version."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Optional

import cbor2

from .member import ack_codec
from .member.events import JoinReply
from .member.wire import (
    INDEX_SIZE,
    KEY_SIZE,
    ROSTER_MAX,
    Introduction,
    IntroRef,
    Message,
    counter,
    decode_introduced_at,
    decode_numbers,
    encode_introduced_at,
    encode_numbers,
    key_of,
)

READ_CAP_SIZE = 136
HASH_SIZE = 32
VERSION = 4
"""The version written: a CBOR array. Version 3, a CBOR map, is read as well."""
MAP_VERSION = 3

MSG_TEXT = 0
MSG_INTRODUCTION = 1
MSG_FILE_UPLOAD = 2
MSG_WHO = 3
MSG_REPLY_WHO = 4
MSG_CONTROL = 10
MSG_PING = 11
"""Asks its readers to play their ping sound: content with a null body."""

OTHER_KEYS = ("file_upload", "who", "reply_who", "tally")
#: The field a message type's body is, in the map form and in ``Gcm.other``.
BODY_KEYS = {MSG_FILE_UPLOAD: "file_upload", MSG_WHO: "who", MSG_REPLY_WHO: "reply_who", 5: "tally", 6: "tally", 7: "tally", 8: "tally", 9: "tally"}

SENTINEL = bytes(HASH_SIZE)
_OLD_SENTINEL = b"TODOTODOTODOTODOTODOTODOTODOTODO"


def start_of(read_cap: bytes) -> bytes:
    return read_cap[KEY_SIZE:]


def is_sentinel(h: bytes) -> bool:
    return h == SENTINEL or h == _OLD_SENTINEL


def membership_hash(read_caps) -> bytes:
    """SHA-256 under a domain of the members' keys, each once, in byte
    order: katzenqt's canonical_membership_hash."""
    keys = sorted({bytes(key_of(c)) for c in read_caps})
    h = hashlib.sha256(b"KP:membership:v1")
    for k in keys:
        h.update(k)
    return h.digest()


# ---- GroupChatMessage ----


@dataclass
class Gcm:
    """A GroupChatMessage. None is an absent field. ``other`` keeps the
    fields this client does not read, as decoded, in katzenqt's order."""

    version: int = VERSION
    membership_hash: bytes = SENTINEL
    msg_type: int = MSG_TEXT
    text: Optional[str] = None
    introduction: Optional[Introduction] = None
    other: Optional[dict] = None
    acks: Optional[bytes] = None
    numbers: Optional[bytes] = None
    introduced_at: Optional[bytes] = None

    def body(self):
        """The type's payload in the array form: text, [name, read_cap], [payload, filetype,
        basename], an app value, or None for control."""
        if self.msg_type == MSG_TEXT:
            return self.text if self.text is not None else ""
        if self.msg_type == MSG_INTRODUCTION:
            return None if self.introduction is None else [self.introduction.name, self.introduction.read_cap]
        key = BODY_KEYS.get(self.msg_type)
        v = (self.other or {}).get(key) if key else None
        if key == "file_upload" and isinstance(v, dict):
            return [v.get("payload", b""), v.get("filetype", ""), v.get("basename", "")]
        return v

    def encode(self) -> bytes:
        if self.version >= VERSION:
            a = [self.version, self.membership_hash, self.msg_type, self.body(), self.acks, self.numbers, self.introduced_at]
            while len(a) > 4 and a[-1] is None:
                a.pop()
            return cbor2.dumps(a)
        return self.encode_map()

    def encode_map(self) -> bytes:
        """The map form, version 3."""
        m: dict = {"version": self.version, "membership_hash": self.membership_hash, "msg_type": self.msg_type}
        if self.text is not None:
            m["text"] = self.text
        if self.introduction is not None:
            m["introduction"] = {"display_name": self.introduction.name, "read_cap": self.introduction.read_cap}
        for k in OTHER_KEYS:
            if self.other and k in self.other:
                m[k] = self.other[k]
        if self.acks is not None:
            m["acks"] = self.acks
        if self.numbers is not None:
            m["numbers"] = self.numbers
        if self.introduced_at is not None:
            m["introduced_at"] = self.introduced_at
        return cbor2.dumps(m)

    @property
    def control(self) -> bool:
        return self.msg_type in (MSG_CONTROL, MSG_INTRODUCTION)


def _intro(name, cap) -> Optional[Introduction]:
    if not isinstance(name, str) or not 1 <= len(name) <= 30 or not isinstance(cap, bytes) or len(cap) != READ_CAP_SIZE:
        return None
    return Introduction(name, cap)


def _opt_bytes(v):
    return v if isinstance(v, bytes) else None


def decode_gcm(data: bytes) -> Optional[Gcm]:
    """The message a box's CBOR holds, in either form, or None when it is refused. The array
    form, version 4, and the map form, version 3, are told apart by the first byte's major
    type."""
    if not data:
        return None
    major = data[0] >> 5
    if major == 4:
        return _decode_array(data)
    if major == 5:
        return _decode_map(data)
    return None


def _decode_array(data: bytes) -> Optional[Gcm]:
    try:
        a = cbor2.loads(data)
    except Exception:
        return None
    if not isinstance(a, list) or not 4 <= len(a) <= 7:
        return None
    a = a + [None] * (7 - len(a))
    version, h, msg_type, body, acks, numbers, introduced_at = a
    if not isinstance(version, int) or version < VERSION or not isinstance(h, bytes) or len(h) != HASH_SIZE:
        return None
    if not isinstance(msg_type, int) or not 0 <= msg_type <= MSG_PING:
        return None
    for f in (acks, numbers, introduced_at):
        if f is not None and not isinstance(f, bytes):
            return None
    text = intro = None
    other = None
    if msg_type == MSG_TEXT:
        if not isinstance(body, str):
            return None
        text = body
    elif msg_type == MSG_INTRODUCTION:
        if not (isinstance(body, list) and len(body) == 2):
            return None
        intro = _intro(body[0], body[1])
        if intro is None:
            return None
    elif msg_type == MSG_FILE_UPLOAD:
        if not (isinstance(body, list) and len(body) == 3 and isinstance(body[0], bytes) and isinstance(body[1], str) and isinstance(body[2], str)):
            return None
        other = {"file_upload": {"payload": body[0], "filetype": body[1], "basename": body[2]}}
    elif msg_type in (MSG_CONTROL, MSG_PING):
        if body is not None:
            return None
    else:
        other = {BODY_KEYS[msg_type]: body} if body is not None else None
    return Gcm(version, h, msg_type, text, intro, other, acks, numbers, introduced_at)


def _decode_map(data: bytes) -> Optional[Gcm]:
    try:
        m = cbor2.loads(data)
    except Exception:
        return None
    if not isinstance(m, dict):
        return None
    version, h = m.get("version"), m.get("membership_hash")
    if not isinstance(version, int) or version < 0 or version > MAP_VERSION:
        return None
    if not isinstance(h, bytes) or len(h) != HASH_SIZE:
        return None
    intro = None
    i = m.get("introduction")
    if isinstance(i, dict):
        intro = _intro(i.get("display_name"), i.get("read_cap"))
        if intro is None:
            return None
    msg_type = m.get("msg_type")
    if msg_type is None:
        if intro is not None:
            msg_type = MSG_INTRODUCTION
        elif m.get("file_upload") is not None:
            msg_type = MSG_FILE_UPLOAD
        elif m.get("who") is not None:
            msg_type = MSG_WHO
        elif m.get("reply_who") is not None:
            msg_type = MSG_REPLY_WHO
        else:
            msg_type = MSG_TEXT
    if not isinstance(msg_type, int) or msg_type > MSG_PING:
        return None
    text = m.get("text")
    if text is not None and not isinstance(text, str):
        return None
    other = {k: m[k] for k in OTHER_KEYS if m.get(k) is not None}
    return Gcm(version, h, msg_type, text, intro, other or None, _opt_bytes(m.get("acks")), _opt_bytes(m.get("numbers")), _opt_bytes(m.get("introduced_at")))


def to_message(data: bytes) -> Optional[Message]:
    """What a member reads of a message's CBOR; a content message's whole
    CBOR travels as its content, as katzenqt's GcmCodec does."""
    g = decode_gcm(data)
    if g is None:
        return None
    try:
        acks = ack_codec.decode(g.acks or b"")
    except ack_codec.AcksError:
        acks = {}
    return Message(
        content=None if g.control else data,
        introduction=g.introduction if g.msg_type == MSG_INTRODUCTION else None,
        numbers=decode_numbers(g.numbers or b""),
        introduced_at=decode_introduced_at(g.introduced_at or b""),
        acks=acks,
        membership_hash=g.membership_hash if g.control and not is_sentinel(g.membership_hash) else None,
    )


def stamp_of(data: bytes) -> Optional[bytes]:
    """The membership hash a control message or introduction carries, or
    None for the sentinel; content carries its own."""
    g = decode_gcm(data)
    if g is None or not g.control or is_sentinel(g.membership_hash):
        return None
    return g.membership_hash


def of_message(m: Message, stamp: Optional[bytes] = None, version: int = VERSION) -> Optional[Gcm]:
    """The GroupChatMessage a member's message is written as; None when its
    content is not a message. A control message or introduction carries
    the membership hash the member stamped it with, or ``stamp``, or the
    sentinel."""
    if m.content is not None:
        g = decode_gcm(m.content)
        if g is None:
            return None
    elif m.introduction is not None:
        g = Gcm(version=version, membership_hash=m.membership_hash or stamp or SENTINEL, msg_type=MSG_INTRODUCTION, introduction=m.introduction)
    else:
        g = Gcm(version=version, membership_hash=m.membership_hash or stamp or SENTINEL, msg_type=MSG_CONTROL)
    g.acks = ack_codec.encode(m.acks) or None
    g.numbers = encode_numbers(m.numbers) or None
    g.introduced_at = encode_introduced_at(m.introduced_at) if m.introduced_at is not None else None
    return g


def text_content(hash_: bytes, text: str, version: int = VERSION) -> bytes:
    return Gcm(version=version, membership_hash=hash_, msg_type=MSG_TEXT, text=text).encode()


def ping_content(hash_: bytes, version: int = VERSION) -> bytes:
    return Gcm(version=version, membership_hash=hash_, msg_type=MSG_PING).encode()


def unsupported(data: bytes) -> Optional[tuple]:
    """(version, msg_type) of the array form data, which decode_gcm refuses, when it is a
    message of a newer version or of a type this client does not know; else None."""
    try:
        a = cbor2.loads(data)
    except Exception:
        return None
    if not isinstance(a, list) or len(a) < 3:
        return None
    version, h, msg_type = a[:3]
    if not (isinstance(version, int) and isinstance(h, bytes) and isinstance(msg_type, int)) or version < 0 or msg_type < 0:
        return None
    return (version, msg_type) if version > VERSION or msg_type > MSG_PING else None


def text_of(content: bytes) -> str:
    """What a content message shows as."""
    g = decode_gcm(content)
    if g is None:
        return "[unreadable message]"
    if g.text is not None:
        return g.text
    if g.msg_type == MSG_FILE_UPLOAD:
        return "[a file that cannot be read]"
    return "[message of type %d]" % g.msg_type


class Codec:
    """The member's codec over this wire: content is the GCM CBOR."""

    def encode(self, message: Message) -> bytes:
        g = of_message(message)
        return g.encode() if g is not None else b""

    def decode(self, plaintext: bytes) -> Optional[Message]:
        return to_message(plaintext)


# ---- files ----

MAX_FILE = 16 * 1024 * 1024
"""The largest file sent or fetched."""

_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-+()[]")
_FILETYPES = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "gif": "image/gif", "webp": "image/webp", "bmp": "image/bmp", "opus": "audio/opus"}


def safe_name(name: str) -> str:
    """A name from elsewhere as a file may be called here: printable ASCII from katzenqt's
    list, no leading dots, at most 200 characters."""
    s = "".join(ch if ch in _NAME_CHARS else "_" for ch in name).lstrip(".")
    return s[:200] or "unnamed"


def filetype_of(name: str) -> str:
    """The type katzenqt tags a file with, from its name."""
    parts = name.split(".")
    return _FILETYPES.get(parts[-1].lower(), "arbitrary") if len(parts) > 1 else "arbitrary"


def file_content(hash_: bytes, payload: bytes, filetype: str, basename: str, version: int = VERSION) -> bytes:
    """A file, as a member's content."""
    return Gcm(version=version, membership_hash=hash_, msg_type=MSG_FILE_UPLOAD, other={"file_upload": {"payload": payload, "filetype": filetype, "basename": basename}}).encode()


def file_of(g: Gcm):
    """The (payload, filetype, basename) a file message carries, or None."""
    f = (g.other or {}).get("file_upload") if g.msg_type == MSG_FILE_UPLOAD else None
    if not isinstance(f, dict) or not isinstance(f.get("payload"), bytes) or not isinstance(f.get("filetype"), str) or not isinstance(f.get("basename"), str):
        return None
    return f["payload"], f["filetype"], f["basename"]


def put_payload(cbor: bytes, payload: bytes) -> Optional[bytes]:
    """A file message with payload in place of the file's bytes, re-encoded in its own form."""
    g = decode_gcm(cbor)
    if g is None or file_of(g) is None:
        return None
    g.other["file_upload"]["payload"] = payload
    return g.encode()


def take_payload(cbor: bytes):
    """A file message with the file's bytes taken out, and the bytes; None for anything else."""
    g = decode_gcm(cbor)
    f = file_of(g) if g is not None else None
    if f is None:
        return None
    g.other["file_upload"]["payload"] = b""
    return g.encode(), f[0]


def chunk_count(n: int, max_: int) -> int:
    """How many boxes of max_ bytes a message of n bytes takes in a substream."""
    return (n + max_ - 2) // (max_ - 1)


# The smallest box a substream is read from, an I box: a reader takes substreams cut to any size.
MIN_BOX = 1 + 4 + READ_CAP_SIZE


def max_chunks(max_: int) -> int:
    """The most boxes a substream is sent or fetched in: a message of MAX_FILE+max_ bytes."""
    return chunk_count(MAX_FILE + max_, max_)


def substream_box(blob: bytes, max_: int, i: int) -> bytes:
    """The ith box of blob's substream."""
    size = max_ - 1
    tag = CONTINUED if i + 1 < chunk_count(len(blob), max_) else FINAL
    return tag + blob[i * size : (i + 1) * size]


def indirection(total: int, read_cap: bytes) -> bytes:
    """The 'I' box naming a substream of total boxes."""
    return INDIRECTION + total.to_bytes(4, "big") + read_cap


def assemble(boxes) -> Optional[bytes]:
    """The message a substream's boxes hold, once its 'F' box is among them."""
    if not boxes or boxes[-1][:1] != FINAL or any(b[:1] != CONTINUED for b in boxes[:-1]):
        return None
    return b"".join(b[1:] for b in boxes)


# ---- framing ----

FINAL = b"F"
CONTINUED = b"C"
INDIRECTION = b"I"


@dataclass(frozen=True)
class Chunk:
    kind: bytes  # FINAL, CONTINUED, INDIRECTION or b""
    data: bytes = b""
    total: Optional[int] = None


def frame(cbor: bytes) -> bytes:
    return FINAL + cbor


def unframe(box: bytes) -> Chunk:
    if not box:
        return Chunk(b"")
    tag, rest = box[:1], box[1:]
    if tag in (FINAL, CONTINUED):
        return Chunk(tag, rest)
    if tag == INDIRECTION:
        if len(rest) == 4 + READ_CAP_SIZE:
            return Chunk(tag, rest[4:], int.from_bytes(rest[:4], "big"))
        if len(rest) == READ_CAP_SIZE:
            return Chunk(tag, rest)
    return Chunk(b"")


def box_of(m: Message, stamp: Optional[bytes] = None, version: int = VERSION) -> Optional[bytes]:
    g = of_message(m, stamp, version)
    return frame(g.encode()) if g is not None else None


def message_of(plaintext: bytes) -> Optional[Message]:
    ch = unframe(plaintext)
    return to_message(ch.data) if ch.kind == FINAL else None


# ---- the reply to a new member ----


def reply_who_encode(reply: JoinReply, name: Callable[[bytes], Optional[str]], version: int = VERSION) -> bytes:
    """The reply for a JoinReply: the array form, or katzenqt's GroupChatReplyWho map for
    ``version`` 3. A member with no name takes no place, as katzenqt leaves out a member it
    does not know."""
    please_adds = []
    for m in reply.members:
        p = None
        if m is not None:
            read_cap, start = m
            n = name(key_of(read_cap))
            if n is not None:
                p = (n, bytes(key_of(read_cap)) + bytes(start))
        please_adds.append(p)
    rosters = [list(list(e) for e in r) if r is not None else None for r in reply.rosters]
    intros = [list(i) for i in reply.introductions]
    if version >= VERSION:
        return cbor2.dumps([[None if p is None else [p[0], p[1]] for p in please_adds], rosters, intros, reply.introducer, reply.newcomer])
    return cbor2.dumps(
        {
            "please_adds": [None if p is None else {"display_name": p[0], "read_cap": p[1]} for p in please_adds],
            "rosters": rosters,
            "introductions": intros,
            "introducer": reply.introducer,
            "newcomer": reply.newcomer,
        }
    )


def reply_who_array(please_adds, rosters=None, introductions=None, introducer=None, newcomer=None) -> bytes:
    """The array form of a reply from its parts; trailing Nones are left out."""
    a = [[None if p is None else [p[0], p[1]] for p in please_adds], rosters, introductions, introducer, newcomer]
    while len(a) > 1 and a[-1] is None:
        a.pop()
    return cbor2.dumps(a)


@dataclass
class ReplyWho:
    please_adds: list  # of (name, read_cap) or None
    rosters: Optional[list]
    introductions: Optional[list]
    introducer: Optional[int]
    newcomer: Optional[int]


def reply_who_decode(data: bytes) -> Optional[ReplyWho]:
    """A reply in either form, or None when it cannot be read."""
    if not data:
        return None
    major = data[0] >> 5
    try:
        m = cbor2.loads(data)
    except Exception:
        return None
    if major == 4:
        if not isinstance(m, list) or not 1 <= len(m) <= 5:
            return None
        m = m + [None] * (5 - len(m))
        please_adds, rosters, intros, introducer, newcomer = m
        if not isinstance(please_adds, list):
            return None
        adds = []
        for p in please_adds:
            if p is None:
                adds.append(None)
                continue
            if not (isinstance(p, list) and len(p) == 2 and isinstance(p[0], str) and 1 <= len(p[0]) <= 30 and isinstance(p[1], bytes) and len(p[1]) == READ_CAP_SIZE):
                return None
            adds.append((p[0], p[1]))
    elif major == 5:
        if not isinstance(m, dict) or not isinstance(m.get("please_adds"), list):
            return None
        adds = []
        for p in m["please_adds"]:
            if p is None:
                adds.append(None)
                continue
            if not isinstance(p, dict):
                return None
            n, c = p.get("display_name"), p.get("read_cap")
            if not isinstance(n, str) or not 1 <= len(n) <= 30 or not isinstance(c, bytes) or len(c) != READ_CAP_SIZE:
                return None
            adds.append((n, c))
        rosters, intros, introducer, newcomer = m.get("rosters"), m.get("introductions"), m.get("introducer"), m.get("newcomer")
    else:
        return None
    if rosters is not None:
        if not isinstance(rosters, list):
            return None
        out = []
        for r in rosters:
            if r is None:
                out.append(None)
                continue
            if not isinstance(r, list):
                return None
            entries = []
            for e in r:
                if not (isinstance(e, (list, tuple)) and len(e) == 2 and isinstance(e[0], int) and (e[1] is None or isinstance(e[1], int))):
                    return None
                entries.append((e[0], e[1]))
            out.append(entries)
        rosters = out
    if intros is not None:
        if not isinstance(intros, list):
            return None
        out = []
        for i in intros:
            if not (isinstance(i, (list, tuple)) and len(i) == 3 and isinstance(i[0], int) and isinstance(i[1], bytes) and isinstance(i[2], int)):
                return None
            out.append((i[0], i[1], i[2]))
        intros = out
    if introducer is not None and not isinstance(introducer, int) or newcomer is not None and not isinstance(newcomer, int):
        return None
    return ReplyWho(adds, rosters, intros, introducer, newcomer)


def to_join_reply(w: ReplyWho) -> Optional[JoinReply]:
    """The JoinReply a reply carries, or None when it carries no rosters or
    cannot be read: katzenqt's acks._join_reply."""
    places = len(w.please_adds)
    if w.rosters is None or w.introducer is None or w.newcomer != places or not w.introducer < places < ROSTER_MAX:
        return None
    if w.please_adds[w.introducer] is None or len(w.rosters) != places:
        return None
    keys = [key_of(p[1]) for p in w.please_adds if p is not None]
    if len(set(keys)) != len(keys):
        return None
    for r in w.rosters:
        for index, slot in r or ():
            if not 0 <= index < ROSTER_MAX or not (slot is None or 0 <= slot < places):
                return None
    intros = tuple(
        (by, index, member)
        for by, index, member in w.introductions or ()
        if 0 <= by < places and 0 <= member < places and len(index) == INDEX_SIZE
    )
    return JoinReply(
        members=tuple((p[1], start_of(p[1])) if p is not None else None for p in w.please_adds),
        rosters=tuple(tuple(r) if r is not None else None for r in w.rosters),
        introductions=intros,
        introducer=w.introducer,
        newcomer=w.newcomer,
    )


def without_rosters(w: ReplyWho) -> Optional[JoinReply]:
    """The JoinReply of a reply that carries no rosters: the members named,
    the introducer first, every roster unknown."""
    if w.rosters is not None:
        return None
    members = []
    seen = set()
    for p in w.please_adds:
        if p is None:
            continue
        k = bytes(key_of(p[1]))
        if k in seen:
            return None
        seen.add(k)
        members.append((p[1], start_of(p[1])))
    places = len(members)
    if not 1 <= places < ROSTER_MAX:
        return None
    return JoinReply(tuple(members), (None,) * places, (), 0, places)


__all__ = [
    "BODY_KEYS", "Chunk", "Codec", "Gcm", "Introduction", "IntroRef", "MAP_VERSION", "MAX_FILE", "MIN_BOX", "Message", "ReplyWho", "VERSION",
    "assemble", "box_of", "chunk_count", "counter", "decode_gcm", "file_content", "file_of", "filetype_of", "frame", "indirection",
    "key_of", "max_chunks", "membership_hash", "message_of", "of_message", "put_payload", "reply_who_array", "reply_who_decode",
    "reply_who_encode", "safe_name", "stamp_of", "start_of", "substream_box", "take_payload", "text_content", "text_of",
    "to_join_reply", "to_message", "unframe", "without_rosters",
]
