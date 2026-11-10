# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""A katzenqt1 group chat client without IO, after pigeonhole_protocols'
engine package: ``step`` takes the state and one input, from the user or
from the network, and returns the files to keep, what changed, and the
network work it asks for. The caller saves what changed before it carries
any of the work out.

The member state machine (``.member``) is driven as katzenqt's adapter
drives it: ``compose`` for each message sent, ``written`` once its box is
written, ``observe`` for each box read in order, ``handle`` for a new epoch
and a user's scan, and for a new member ``begin_induction``, then once
everything owed is written ``reply``, then ``introduce_now`` as soon as the
reply is sealed, ahead of anything sent while it sealed, so that the
Introduction is the box at the index the reply names. The member never
picks a box itself: its pool is emptied once and never refilled.

A message too long for one box, a file mostly, is written to a substream
of its own, 'C' boxes then an 'F' box, before the 'I' box naming it; a
file's bytes are kept in a file under the state directory and spliced out
of the message as it is read and written. A member's 'I' box is fetched
before their stream is read further.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from . import wire
from .member import events as mev
from .member.group import Group, Outgoing
from .member.ledger import Induction
from .member.trace import Recorder, TracedGroup
from .member.wire import INDEX_SIZE, KEY_SIZE

ChatID = str
Key = bytes
Index = bytes

MAX_LOG = 10000
WINDOW = 8
"""How many boxes of an upload are written at once."""
RECEIPT_DELAY = 30000
"""How long, in milliseconds, what we have read waits for a message of ours to acknowledge it
before a control message goes out to."""

NOT_FOUND, TOMBSTONE, DATA = 0, 1, 2


def backoff_ms(n: int) -> int:
    """How long to wait before reading a box that was not there, after n
    misses in a row."""
    return min(60000, 2000 << min(n, 5))


# ---- what the transport hands back ----


@dataclass(frozen=True)
class Keypair:
    write_cap: bytes
    read_cap: bytes
    first: Index


@dataclass(frozen=True)
class Minted:
    voucher: bytes
    payload: bytes
    write_cap: bytes
    read_cap: bytes
    secret_key: bytes
    version: int = 2
    """The payload's form: 2 the compact array, answered by a sealed box framed over boxes 1
    on; 1 the signed map, answered by an unframed MKEM reply in box 1."""


@dataclass(frozen=True)
class Inducted:
    name: str
    mutated_read_cap: bytes
    sealed_reply: bytes
    version: int = 2


@dataclass(frozen=True)
class Opened:
    who_reply: bytes
    mutated_write_cap: bytes


@dataclass(frozen=True)
class Outcome:
    """What reading a box found, with the index after it for data or a
    tombstone."""

    kind: int
    plaintext: bytes = b""
    next: Optional[Index] = None


# ---- inputs: what a user asks ----


@dataclass(frozen=True)
class Create:
    chat: ChatID
    name: str


@dataclass(frozen=True)
class Join:
    chat: ChatID
    name: str


@dataclass(frozen=True)
class Induct:
    chat: ChatID
    code: str


@dataclass(frozen=True)
class Send:
    chat: ChatID
    text: str


@dataclass(frozen=True)
class Ping:
    """Asks the group's members to play their ping sound."""

    chat: ChatID


@dataclass(frozen=True)
class SendFile:
    chat: ChatID
    name: str
    data: bytes


@dataclass(frozen=True)
class Scan:
    chat: ChatID


@dataclass(frozen=True)
class Leave:
    chat: ChatID


@dataclass(frozen=True)
class RemoveMember:
    chat: ChatID
    who: Key


@dataclass(frozen=True)
class Clear:
    chat: ChatID


@dataclass(frozen=True)
class Rename:
    chat: ChatID
    to: str


# ---- inputs: what came of an action ----


@dataclass(frozen=True)
class Created:
    chat: ChatID
    joining: bool
    keypair: Keypair


@dataclass(frozen=True)
class Wrote:
    chat: ChatID
    job: int
    index: Index
    next: Index


@dataclass(frozen=True)
class Refused:
    """A write found its box holding other bytes."""

    chat: ChatID
    job: int


@dataclass(frozen=True)
class Read:
    chat: ChatID
    stream: Key
    index: Index
    outcome: Outcome


@dataclass(frozen=True)
class Wake:
    chat: ChatID
    stream: Key


@dataclass(frozen=True)
class Tick:
    """A receipt is due for the content that came in unreceipted, numbered n."""

    chat: ChatID
    n: int


@dataclass(frozen=True)
class ScanRead:
    chat: ChatID
    stream: Key
    index: Index
    outcome: Outcome


@dataclass(frozen=True)
class Walked:
    chat: ChatID
    stream: Key
    target: Optional[Index]
    skipped: Tuple[Index, ...]
    steps: int


@dataclass(frozen=True)
class Derived:
    chat: ChatID
    stream: Key
    indexes: Tuple[Index, ...]


@dataclass(frozen=True)
class MintedIn:
    chat: ChatID
    minted: Minted
    box1: Index


@dataclass(frozen=True)
class OpenedIn:
    chat: ChatID
    opened: Opened


@dataclass(frozen=True)
class JoinerPayload:
    chat: ChatID
    voucher: bytes
    voucher_write_cap: bytes
    payload: bytes
    box1: Index


@dataclass(frozen=True)
class SealedReply:
    chat: ChatID
    inducted: Inducted


@dataclass(frozen=True)
class Published:
    chat: ChatID


@dataclass(frozen=True)
class Epoch:
    n: int


@dataclass(frozen=True)
class Failed:
    chat: ChatID
    what: str


@dataclass(frozen=True)
class Loaded:
    """An upload's message read back from its file, or lost."""

    chat: ChatID
    job: int
    data: bytes
    lost: bool


@dataclass(frozen=True)
class Substream:
    chat: ChatID
    job: int
    keypair: Keypair


@dataclass(frozen=True)
class WroteChunk:
    chat: ChatID
    job: int
    n: int
    next: Index


@dataclass(frozen=True)
class ChunkIndexes:
    chat: ChatID
    job: int
    start: Index
    indexes: Tuple[Index, ...]


@dataclass(frozen=True)
class ReadChunk:
    chat: ChatID
    stream: Key
    index: Index
    outcome: Outcome


# ---- actions: network or disk work; each comes back as the input named ----


@dataclass(frozen=True)
class DoCreate:
    """A new stream: Created."""

    chat: ChatID
    joining: bool


@dataclass(frozen=True)
class DoWrite:
    """Write a box, retrying until written: Wrote, or Refused."""

    chat: ChatID
    job: int
    write_cap: bytes
    index: Index
    box: bytes


@dataclass(frozen=True)
class DoRead:
    """Read a box once: Read."""

    chat: ChatID
    stream: Key
    read_cap: bytes
    index: Index


@dataclass(frozen=True)
class DoWake:
    """Wake after ms milliseconds."""

    chat: ChatID
    stream: Key
    ms: int


@dataclass(frozen=True)
class DoTick:
    """Tick after ms milliseconds."""

    chat: ChatID
    ms: int
    n: int


@dataclass(frozen=True)
class DoScanRead:
    chat: ChatID
    stream: Key
    read_cap: bytes
    index: Index


@dataclass(frozen=True)
class DoWalk:
    chat: ChatID
    stream: Key
    start: Index
    targets: Tuple[int, ...]
    keep: int


@dataclass(frozen=True)
class DoDerive:
    chat: ChatID
    stream: Key
    start: Index
    count: int


@dataclass(frozen=True)
class DoMint:
    """Mint a voucher and publish its box 0: MintedIn."""

    chat: ChatID
    write_cap: bytes
    name: str
    version: int = 2
    """The payload's form to mint: 2 the compact array, 1 the signed map."""


@dataclass(frozen=True)
class DoAwaitReply:
    """Wait for the reply from box 1 and open it: OpenedIn. A version 2 reply is framed, `C`
    boxes then an `F` box, from box 1 on; a version 1 reply is box 1 alone, unframed."""

    chat: ChatID
    secret_key: bytes
    voucher_read_cap: bytes
    box1: Index
    write_cap: bytes
    version: int = 1


@dataclass(frozen=True)
class DoReadVoucher:
    """Read a voucher's box 0: JoinerPayload."""

    chat: ChatID
    voucher: bytes


@dataclass(frozen=True)
class DoSeal:
    """Seal the reply to a voucher: SealedReply."""

    chat: ChatID
    voucher: bytes
    payload: bytes
    who_reply: bytes


@dataclass(frozen=True)
class DoPublish:
    """Write the sealed reply from box 1 on, retrying until written: Published. Version 2 is
    framed in pieces of a box less one byte, `C` then `F`; version 1 is box 1 alone."""

    chat: ChatID
    voucher_write_cap: bytes
    box1: Index
    reply: bytes
    version: int = 1


@dataclass(frozen=True)
class DoDelete:
    """Delete a file under the state directory."""

    file: str


@dataclass(frozen=True)
class DoLoad:
    """Read back the file holding an upload's message: Loaded."""

    chat: ChatID
    job: int
    file: str


@dataclass(frozen=True)
class DoSubstream:
    """A new stream for an upload: Substream."""

    chat: ChatID
    job: int


@dataclass(frozen=True)
class DoWriteChunk:
    """Write the nth box of an upload: WroteChunk, or Refused."""

    chat: ChatID
    job: int
    n: int
    write_cap: bytes
    index: Index
    box: bytes


@dataclass(frozen=True)
class DoChunkIndexes:
    """Derive the indexes of count boxes after start of an upload's substream: ChunkIndexes."""

    chat: ChatID
    job: int
    start: Index
    count: int


@dataclass(frozen=True)
class DoReadChunk:
    """Read a box of the substream an I box named: ReadChunk."""

    chat: ChatID
    stream: Key
    read_cap: bytes
    index: Index


# ---- state ----


@dataclass
class Upload:
    """A message too long for a box, being written to a substream of its own."""

    file: str
    """Holds the message under the state directory, until it is written."""
    box_size: int
    total: int
    write_cap: bytes = b""
    """The substream's, once made."""
    sent: int = 0
    """The boxes written so far; next is the index of the next."""
    next: Index = b""


@dataclass
class Job:
    """A box to write to our own stream, in order."""

    id: int
    token: Optional[int]
    """The message's, to tell the member when it is written; None for a
    rewrite."""
    index: Optional[Index]
    """Chosen when the job is first sent, given for a rewrite."""
    box: bytes
    """Empty for a tombstone."""
    line: Optional[int] = None
    upload: Optional[Upload] = None
    """Set for a message too long for a box: its substream is written first, and box is then
    the I box naming it."""
    packed: List[int] = field(default_factory=list)
    """The lines of the messages packed in after line's."""


SENT, PENDING = 0, 1


@dataclass
class Notice:
    kind: str
    args: Tuple[str, ...] = ()


@dataclass
class Attachment:
    """A file a line carries, kept under the state directory."""

    name: str
    filetype: str
    size: int
    file: str


@dataclass
class Line:
    id: int
    sender: Optional[Key] = None
    index: Optional[Index] = None
    text: str = ""
    notice: Optional[Notice] = None
    status: int = SENT
    idx64: Optional[int] = None
    time: int = 0
    attachment: Optional[Attachment] = None


@dataclass
class Download:
    """A message a member's I box announced, being read from its substream. Their stream is
    read no further until it is."""

    stream: Key
    index: Index
    next: Index
    read_cap: bytes
    total: Optional[int] = None


@dataclass
class Joining:
    """Joining a group through a voucher we minted: minting until code is
    set."""

    code: str = ""
    secret_key: bytes = b""
    voucher_read_cap: bytes = b""
    box1: Index = b""
    version: int = 1
    """The payload's form, hence the reply's; state saved before there were two is 1."""


@dataclass
class Sealed:
    name: str
    mutated_read_cap: bytes
    reply: bytes
    version: int = 1


@dataclass
class Inducting:
    """Inducting a member whose voucher we were given: reading the voucher
    until payload is set."""

    voucher: bytes
    payload: Optional[bytes] = None
    voucher_write_cap: bytes = b""
    box1: Index = b""
    sealing: bool = False
    sealed: Optional[Sealed] = None


@dataclass
class Chat:
    id: ChatID
    name: str
    write_cap: bytes = b""
    next_write: Index = b""
    group: Optional[Group] = None
    cursors: Dict[Key, Index] = field(default_factory=dict)
    """Where we read each member's stream next."""
    names: Dict[Key, str] = field(default_factory=dict)
    jobs: List[Job] = field(default_factory=list)
    log: List[Line] = field(default_factory=list)
    joining: Optional[Joining] = None
    inducting: Optional[Inducting] = None
    next_id: int = 0
    downloads: List[Download] = field(default_factory=list)

    def files(self) -> List[str]:
        """The files the conversation's lines and jobs hold."""
        return [l.attachment.file for l in self.log if l.attachment is not None] + [j.upload.file for j in self.jobs if j.upload is not None]

    def fresh(self) -> int:
        self.next_id += 1
        return self.next_id - 1

    def job(self, id: int) -> Optional[Job]:
        for j in self.jobs:
            if j.id == id:
                return j
        return None

    def acknowledged(self, line: Line) -> bool:
        """Whether any member has acknowledged our line."""
        if self.group is None or line.idx64 is None:
            return False
        return any(line.idx64 <= n for n in self.group.ledger.acked_by.values())


@dataclass
class State:
    me: str
    chats: List[Chat] = field(default_factory=list)

    def chat(self, id: ChatID) -> Optional[Chat]:
        for c in self.chats:
            if c.id == id:
                return c
        return None

    def chat_named(self, name: str) -> Optional[Chat]:
        for c in self.chats:
            if c.name == name:
                return c
        return None

    def wanted(self, a) -> bool:
        """Whether an action tried again is still of use: its chat is still
        here and, for a voucher's box, still waiting for it."""
        if isinstance(a, DoAwaitReply):
            c = self.chat(a.chat)
            return c is not None and c.joining is not None and c.joining.secret_key == a.secret_key
        if isinstance(a, DoReadVoucher):
            c = self.chat(a.chat)
            return c is not None and c.inducting is not None and c.inducting.payload is None and c.inducting.voucher == a.voucher
        if isinstance(a, (DoWrite, DoRead, DoScanRead, DoWalk, DoDerive, DoSubstream, DoWriteChunk, DoChunkIndexes, DoReadChunk)):
            return self.chat(a.chat) is not None
        return True


# ---- results ----


@dataclass
class FileWrite:
    file: str
    data: bytes


@dataclass
class Changes:
    chats: set = field(default_factory=set)
    lines: Dict[ChatID, set] = field(default_factory=dict)
    dropped: Dict[ChatID, set] = field(default_factory=dict)
    removed: set = field(default_factory=set)

    def empty(self) -> bool:
        return not (self.chats or self.lines or self.dropped or self.removed)


@dataclass
class Result:
    """Files to keep, then the state to save, then work to start."""

    files: List[FileWrite] = field(default_factory=list)
    changes: Changes = field(default_factory=Changes)
    actions: list = field(default_factory=list)


def voucher_code(voucher: bytes) -> str:
    return base64.b64encode(voucher).decode()


def parse_voucher_code(code: str) -> bytes | None:
    try:
        voucher = base64.b64decode("".join(code.split()), validate=True)
    except ValueError:
        return None
    return voucher if len(voucher) == 32 else None


def voucher_file(group: str) -> str:
    return "voucher-" + slug(group) + ".txt"


def slug(s: str) -> str:
    return "".join(ch if ch.isascii() and ch.isalnum() else "_" for ch in s)


def size_text(n: int) -> str:
    if n < 1024:
        return "%d bytes" % n
    if n < 1024 * 1024:
        return "%d KB" % ((n + 512) // 1024)
    return "%d.%d MB" % (n // (1024 * 1024), n % (1024 * 1024) * 10 // (1024 * 1024))


def file_text(a: Attachment) -> str:
    return "[file %s, %s]" % (a.name, size_text(a.size))


def sanitize(name: str) -> str:
    out = "".join(ch for ch in name if not (ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F))
    return out or "unnamed"


def new_group(read_cap: bytes, *, reply: Optional[mev.JoinReply] = None) -> Group:
    """A member this client writes for: it never allocates a box itself."""
    if reply is None:
        g = Group.found(read_cap, [read_cap], codec=wire.Codec())
    else:
        g = Group.joined(read_cap, reply, codec=wire.Codec())
    g.pool = []
    g.deriving = True
    return g


def membership(g: Group) -> bytes:
    """The sender's view of the group, for the content it writes: itself
    and every member it reads. The member stamps its own control messages."""
    return g.membership()


def acknowledge(g: Group) -> List[Outgoing]:
    """A control message carrying whatever g owes, acknowledgements among it, or none when
    nothing is. The member is katzenqt's as copied, so this is made of its parts."""
    owes_acks = False
    for member in g.rosters.known(g.me).values():
        r = g.readers.get(member) if member else None
        if r is not None and g.ledger.owed(r.stream, r.run) is not None:
            owes_acks = True
    if not g._owes_control() and not owes_acks:
        return []
    g.allocates = False
    m, p = g._control()
    return [g._stage(g._with_acks(m, p), p)]


def tracer_from_env() -> Optional[Recorder]:
    """A member trace recorder writing to the file PIGEONHOLE_TRACE names, one
    JSON line per call on each group, for replay against the model; None
    when unset."""
    path = os.environ.get("PIGEONHOLE_TRACE")
    if not path:
        return None
    return Recorder(open(path, "a", buffering=1))


class Engine:
    def __init__(self, state: State, max_plaintext: int, epoch: int = 0, tracer: Optional[Recorder] = None, wire_version: int = wire.VERSION, pack: bool = True, receipt_delay: int = RECEIPT_DELAY):
        if wire_version not in (wire.MAP_VERSION, wire.ARRAY_VERSION, wire.VERSION):
            raise ValueError("wire_version must be %d, %d or %d" % (wire.MAP_VERSION, wire.ARRAY_VERSION, wire.VERSION))
        self.state = state
        # What this client writes and mints; it reads both forms.
        self.wire_version = wire_version
        self.max_plaintext = max_plaintext
        # Pack a text message sent into the one before it, while that is not yet being written
        # and both fit in a box; send a receipt receipt_delay after content came in, or never
        # for 0.
        self.pack = pack
        self.receipt_delay = receipt_delay
        self.tracer = tracer if tracer is not None else tracer_from_env()
        if self.tracer is not None:
            for c in state.chats:
                if c.group is not None:
                    c.group = TracedGroup.of(c.group, self.tracer)
        # The replicas' epoch as last reported; a group made now starts there,
        # so that what it writes before the next report is not taken for
        # hundreds of epochs old when the report comes.
        self.epoch = epoch
        # Under way on the network; not saved, since a restart begins it again.
        self._writing: set = set()
        self._reading: set = set()  # (chat, stream) with a read out or a wake pending
        self._misses: Dict[Tuple[ChatID, Key], int] = {}
        # Uploads, by (chat, job): those making a substream or deriving indexes; the indexes
        # from the first box not yet written on, as far as derived; the boxes being written;
        # those written after one not yet written, as (n, index after); those reading their
        # message back; and the messages, once made or read back.
        self._uploading: set = set()
        self._ahead: Dict[tuple, list] = {}
        self._chunks_out: Dict[tuple, set] = {}
        self._landed: Dict[tuple, list] = {}
        self._loading: set = set()
        self._blobs: Dict[tuple, bytes] = {}
        # Downloads, by (chat, stream): the index of the next box and the boxes so far; and
        # the bytes of a file one just brought, by (sender, index), while the member reads the
        # message without them.
        self._fetched: Dict[tuple, tuple] = {}
        self._arriving: Dict[tuple, bytes] = {}
        # Content come in that no message of ours has acknowledged yet, numbered from
        # _receipts by chat, and the number each chat has a Tick out for.
        self._unreceipted: Dict[ChatID, int] = {}
        self._ticking: Dict[ChatID, int] = {}
        self._receipts = 0
        self._now = 0
        self._out = Result()

    def _voucher_form(self) -> int:
        return 1 if self.wire_version == wire.MAP_VERSION else 2

    def _traced(self, g: Group) -> Group:
        return g if self.tracer is None else TracedGroup.of(g, self.tracer)

    # ---- bookkeeping ----

    def _begin(self, now: int) -> None:
        self._now = now
        self._out = Result()

    def _emit(self, a) -> None:
        self._out.actions.append(a)

    def _keep(self, file: str, data: bytes) -> None:
        self._out.files.append(FileWrite(file, data))

    def _dirty(self, c: Chat) -> None:
        self._out.changes.chats.add(c.id)

    def _line_changed(self, c: Chat, id: int) -> None:
        self._out.changes.lines.setdefault(c.id, set()).add(id)

    def _line_dropped(self, c: Chat, id: int) -> None:
        self._out.changes.lines.get(c.id, set()).discard(id)
        self._out.changes.dropped.setdefault(c.id, set()).add(id)

    def _say(self, c: Chat, line: Line) -> int:
        line.id = c.fresh()
        line.time = self._now
        c.log.append(line)
        self._dirty(c)
        self._line_changed(c, line.id)
        if len(c.log) > MAX_LOG:
            for d in c.log[: len(c.log) - MAX_LOG]:
                self._unlink(d)
                self._line_dropped(c, d.id)
            c.log = c.log[len(c.log) - MAX_LOG :]
        return line.id

    def _unlink(self, line: Line) -> None:
        if line.attachment is not None:
            self._emit(DoDelete(line.attachment.file))

    def _notice(self, c: Chat, kind: str, *args: str) -> None:
        self._say(c, Line(0, notice=Notice(kind, args)))

    # ---- writing ----

    def _enqueue(self, c: Chat, outgoing: List[Outgoing], content: Optional[bytes], line: Optional[int], payload: Optional[bytes] = None) -> None:
        """Queue each message to write, in order; line shows the one carrying content, into
        which the bytes of a file it carries, payload, are put. A message too long for a box
        goes to a substream, written before the I box naming it."""
        for o in outgoing:
            g = c.group
            if g is None:
                continue
            mine = content is not None and o.message.content is not None and o.message.content == content
            box = wire.box_of(o.message, version=self.wire_version)
            if box is not None and payload is not None and mine:
                full = wire.put_payload(box[1:], payload)
                box = wire.frame(full) if full is not None else None
            if box is not None and len(box) <= self.max_plaintext:
                c.jobs.append(Job(c.fresh(), o.token, None, box, line if mine else None))
                self._dirty(c)
                continue
            if box is not None and len(box) - 1 <= wire.MAX_FILE + self.max_plaintext:
                blob, id = box[1:], c.fresh()
                file = "spool/%s-%d-%d.cbor" % (slug(c.name), self._now, id)
                self._keep(file, blob)
                self._blobs[(c.id, id)] = blob
                u = Upload(file, self.max_plaintext, wire.chunk_count(len(blob), self.max_plaintext))
                c.jobs.append(Job(id, o.token, None, b"", line if mine else None, u))
                self._dirty(c)
                continue
            g.abandoned(o.token)
            self._notice(c, "too_long" if mine else "not_written")

    def _compose(self, c: Chat, content: bytes) -> List[Outgoing]:
        """What the member sends now, content last; it acknowledges all we have read."""
        self._unreceipted.pop(c.id, None)
        return c.group.compose(content)

    def _pack(self, c: Chat, text: str, line: int) -> bool:
        """Put text, shown as line, into the last job when that is a text message not yet being
        written, nothing is owed ahead of it, and both fit in a box."""
        if not self.pack or self.wire_version < wire.VERSION or not c.jobs or c.group._owes_control():
            return False
        j = c.jobs[-1]
        if j.token is None or j.index is not None or j.upload is not None or j.line is None or wire.unframe(j.box).kind != wire.FINAL:
            return False
        packed = wire.pack(j.box[1:], text)
        if packed is None or 1 + len(packed) > self.max_plaintext:
            return False
        j.box = wire.frame(packed)
        j.packed.append(line)
        self._dirty(c)
        return True

    def _rewrite(self, c: Chat, index: Index, box: bytes) -> None:
        c.jobs.append(Job(c.fresh(), None, index, box))
        self._dirty(c)

    # ---- reading ----

    def _attachment_file(self, c: Chat, name: str) -> str:
        return "attachments/%s/%d-%d-%s" % (slug(c.name), self._now, c.next_id, name)

    def _deliver(self, c: Chat, sender: Key, index: Index, content: bytes) -> None:
        """Add a line for content from sender, and keep the file it carries."""
        if c.group is not None and sender != c.group.me and c.id not in self._unreceipted:
            self._receipts += 1
            self._unreceipted[c.id] = self._receipts
        g = wire.decode_gcm(content)
        f = wire.file_of(g) if g is not None else None
        if f is None and g is not None and g.msg_type == wire.MSG_PING:
            self._notice(c, "pinged", self._label(c, sender))
            return
        if f is None:
            for t in wire.texts_of(content):
                self._say(c, Line(0, sender=sender, index=index, text=t))
            return
        payload, filetype, basename = f
        payload = self._arriving.get((sender, index), payload)
        name = wire.safe_name(basename)
        a = Attachment(name, filetype, len(payload), self._attachment_file(c, name))
        if len(payload) > wire.MAX_FILE:
            self._say(c, Line(0, sender=sender, index=index, text="[file %s, %s, too large to keep]" % (name, size_text(a.size))))
            return
        self._keep(a.file, payload)
        self._say(c, Line(0, sender=sender, index=index, text=file_text(a), attachment=a))

    def _drop_lines(self, c: Chat, keep: Callable[[Line], bool]) -> None:
        kept = []
        for line in c.log:
            if keep(line):
                kept.append(line)
            else:
                self._unlink(line)
                self._line_dropped(c, line.id)
        if len(kept) != len(c.log):
            self._dirty(c)
        c.log = kept

    def _effects(self, c: Chat, effects: list) -> None:
        for ef in effects:
            if isinstance(ef, mev.WriteBox):
                if ef.plaintext:
                    self._rewrite(c, ef.index, ef.plaintext)
            elif isinstance(ef, mev.WriteTombstone):
                self._rewrite(c, ef.index, b"")
            elif isinstance(ef, mev.ReadBox):
                self._emit(DoScanRead(c.id, ef.stream, ef.read_cap, ef.index))
            elif isinstance(ef, mev.DeriveIndexes):
                self._emit(DoDerive(c.id, ef.stream, ef.start, ef.count))
            elif isinstance(ef, mev.Walk):
                self._emit(DoWalk(c.id, ef.stream, ef.start, tuple(ef.targets), ef.keep))
            elif isinstance(ef, mev.Deliver):
                self._deliver(c, ef.sender, ef.index, ef.content)
            elif isinstance(ef, mev.Expire):
                self._drop_lines(c, lambda l: not (l.sender == ef.sender and l.index == ef.index))

    def _label(self, c: Chat, key: Key) -> str:
        if c.group is not None and c.group.me == key:
            return "me"
        return "~" + c.names.get(key, "?")

    def _remark(self, c: Chat, stream: Key, plaintext: bytes) -> None:
        """Note who an Introduction introduced, or a message this client
        cannot show."""
        ch = wire.unframe(plaintext)
        if ch.kind == wire.FINAL:
            m = wire.to_message(ch.data)
            if m is None:
                u = wire.unsupported(ch.data)
                if u is not None:
                    self._notice(c, "unsupported", self._label(c, stream), str(u[1]), str(u[0]))
                return
            if m.introduction is None:
                return
            k = bytes(wire.key_of(m.introduction.read_cap))
            if k not in c.names:
                c.names[k] = m.introduction.name
                self._dirty(c)
            if c.group is not None and c.group.me == k:
                return
            self._notice(c, "member_added", self._label(c, stream), m.introduction.name)
        elif ch.kind == wire.CONTINUED:
            self._notice(c, "unreadable", self._label(c, stream))

    # ---- under way ----

    def _start_reads(self, c: Chat) -> None:
        g = c.group
        if g is None:
            return
        for r in g.readers.values():
            k = (c.id, r.stream)
            if k in self._reading or any(d.stream == r.stream for d in c.downloads):
                continue
            at = c.cursors.get(r.stream)
            if at is None:
                at = r.next
                c.cursors[r.stream] = at
                self._dirty(c)
            self._reading.add(k)
            self._emit(DoRead(c.id, r.stream, r.read_cap, at))

    def _start_write(self, c: Chat) -> None:
        if c.id in self._writing or not c.write_cap or not c.jobs:
            return
        # While a reply is sealing, nothing takes the next index: the reply
        # names it as where the new member starts reading, and the
        # Introduction, queued first once the reply is sealed, must be there.
        if c.inducting is not None and c.inducting.sealing:
            return
        j = c.jobs[0]
        if j.upload is not None and j.upload.sent < j.upload.total:
            return
        if j.index is None:
            j.index = c.next_write
            self._dirty(c)
        self._writing.add(c.id)
        self._emit(DoWrite(c.id, j.id, c.write_cap, j.index, j.box))

    def _start_receipt(self, c: Chat) -> None:
        """Ask for a Tick when a receipt is due."""
        n = self._unreceipted.get(c.id)
        if n is None or self.receipt_delay <= 0 or self._ticking.get(c.id) == n:
            return
        self._ticking[c.id] = n
        self._emit(DoTick(c.id, self.receipt_delay, n))

    def _start_induction(self, c: Chat) -> None:
        """Seal the new member's reply, once everything owed is written."""
        i, g = c.inducting, c.group
        if i is None or g is None or i.payload is None or i.sealing or i.sealed is not None or any(j.token is not None for j in c.jobs):
            return

        def name(key: bytes) -> Optional[str]:
            if key == g.me:
                return self.state.me
            return c.names.get(bytes(key))

        # A joiner that minted the map form of the voucher reads only the map form of the reply.
        who = wire.reply_who_encode(g.reply(c.next_write), name, wire.MAP_VERSION if i.payload[0] >> 5 == 5 else wire.VERSION)
        self._emit(DoSeal(c.id, i.voucher, i.payload, who))
        i.sealing = True
        self._dirty(c)

    def _start_uploads(self, c: Chat) -> None:
        """Write the next boxes of each upload, making its substream, reading its message back
        and deriving their indexes first."""
        for j in c.jobs:
            u, key = j.upload, (c.id, j.id)
            if u is None or u.sent >= u.total or key in self._uploading:
                continue
            if not u.write_cap:
                self._uploading.add(key)
                self._emit(DoSubstream(c.id, j.id))
                continue
            blob = self._blobs.get(key)
            if blob is None:
                if key not in self._loading:
                    self._loading.add(key)
                    self._emit(DoLoad(c.id, j.id, u.file))
                continue
            want = min(WINDOW, u.total - u.sent)
            ahead = self._ahead.get(key, [])
            if len(ahead) < want:
                self._uploading.add(key)
                self._emit(DoChunkIndexes(c.id, j.id, u.next, min(2 * WINDOW, u.total - u.sent) - 1))
                continue
            out = self._chunks_out.setdefault(key, set())
            for i, index in enumerate(ahead[:want]):
                n = u.sent + i
                if n in out or any(l[0] == n for l in self._landed.get(key, [])):
                    continue
                out.add(n)
                self._emit(DoWriteChunk(c.id, j.id, n, u.write_cap, index, wire.substream_box(blob, u.box_size, n)))

    def _start_downloads(self, c: Chat) -> None:
        for d in c.downloads:
            k = (c.id, d.stream)
            if k in self._reading:
                continue
            at = self._fetched.get(k, (wire.start_of(d.read_cap),))[0]
            self._reading.add(k)
            self._emit(DoReadChunk(c.id, d.stream, d.read_cap, at))

    def _pump(self) -> None:
        for c in self.state.chats:
            self._start_write(c)
            self._start_reads(c)
            self._start_induction(c)
            self._start_uploads(c)
            self._start_downloads(c)
            self._start_receipt(c)

    def _stop_reading(self, chat: ChatID, stream: Key) -> None:
        self._reading.discard((chat, stream))

    def _missed(self, chat: ChatID, stream: Key) -> int:
        n = self._misses.get((chat, stream), 0)
        self._misses[(chat, stream)] = n + 1
        return n

    def _hit(self, chat: ChatID, stream: Key) -> None:
        self._misses.pop((chat, stream), None)

    def _follow_reader(self, c: Chat, stream: Key) -> None:
        """Move a cursor that a scan has carried past it."""
        if c.group is None:
            return
        r = c.group.readers.get(stream)
        at = c.cursors.get(stream)
        if r is not None and at is not None and wire.counter(at) < wire.counter(r.next):
            c.cursors[stream] = r.next
            self._dirty(c)

    def _forget(self, chat: ChatID) -> None:
        self._writing.discard(chat)
        self._unreceipted.pop(chat, None)
        self._ticking.pop(chat, None)
        for m in (self._uploading, self._loading, self._reading):
            m -= {k for k in m if k[0] == chat}
        for d in (self._misses, self._ahead, self._chunks_out, self._landed, self._blobs, self._fetched):
            for k in [k for k in d if k[0] == chat]:
                del d[k]

    def _finish(self, c: Chat, d: Download, blob: Optional[bytes]) -> None:
        """End a download: tell the member what came of it, in its place in the stream."""
        self._fetched.pop((c.id, d.stream), None)
        c.downloads = [x for x in c.downloads if x.stream != d.stream]
        self._dirty(c)
        without = blob
        if blob is not None and (taken := wire.take_payload(blob)) is not None:
            without, payload = taken
            self._arriving = {(d.stream, d.index): payload}
        if without is not None and wire.to_message(without) is not None:
            self._remark(c, d.stream, wire.frame(without))
        else:
            without = None
            self._notice(c, "not_fetched", self._label(c, d.stream))
        if c.group is not None:
            self._effects(c, c.group.observe(d.stream, d.index, without, d.next))
        self._arriving = {}

    def _cancel_held(self, c: Chat) -> None:
        if c.group is not None and c.group.ledger.induction is Induction.INDUCTING:
            c.group.cancel_induction()

    # ---- inputs ----

    def _chat(self, id: ChatID) -> Optional[Chat]:
        c = self.state.chat(id)
        if c is not None:
            self._dirty(c)
        return c

    def _handle(self, inp) -> None:
        s = self.state
        if isinstance(inp, Create):
            if (c := s.chat_named(inp.name)) is not None:
                self._notice(c, "name_taken", inp.name)
                return
            c = Chat(inp.chat, inp.name)
            s.chats.append(c)
            self._dirty(c)
            self._emit(DoCreate(c.id, False))
        elif isinstance(inp, Join):
            if (c := s.chat_named(inp.name)) is not None:
                self._notice(c, "name_taken_joining", inp.name)
                return
            c = Chat(inp.chat, inp.name, joining=Joining())
            s.chats.append(c)
            self._dirty(c)
            self._emit(DoCreate(c.id, True))
        elif isinstance(inp, Created):
            c = self._chat(inp.chat)
            if c is None:
                return
            c.write_cap, c.next_write = inp.keypair.write_cap, inp.keypair.first
            if inp.joining:
                self._emit(DoMint(c.id, c.write_cap, s.me, self._voucher_form()))
                self._notice(c, "minting")
                return
            c.group = self._traced(new_group(inp.keypair.read_cap))
            self._effects(c, c.group.handle(mev.EpochChanged(self.epoch)))
            self._notice(c, "new_group")
        elif isinstance(inp, MintedIn):
            c = self._chat(inp.chat)
            if c is None:
                return
            m = inp.minted
            code = voucher_code(m.voucher)
            self._emit(DoAwaitReply(c.id, m.secret_key, m.read_cap, inp.box1, c.write_cap, m.version))
            c.joining = Joining(code, m.secret_key, m.read_cap, inp.box1, m.version)
            self._keep(voucher_file(c.name), (code + "\n").encode())
            self._notice(c, "voucher_minted", code, c.name, voucher_file(c.name))
        elif isinstance(inp, OpenedIn):
            c = self._chat(inp.chat)
            if c is None or c.joining is None or not c.joining.code or c.group is not None:
                return
            joined = joined_from(inp.opened)
            if joined is None:
                c.joining = None
                self._notice(c, "reply_unreadable")
                return
            g, who = joined
            for p in who.please_adds:
                if p is not None:
                    c.names[bytes(wire.key_of(p[1]))] = sanitize(p[0])
            wc = inp.opened.mutated_write_cap
            c.group, c.write_cap, c.next_write = self._traced(g), wc, wc[len(wc) - INDEX_SIZE :]
            c.joining, c.cursors = None, {}
            self._effects(c, c.group.handle(mev.EpochChanged(self.epoch)))
            self._notice(c, "joined")
        elif isinstance(inp, Induct):
            c = self._chat(inp.chat)
            if c is None:
                return
            voucher = parse_voucher_code(inp.code)
            if c.group is None:
                self._notice(c, "not_joined_yet")
            elif c.inducting is not None and c.inducting.payload is not None:
                self._notice(c, "already_adding")
            elif voucher is None:
                self._notice(c, "not_a_voucher")
            else:
                c.inducting = Inducting(voucher)
                self._emit(DoReadVoucher(c.id, voucher))
                self._notice(c, "reading_voucher")
        elif isinstance(inp, JoinerPayload):
            c = self._chat(inp.chat)
            if c is None or c.inducting is None or c.inducting.payload is not None or c.inducting.voucher != inp.voucher:
                return
            if c.group is not None:
                self._unreceipted.pop(c.id, None)
                self._enqueue(c, c.group.begin_induction(), None, None)
            c.inducting = Inducting(inp.voucher, inp.payload, inp.voucher_write_cap, inp.box1)
        elif isinstance(inp, SealedReply):
            c = self._chat(inp.chat)
            if c is None or c.inducting is None:
                return
            i = c.inducting
            i.sealing = False
            i.sealed = Sealed(inp.inducted.name, inp.inducted.mutated_read_cap, inp.inducted.sealed_reply, inp.inducted.version)
            # The Introduction goes ahead of anything queued while the reply
            # was sealing, so it is the box at the index the reply names.
            if c.group is not None:
                waiting, c.jobs = c.jobs, []
                self._enqueue(c, [c.group.introduce_now(sanitize(i.sealed.name), i.sealed.mutated_read_cap)], None, None)
                c.jobs.extend(waiting)
                self._dirty(c)
            self._emit(DoPublish(c.id, i.voucher_write_cap, i.box1, i.sealed.reply, i.sealed.version))
        elif isinstance(inp, Published):
            c = self._chat(inp.chat)
            if c is None or c.inducting is None or c.inducting.sealed is None:
                return
            sealed = c.inducting.sealed
            who = sanitize(sealed.name)
            c.inducting = None
            c.names[bytes(wire.key_of(sealed.mutated_read_cap))] = who
            self._notice(c, "added", who)
        elif isinstance(inp, Send):
            c = self._chat(inp.chat)
            if c is None:
                return
            g = c.group
            if g is None:
                self._notice(c, "not_joined")
                return
            id = self._say(c, Line(0, sender=g.me, text=inp.text, status=PENDING))
            if self._pack(c, inp.text, id):
                return
            content = wire.text_content(membership(g), inp.text, self.wire_version)
            self._enqueue(c, self._compose(c, content), content, id)
        elif isinstance(inp, Ping):
            c = self._chat(inp.chat)
            if c is None:
                return
            g = c.group
            if g is None:
                self._notice(c, "not_joined")
                return
            content = wire.ping_content(membership(g), self.wire_version)
            self._enqueue(c, self._compose(c, content), content, None)
        elif isinstance(inp, SendFile):
            c = self._chat(inp.chat)
            if c is None:
                return
            g = c.group
            if g is None:
                self._notice(c, "not_joined")
                return
            if len(inp.data) > wire.MAX_FILE:
                self._notice(c, "file_too_large", size_text(wire.MAX_FILE))
                return
            safe = wire.safe_name(inp.name)
            content = wire.file_content(membership(g), b"", wire.filetype_of(safe), safe, self.wire_version)
            a = Attachment(safe, wire.filetype_of(safe), len(inp.data), self._attachment_file(c, safe))
            self._keep(a.file, inp.data)
            id = self._say(c, Line(0, sender=g.me, text=file_text(a), status=PENDING, attachment=a))
            self._enqueue(c, self._compose(c, content), content, id, inp.data)
        elif isinstance(inp, Loaded):
            key = (inp.chat, inp.job)
            self._loading.discard(key)
            c = self._chat(inp.chat)
            j = c.job(inp.job) if c is not None else None
            if j is None:
                return
            if not inp.lost:
                self._blobs[key] = inp.data
                return
            if j.token is not None and c.group is not None:
                c.group.abandoned(j.token)
            c.jobs = [x for x in c.jobs if x.id != inp.job]
            self._notice(c, "send_lost")
        elif isinstance(inp, Substream):
            self._uploading.discard((inp.chat, inp.job))
            c = self._chat(inp.chat)
            j = c.job(inp.job) if c is not None else None
            if j is not None and j.upload is not None:
                j.upload.write_cap, j.upload.next = inp.keypair.write_cap, inp.keypair.first
        elif isinstance(inp, ChunkIndexes):
            key = (inp.chat, inp.job)
            self._uploading.discard(key)
            c = s.chat(inp.chat)
            j = c.job(inp.job) if c is not None else None
            if j is not None and j.upload is not None and j.upload.next == inp.start:
                self._ahead[key] = [inp.start, *inp.indexes]
        elif isinstance(inp, WroteChunk):
            self._wrote_chunk(inp)
        elif isinstance(inp, ReadChunk):
            self._read_chunk(inp)
        elif isinstance(inp, Wrote):
            self._writing.discard(inp.chat)
            c = self._chat(inp.chat)
            if c is None:
                return
            j = c.job(inp.job)
            if j is None:
                return
            c.jobs = [x for x in c.jobs if x.id != inp.job]
            if j.token is not None and c.group is not None:
                c.group.written(j.token, inp.index, j.box)
                c.next_write = inp.next
            if j.line is not None:
                for line in c.log:
                    if line.id == j.line or line.id in j.packed:
                        line.status, line.idx64 = SENT, wire.counter(inp.index)
                        self._line_changed(c, line.id)
        elif isinstance(inp, Refused):
            # The chat's writes stop here: the job stays first, and nothing writes after it.
            if (c := self._chat(inp.chat)) is not None:
                self._notice(c, "desync")
        elif isinstance(inp, Read):
            self._read(inp)
        elif isinstance(inp, Wake):
            self._stop_reading(inp.chat, inp.stream)
        elif isinstance(inp, Tick):
            c = s.chat(inp.chat)
            if self._unreceipted.get(inp.chat) != inp.n or c is None or c.group is None:
                return
            del self._unreceipted[inp.chat]
            self._ticking.pop(inp.chat, None)
            self._enqueue(c, acknowledge(c.group), None, None)
        elif isinstance(inp, Scan):
            c = self._chat(inp.chat)
            if c is None or c.group is None:
                return
            for stream in list(c.group.readers):
                self._effects(c, c.group.handle(mev.Scan(stream)))
            self._notice(c, "scanning")
        elif isinstance(inp, Leave):
            c = s.chat(inp.chat)
            if c is None:
                return
            for f in c.files():
                self._emit(DoDelete(f))
            s.chats = [x for x in s.chats if x.id != inp.chat]
            self._forget(inp.chat)
            self._out.changes.chats.discard(inp.chat)
            self._out.changes.lines.pop(inp.chat, None)
            self._out.changes.dropped.pop(inp.chat, None)
            self._out.changes.removed.add(inp.chat)
        elif isinstance(inp, RemoveMember):
            c = self._chat(inp.chat)
            if c is None:
                return
            if c.group is None or inp.who not in c.group.readers:
                self._notice(c, "no_longer_member")
                return
            label = self._label(c, inp.who)
            c.group.remove(inp.who)
            self._stop_reading(c.id, inp.who)
            self._hit(c.id, inp.who)
            self._fetched.pop((c.id, inp.who), None)
            self._drop_lines(c, lambda l: l.sender != inp.who)
            c.cursors.pop(inp.who, None)
            c.downloads = [d for d in c.downloads if d.stream != inp.who]
            self._notice(c, "stopped_reading", label)
        elif isinstance(inp, Clear):
            if (c := self._chat(inp.chat)) is not None:
                self._drop_lines(c, lambda l: False)
        elif isinstance(inp, Rename):
            c = self._chat(inp.chat)
            if c is None or not inp.to or inp.to == c.name:
                return
            if s.chat_named(inp.to) is not None:
                self._notice(c, "name_taken", inp.to)
                return
            old = c.name
            c.name = inp.to
            self._notice(c, "renamed", old)
        elif isinstance(inp, ScanRead):
            c = self._chat(inp.chat)
            if c is None or c.group is None:
                return
            res, nxt = read_result(inp.outcome)
            self._effects(c, c.group.handle(mev.BoxRead(inp.stream, inp.index, res, nxt)))
            self._follow_reader(c, inp.stream)
        elif isinstance(inp, Walked):
            c = self._chat(inp.chat)
            if c is None or c.group is None:
                return
            self._effects(c, c.group.handle(mev.Walked(inp.stream, inp.target, tuple(inp.skipped), inp.steps)))
            self._follow_reader(c, inp.stream)
        elif isinstance(inp, Derived):
            c = self._chat(inp.chat)
            if c is None or c.group is None:
                return
            self._effects(c, c.group.handle(mev.IndexesDerived(inp.stream, tuple(inp.indexes))))
        elif isinstance(inp, Epoch):
            self.epoch = max(self.epoch, inp.n)
            for c in s.chats:
                if c.group is None or c.group.epoch >= inp.n:
                    continue
                self._dirty(c)
                self._effects(c, c.group.handle(mev.EpochChanged(inp.n)))
        elif isinstance(inp, Failed):
            c = self._chat(inp.chat)
            if c is None:
                return
            # A chat still joining stays so, and joins on when resumed.
            self._cancel_held(c)
            c.inducting = None
            self._notice(c, "action_failed", inp.what)

    def _wrote_chunk(self, inp: WroteChunk) -> None:
        key = (inp.chat, inp.job)
        self._chunks_out.get(key, set()).discard(inp.n)
        c = self.state.chat(inp.chat)
        j = c.job(inp.job) if c is not None else None
        if j is None or j.upload is None or inp.n < j.upload.sent:
            return
        u = j.upload
        landed = self._landed.setdefault(key, [])
        landed.append((inp.n, inp.next))
        # Count the boxes written in a row from the first not yet counted.
        while (hit := next((l for l in landed if l[0] == u.sent), None)) is not None:
            landed.remove(hit)
            self._ahead[key] = self._ahead.get(key, [])[1:]
            u.sent, u.next = u.sent + 1, hit[1]
        self._dirty(c)
        if u.sent < u.total:
            return
        for d in (self._blobs, self._ahead, self._landed):
            d.pop(key, None)
        self._emit(DoDelete(u.file))
        j.box = wire.indirection(u.total, u.write_cap[KEY_SIZE:])

    def _read_chunk(self, inp: ReadChunk) -> None:
        self._stop_reading(inp.chat, inp.stream)
        c = self.state.chat(inp.chat)
        d = next((d for d in c.downloads if d.stream == inp.stream), None) if c is not None else None
        if d is None:
            return
        k = (inp.chat, inp.stream)
        at, parts = self._fetched.get(k, (wire.start_of(d.read_cap), []))
        if at != inp.index:
            return
        o = inp.outcome
        if o.kind == NOT_FOUND:
            self._reading.add(k)
            self._emit(DoWake(inp.chat, inp.stream, backoff_ms(self._missed(inp.chat, inp.stream))))
            return
        if o.kind == TOMBSTONE:
            self._finish(c, d, None)
            return
        self._hit(inp.chat, inp.stream)
        parts = parts + [o.plaintext]
        tag = o.plaintext[:1]
        if tag == wire.FINAL:
            self._finish(c, d, wire.assemble(parts))
        elif tag == wire.CONTINUED and len(parts) < wire.max_chunks(wire.MIN_BOX) and (d.total is None or len(parts) < d.total):
            self._fetched[k] = (o.next, parts)
        else:
            self._finish(c, d, None)

    def _read(self, inp: Read) -> None:
        self._stop_reading(inp.chat, inp.stream)
        c = self.state.chat(inp.chat)
        if c is None:
            return
        at = c.cursors.get(inp.stream)
        if at is None or at != inp.index:
            return
        o = inp.outcome
        if o.kind == NOT_FOUND:
            self._reading.add((inp.chat, inp.stream))
            self._emit(DoWake(inp.chat, inp.stream, backoff_ms(self._missed(inp.chat, inp.stream))))
            return
        assert o.next is not None
        self._hit(inp.chat, inp.stream)
        self._dirty(c)
        if o.kind == TOMBSTONE:
            c.cursors[inp.stream] = o.next
            return
        ch = wire.unframe(o.plaintext)
        if ch.kind == wire.INDIRECTION:
            if (ch.total or 0) <= wire.max_chunks(wire.MIN_BOX):
                c.downloads.append(Download(inp.stream, inp.index, o.next, ch.data, ch.total))
                c.cursors[inp.stream] = o.next
                return
            self._notice(c, "file_too_large_to_fetch", self._label(c, inp.stream))
            if c.group is not None:
                self._effects(c, c.group.observe(inp.stream, inp.index, None, o.next))
            c.cursors[inp.stream] = o.next
            return
        self._remark(c, inp.stream, o.plaintext)
        if c.group is not None:
            self._effects(c, c.group.observe(inp.stream, inp.index, ch.data if ch.kind == wire.FINAL else None, o.next))
        c.cursors[inp.stream] = o.next

    # ---- the two entry points ----

    def step(self, now: int, inp) -> Result:
        """One input at time now, in milliseconds since the Unix epoch."""
        self._begin(now)
        self._handle(inp)
        self._pump()
        return self._out

    def resume(self, now: int) -> Result:
        """Begin again after a restart: whatever was under way is started
        afresh."""
        self._begin(now)
        for c in self.state.chats:
            if not c.write_cap:
                self._emit(DoCreate(c.id, c.joining is not None))
                continue
            if (j := c.joining) is not None:
                if not j.code:
                    self._emit(DoMint(c.id, c.write_cap, self.state.me, self._voucher_form()))
                else:
                    self._emit(DoAwaitReply(c.id, j.secret_key, j.voucher_read_cap, j.box1, c.write_cap, j.version))
            if (i := c.inducting) is not None:
                if i.payload is None:
                    self._emit(DoReadVoucher(c.id, i.voucher))
                elif i.sealed is not None:
                    self._emit(DoPublish(c.id, i.voucher_write_cap, i.box1, i.sealed.reply, i.sealed.version))
                elif i.sealing:
                    # The sealed reply was never kept, so never published: seal it again.
                    i.sealing = False
                    self._dirty(c)
        self._pump()
        return self._out


def read_result(o: Outcome):
    """A box a scan read, as the member takes it."""
    if o.kind == NOT_FOUND:
        return mev.Missing.NOT_FOUND, None
    if o.kind == TOMBSTONE:
        return mev.Missing.TOMBSTONE, o.next
    ch = wire.unframe(o.plaintext)
    return (ch.data if ch.kind == wire.FINAL else b""), o.next


def joined_from(o: Opened):
    """The group a reply to our voucher puts us in, with the reply, or None."""
    who = wire.reply_who_decode(o.who_reply)
    if who is None or len(o.mutated_write_cap) < KEY_SIZE:
        return None
    reply = wire.to_join_reply(who)
    if reply is None:
        reply = wire.without_rosters(who)
    if reply is None:
        return None
    own = o.mutated_write_cap[KEY_SIZE:]
    for m in reply.members:
        if m is not None and wire.key_of(m[0]) == wire.key_of(own):
            return None
    return new_group(own, reply=reply), who


PLAIN = {
    "name_taken": "you already have a group called {0}",
    "name_taken_joining": "you already have a group called {0}: to join someone else's group, give it a name of its own",
    "minting": "minting a voucher",
    "new_group": "a new group: adding a member's voucher code adds them",
    "voucher_minted": "give the voucher code to a member of the group (it is also in {2})",
    "reply_unreadable": "the reply to our voucher cannot be read",
    "joined": "joined the group",
    "not_joined_yet": "join or create the group first",
    "already_adding": "already adding a member",
    "not_a_voucher": "that is not a voucher code",
    "reading_voucher": "reading the voucher",
    "added": "added ~{0}: they now read everything said in this group",
    "not_joined": "this conversation has not been joined yet",
    "file_too_large": "that file is too large to send: at most {0}",
    "send_lost": "a message could not be sent: what it held was lost",
    "file_too_large_to_fetch": "{0} sent a file too large to fetch",
    "scanning": "scanning for missed messages",
    "no_longer_member": "that member is no longer in this group",
    "stopped_reading": "stopped reading {0} and deleted what they sent; they can still read this group",
    "renamed": "renamed from {0}",
    "action_failed": "{0}",
    "too_long": "that message is too long to send",
    "not_written": "a message could not be written",
    "member_added": "{0} added ~{1}",
    "unreadable": "{0} sent a message that cannot be read",
    "not_fetched": "{0} sent a message that could not be fetched",
    "desync": "a box of our stream holds something else: is this group used from another client?",
    "pinged": "{0} pinged",
    "unsupported": "{0} sent a message this app cannot show (type {1}, version {2}): update the app",
}


def plain(n: Notice) -> str:
    """A notice in words, as pigeonhole_protocols' plain presentation."""
    try:
        return PLAIN[n.kind].format(*n.args)
    except (KeyError, IndexError):
        return "notice %s %r" % (n.kind, n.args)
