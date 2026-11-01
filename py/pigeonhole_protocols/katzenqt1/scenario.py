# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Client scenarios: members, each a client engine with its state on disk,
over the in-memory Pigeonhole, driven by a script written as the Go and
Rust clients' scenarios are (``client/testdata/scenarios`` and
``testdata/katzenqt1/client_scenarios``). The network runs on a logical
clock, and only when told to: ``run`` carries out what the members asked
for, in order, and lets time pass. A scenario passes when every checked
command prints what the file says."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import cbor2

from ..transport.sim import SimBackend
from . import engine as eng
from . import wire
from .client import Executor, Performed
from .member import state as member_state
from .store import Store

MAX_PLAINTEXT = 1530


class ScenarioError(Exception):
    pass


@dataclass
class Member:
    name: str
    dir: str
    store: Store
    eng: eng.Engine


@dataclass
class Later:
    at: int
    who: int
    action: object = None
    input: object = None


def kind_of(x) -> str:
    """An action's or input's kind, as the Go and Rust runners name it."""
    n = type(x).__name__
    if n.startswith("Do"):
        n = n[2:]
    return {"MintedIn": "Minted", "OpenedIn": "Opened"}.get(n, n)


class World:
    def __init__(self, root: Optional[str] = None):
        self.sim = SimBackend(max_plaintext=MAX_PLAINTEXT, epoch=1)
        self.root = root or tempfile.mkdtemp(prefix="scenario-")
        self.members: List[Member] = []
        self.queue: List[Tuple[int, object]] = []
        self.later: List[Later] = []
        self.clock = 0
        self.held: Set[int] = set()
        self.epoch = 1
        self.fail_next: Dict[int, str] = {}
        # delay_next names, for a member, the kind of its next action whose
        # outcome is kept back until the member is released: the action is
        # done, the member has yet to hear so.
        self.delay_next: Dict[int, str] = {}
        self.delayed: Dict[int, list] = {}
        self.clobber_next: Dict[int, str] = {}
        self.opened: Dict[Tuple[int, str], eng.OpenedIn] = {}
        self.rosterless: Set[int] = set()
        self.unsaved: List[str] = []

    # ---- members ----

    def who(self, name: str) -> int:
        for i, m in enumerate(self.members):
            if m.name == name:
                return i
        d = os.path.join(self.root, name)
        st = Store(d)
        m = Member(name, d, st, eng.Engine(st.load(name), MAX_PLAINTEXT))
        self.members.append(m)
        return len(self.members) - 1

    def feed(self, i: int, inp) -> None:
        m = self.members[i]
        if isinstance(inp, eng.OpenedIn):
            self.opened[(i, inp.chat)] = inp
        res = m.eng.step(0, inp)
        m.store.commit(m.eng.state, res)
        for c in m.eng.state.chats:
            if c.group is not None and member_state.load(member_state.dump(c.group), codec=c.group.codec) != c.group:
                self.unsaved.append("%s %s after %s" % (m.name, c.name, kind_of(inp)))
        for a in res.actions:
            self.queue.append((i, a))

    def executor(self, i: int) -> Executor:
        return Executor(self.sim, self.members[i].store.remove, lambda ms: None)

    def act(self) -> bool:
        k = next((n for n, (who, _) in enumerate(self.queue) if who not in self.held), -1)
        if k < 0:
            return False
        who, a = self.queue.pop(k)
        if isinstance(a, eng.DoSeal) and who in self.rosterless:
            full = wire.reply_who_decode(a.who_reply)
            bare = cbor2.dumps({"please_adds": [{"display_name": p[0], "read_cap": p[1]} for p in full.please_adds if p is not None]})
            a = eng.DoSeal(a.chat, a.voucher, a.payload, bare)
        kind = kind_of(a)
        if self.fail_next.get(who) == kind:
            del self.fail_next[who]
            p = Performed(input=eng.Failed(getattr(a, "chat", ""), "%s failed: injected" % describe(a)))
        else:
            if self.clobber_next.get(who) == kind:
                del self.clobber_next[who]
                self.sim.clobber(a.write_cap, a.index, b"clobbered")
            p = self.executor(who).perform(a)
        if self.delay_next.get(who) == kind and p.input is not None and p.after_ms == 0 and p.retry is None:
            del self.delay_next[who]
            self.delayed.setdefault(who, []).append(p.input)
        elif p.retry is not None:
            self.later.append(Later(self.clock + p.after_ms, who, action=p.retry))
        elif p.input is not None and p.after_ms > 0:
            self.later.append(Later(self.clock + p.after_ms, who, input=p.input))
        elif p.input is not None:
            self.feed(who, p.input)
        return True

    def run_to(self, stop: int) -> None:
        while True:
            if self.act():
                continue
            due = [l.at for l in self.later if l.at <= stop and l.who not in self.held]
            if not due:
                self.clock = max(self.clock, stop)
                return
            at = min(due)
            now = [l for l in self.later if l.at <= at and l.who not in self.held]
            self.later = [l for l in self.later if not (l.at <= at and l.who not in self.held)]
            self.clock = max(self.clock, at)
            for l in now:
                if l.action is not None:
                    if self.members[l.who].eng.state.wanted(l.action):
                        self.queue.append((l.who, l.action))
                else:
                    self.feed(l.who, l.input)

    # ---- what the script asks ----

    def chat_of(self, i: int, group: str) -> Optional[eng.Chat]:
        return self.members[i].eng.state.chat(group)

    def name_of(self, key: bytes) -> str:
        for m in self.members:
            for c in m.eng.state.chats:
                if c.group is not None and c.group.me == key:
                    return m.name
        return "?"

    @staticmethod
    def first_of(c: eng.Chat) -> int:
        return wire.counter(c.write_cap[len(c.write_cap) - 104 :])

    def show(self, i: int, group: str) -> List[str]:
        c = self.chat_of(i, group)
        if c is None:
            return ["no such group"]
        out = []
        for l in c.log:
            if l.notice is not None:
                out.append("— " + eng.plain(l.notice))
                continue
            mark = ""
            if c.group is not None and c.group.me == l.sender:
                if l.status == eng.PENDING:
                    mark = " …"
                elif c.acknowledged(l):
                    mark = " ✓✓"
                else:
                    mark = " ✓"
            out.append("%s%s: %s" % (self.name_of(l.sender), mark, l.text.replace("\n", " | ")))
        return out

    def members_of(self, i: int, group: str) -> List[str]:
        c = self.chat_of(i, group)
        if c is None:
            return ["no such group"]
        if c.group is None:
            return ["not joined"]
        names = sorted(self.name_of(k) for k in c.group.readers)
        return [" ".join(names).strip() or "nobody"]

    def acked(self, i: int, group: str) -> List[str]:
        c = self.chat_of(i, group)
        if c is None:
            return ["no such group"]
        if c.group is None:
            return ["not joined"]
        first = self.first_of(c)
        acks = sorted("%s:%d" % (self.name_of(k), n - first) for k, n in c.group.ledger.acked_by.items())
        return [" ".join(acks)] if acks else ["none"]

    def state(self, i: int, group: str) -> List[str]:
        c = self.chat_of(i, group)
        if c is None:
            return ["no such group"]
        parts = ["joined" if c.group is not None else "not joined"]
        if c.joining is not None:
            parts.append("awaiting a reply" if c.joining.code else "minting")
        if c.inducting is not None:
            parts.append("adding a member")
        if c.jobs:
            parts.append("%d to write" % len(c.jobs))
        return [", ".join(parts)]

    def jobs(self, i: int, group: str) -> List[str]:
        c = self.chat_of(i, group)
        if c is None:
            return ["no such group"]
        if not c.jobs:
            return ["none"]
        first = self.first_of(c)
        out = []
        for j in c.jobs:
            at = "next box" if j.index is None else "box %d" % (wire.counter(j.index) - first)
            what = "message" if j.token is not None else ("tombstone" if not j.box else "rewrite")
            out.append("%s to %s, %d bytes" % (what, at, len(j.box)))
        return out

    def refused(self) -> List[str]:
        names: List[str] = []
        for stream, idx64 in self.sim.refused:
            name, n = "?", idx64
            for m in self.members:
                for c in m.eng.state.chats:
                    if c.write_cap and c.write_cap[32:64] == stream:
                        name, n = m.name, idx64 - self.first_of(c)
            s = "%s@%d" % (name, n)
            if s not in names:
                names.append(s)
        return [" ".join(names)] if names else ["none"]

    def pending(self, i: int) -> List[str]:
        kinds = [kind_of(a) for who, a in self.queue if who == i]
        kinds += [kind_of(l.action if l.action is not None else l.input) for l in self.later if l.who == i]
        return [" ".join(sorted(kinds))] if kinds else ["none"]

    def files_held(self, i: int) -> List[str]:
        m = self.members[i]
        names = []
        for dirpath, _, files in os.walk(m.dir):
            for f in files:
                if f.startswith("chat.sqlite"):
                    continue
                names.append(os.path.relpath(os.path.join(dirpath, f), m.dir))
        return sorted(names) or ["none"]

    def code(self, i: int, group: str) -> str:
        c = self.chat_of(i, group)
        return c.joining.code if c is not None and c.joining is not None else ""

    def restart(self, i: int) -> None:
        """Start the member again from what is on disk, as a client does."""
        m = self.members[i]
        self.queue = [(who, a) for who, a in self.queue if who != i]
        self.later = [l for l in self.later if l.who != i]
        m.store.close()
        m.store = Store(m.dir)
        m.eng = eng.Engine(m.store.load(m.name), MAX_PLAINTEXT)
        res = m.eng.resume(0)
        m.store.commit(m.eng.state, res)
        for a in res.actions:
            self.queue.append((i, a))

    def command(self, words: List[str]) -> Optional[List[str]]:
        w, n = words, len(words)
        if w[0] == "create" and n == 3:
            self.feed(self.who(w[1]), eng.Create(w[2], w[2]))
        elif w[0] == "join" and n == 3:
            self.feed(self.who(w[1]), eng.Join(w[2], w[2]))
        elif w[0] == "invite" and n >= 4:
            theirs = w[4] if n > 4 else w[2]
            code = self.code(self.who(w[3]), theirs)
            if not code:
                return [w[3] + " has no voucher code"]
            self.feed(self.who(w[1]), eng.Induct(w[2], code))
        elif w[0] == "invite-code" and n == 4:
            self.feed(self.who(w[1]), eng.Induct(w[2], w[3]))
        elif w[0] == "send" and n >= 3:
            self.feed(self.who(w[1]), eng.Send(w[2], " ".join(w[3:])))
        elif w[0] == "remove" and n == 4:
            i = self.who(w[1])
            c = self.chat_of(self.who(w[3]), w[2])
            if c is None or c.group is None:
                return [w[3] + " is not in " + w[2]]
            self.feed(i, eng.RemoveMember(w[2], c.group.me))
        elif w[0] == "scan" and n == 3:
            self.feed(self.who(w[1]), eng.Scan(w[2]))
        elif w[0] == "leave" and n == 3:
            self.feed(self.who(w[1]), eng.Leave(w[2]))
        elif w[0] == "run" and n <= 2:
            ms = int(w[1]) * 1000 if n == 2 else 600000
            self.run_to(self.clock + ms)
        elif w[0] == "hold" and n == 2:
            self.held.add(self.who(w[1]))
        elif w[0] == "release" and n == 2:
            i = self.who(w[1])
            self.held.discard(i)
            for inp in self.delayed.pop(i, []):
                self.feed(i, inp)
        elif w[0] == "delay-next" and n == 3:
            self.delay_next[self.who(w[1])] = w[2]
        elif w[0] == "epoch" and n == 1:
            self.epoch += 1
            self.sim.epoch = self.epoch
            for i in range(len(self.members)):
                self.feed(i, eng.Epoch(self.epoch))
        elif w[0] == "fail-writes" and n == 2:
            self.sim.fail_writes(int(w[1]))
        elif w[0] == "show" and n == 3:
            return self.show(self.who(w[1]), w[2])
        elif w[0] == "members" and n == 3:
            return self.members_of(self.who(w[1]), w[2])
        elif w[0] == "acked" and n == 3:
            return self.acked(self.who(w[1]), w[2])
        elif w[0] == "state" and n == 3:
            return self.state(self.who(w[1]), w[2])
        elif w[0] == "jobs" and n == 3:
            return self.jobs(self.who(w[1]), w[2])
        elif w[0] == "refused" and n == 1:
            return self.refused()
        elif w[0] == "voucher-file" and n == 3:
            i = self.who(w[1])
            try:
                with open(self.members[i].store.path("voucher-%s.txt" % w[2])) as f:
                    b = f.read()
            except FileNotFoundError:
                return ["none"]
            return ["the code"] if b == self.code(i, w[2]) + "\n" else ["not the code"]
        elif w[0] == "files" and n == 2:
            return self.files_held(self.who(w[1]))
        elif w[0] == "pending" and n == 2:
            return self.pending(self.who(w[1]))
        elif w[0] == "restart" and n == 2:
            self.restart(self.who(w[1]))
        elif w[0] in ("fail-next", "clobber-next") and n == 3:
            (self.fail_next if w[0] == "fail-next" else self.clobber_next)[self.who(w[1])] = w[2]
        elif w[0] == "reopen" and n == 3:
            i = self.who(w[1])
            o = self.opened.get((i, w[2]))
            if o is None:
                return ["nothing to reopen"]
            self.feed(i, o)
        elif w[0] == "repeat" and n >= 3:
            out = None
            for _ in range(int(w[1])):
                out = self.command(w[2:])
            return out
        elif w[0] in ("send-file", "file"):
            raise ScenarioError("files are not sent by this client yet: " + " ".join(w))
        else:
            raise ScenarioError("not a command: " + " ".join(w))
        return None

    def close(self) -> None:
        for m in self.members:
            m.store.close()


def describe(a) -> str:
    from .client import _describe

    return _describe(a)


def run(script: str, root: Optional[str] = None) -> Tuple[str, List[str]]:
    """The script with every checked command's output replaced by what it
    printed now, and the groups that did not save whole."""
    w = World(root)
    try:
        lines = script.split("\n")
        if lines and lines[-1] == "":
            lines = lines[:-1]
        out: List[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            out.append(line)
            i += 1
            cmd = line.split("#", 1)[0].strip()
            if not cmd:
                continue
            printed = w.command(cmd.split())
            if i < len(lines) and lines[i] == "----":
                out.append("----")
                i += 1
                while i < len(lines) and lines[i].strip() != "":
                    i += 1
                out.extend(printed or [])
        return "\n".join(out) + "\n", w.unsaved
    finally:
        w.close()
