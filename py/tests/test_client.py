# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Two chat clients over one simulated Pigeonhole, in virtual time."""

import os

import pytest

from pigeonhole_protocols.katzenqt1 import engine as eng
from pigeonhole_protocols.katzenqt1 import wire
from pigeonhole_protocols.transport.sim import SimBackend
from pigeonhole_protocols.katzenqt1.client import SyncClient

STEP = 1000


def settle(clients, ms=120_000, step=STEP):
    for _ in range(ms // step):
        for c in clients:
            c.run(step)


def texts(c, chat):
    return [c.plain(chat, l) for l in c.lines(chat) if l.notice is None]


def notices(c, chat):
    return [l.notice.kind for l in c.lines(chat) if l.notice is not None]


@pytest.fixture
def world(tmp_path):
    sim = SimBackend(max_plaintext=1000)
    clock = [0]

    def make(name):
        return SyncClient(str(tmp_path / name), name, sim, clock=clock)

    return sim, clock, make


def test_wire_roundtrip():
    m = wire.Message(content=wire.text_content(bytes(32), "hi"))
    box = wire.box_of(m)
    assert box[:1] == b"F"
    back = wire.message_of(box)
    assert back.content == m.content and wire.text_of(back.content) == "hi"
    intro = wire.Message(introduction=wire.Introduction("bob", bytes(136)), numbers=((1, None),))
    back = wire.message_of(wire.box_of(intro))
    assert back.content is None and back.introduction.name == "bob" and back.numbers == ((1, None),)


def join(make, sim):
    """alice founds g; bob joins through a voucher alice inducts."""
    alice, bob = make("alice"), make("bob")
    alice.start()
    bob.start()
    alice.feed(eng.Create("g", "g"))
    bob.feed(eng.Join("g", "g"))
    settle([alice, bob], 10_000)
    code = open(os.path.join(bob.store.dir, "voucher-g.txt")).read().strip()
    assert "voucher_minted" in notices(bob, "g")
    alice.feed(eng.Induct("g", code))
    settle([alice, bob], 60_000)
    assert "added" in notices(alice, "g"), notices(alice, "g")
    assert "joined" in notices(bob, "g"), notices(bob, "g")
    return alice, bob


def test_join_and_chat(world):
    sim, clock, make = world
    alice, bob = join(make, sim)
    assert [n for _, n in alice.members("g")] == ["alice", "bob"]
    assert sorted(n for _, n in bob.members("g")) == ["alice", "bob"]

    alice.feed(eng.Send("g", "hello bob"))
    settle([alice, bob], 30_000)
    assert texts(bob, "g") == ["alice: hello bob"]
    bob.feed(eng.Send("g", "hey alice"))
    settle([alice, bob], 30_000)
    assert texts(alice, "g") == ["alice: hello bob", "bob: hey alice"]
    # bob's reply acknowledged alice's box.
    line = [l for l in alice.lines("g") if l.notice is None][0]
    assert line.status == eng.SENT and alice.state.chat("g").acknowledged(line)
    alice.close()
    bob.close()


def test_restart_keeps_state_and_reads_on(world):
    sim, clock, make = world
    alice, bob = join(make, sim)
    alice.feed(eng.Send("g", "one"))
    settle([alice, bob], 30_000)
    bob.close()
    alice.feed(eng.Send("g", "two"))
    settle([alice], 10_000)
    bob = make("bob")
    bob.start()
    settle([alice, bob], 30_000)
    assert texts(bob, "g") == ["alice: one", "alice: two"]
    alice.close()
    bob.close()


def test_write_retries_and_rewrite_after_epoch(world):
    sim, clock, make = world
    alice, bob = join(make, sim)
    sim.fail_next.add("write")
    alice.feed(eng.Send("g", "flaky"))
    # The write is tried again after 5s; bob's reads of a quiet stream have backed off to a minute.
    settle([alice, bob], 120_000)
    assert texts(bob, "g") == ["alice: flaky"]
    # The next epoch: alice backfills nothing bob acknowledged, and nothing is lost.
    before = sim.writes
    alice.feed(eng.Epoch(2))
    bob.feed(eng.Epoch(2))
    settle([alice, bob], 30_000)
    assert texts(bob, "g") == ["alice: flaky"]
    assert sim.writes >= before
    alice.close()
    bob.close()


def test_third_member_through_bob(world):
    sim, clock, make = world
    alice, bob = join(make, sim)
    carol = make("carol")
    carol.start()
    carol.feed(eng.Join("g", "g"))
    settle([alice, bob, carol], 10_000)
    code = open(os.path.join(carol.store.dir, "voucher-g.txt")).read().strip()
    bob.feed(eng.Induct("g", code))
    settle([alice, bob, carol], 90_000)
    assert "joined" in notices(carol, "g")
    assert sorted(n for _, n in alice.members("g")) == ["alice", "bob", "carol"], alice.members("g")
    carol.feed(eng.Send("g", "hi all"))
    settle([alice, bob, carol], 60_000)
    assert "carol: hi all" in texts(alice, "g")
    assert "carol: hi all" in texts(bob, "g")
    for c in (alice, bob, carol):
        c.close()


def test_scan_and_remove(world):
    sim, clock, make = world
    alice, bob = join(make, sim)
    alice.feed(eng.Send("g", "x"))
    settle([alice, bob], 30_000)
    bob.feed(eng.Scan("g"))
    settle([alice, bob], 30_000)
    assert "scanning" in notices(bob, "g")
    assert texts(bob, "g") == ["alice: x"]
    bob_key = [k for k, n in alice.members("g") if n == "bob"][0]
    alice.feed(eng.RemoveMember("g", bob_key))
    assert "stopped_reading" in notices(alice, "g")
    assert [n for _, n in alice.members("g")] == ["alice"]
    alice.close()
    bob.close()


@pytest.mark.parametrize("traced", [False, True], ids=["plain", "traced"])
def test_group_made_late_in_a_high_epoch_keeps_its_records(world, traced, monkeypatch, tmp_path):
    """The replicas are at epoch 491 when the group is made, as on a real
    network. The first message must still be found by the acknowledgement
    that names it after the next epoch report. With a trace recording, the
    group the engine keeps is the traced one, so the epoch must reach it."""
    if traced:
        monkeypatch.setenv("PIGEONHOLE_TRACE", str(tmp_path / "trace.jsonl"))
    sim, clock, make = world
    sim.epoch = 491
    alice, bob = join(make, sim)
    alice.feed(eng.Send("g", "first"))
    settle([alice, bob], 30_000)
    bob.feed(eng.Send("g", "read it"))
    settle([alice, bob], 60_000)
    # Both wrote before the next report; neither record may go with it.
    alice.feed(eng.Epoch(491))
    bob.feed(eng.Epoch(491))
    alice.feed(eng.Send("g", "and you"))
    settle([alice, bob], 60_000)
    line = [l for l in alice.lines("g") if l.notice is None and l.text == "first"][0]
    assert alice.state.chat("g").acknowledged(line)
    line = [l for l in bob.lines("g") if l.notice is None and l.text == "read it"][0]
    assert bob.state.chat("g").acknowledged(line)
    alice.close()
    bob.close()


def test_reply_spans_boxes(tmp_path):
    """A sealed reply larger than a box is written framed over boxes 1 on and read back: carol's,
    naming alice and bob with their rosters, outgrows a 400 byte box."""
    sim = SimBackend(max_plaintext=400, real_vouchers=True)
    clock = [0]

    def make(name):
        return SyncClient(str(tmp_path / name), name, sim, clock=clock)

    alice, bob = join(make, sim)
    carol = make("carol")
    carol.start()
    carol.feed(eng.Join("g", "g"))
    settle([alice, bob, carol], 10_000)
    code = open(os.path.join(carol.store.dir, "voucher-g.txt")).read().strip()
    alice.feed(eng.Induct("g", code))
    settle([alice, bob, carol], 90_000)
    assert "joined" in notices(carol, "g")
    assert any(p[:1] == b"C" for _, p in sim.boxes.values()), "the reply was not split"
    carol.feed(eng.Send("g", "fits"))
    settle([alice, bob, carol], 60_000)
    assert "carol: fits" in texts(alice, "g")
    for c in (alice, bob, carol):
        c.close()


def test_old_voucher_form_still_joins(world, monkeypatch):
    """A joiner that minted the map form gets the unframed MKEM reply in box 1 alone."""
    from hpqc.voucher import api as voucher

    sim, clock, make = world
    sim.real_vouchers = True
    real = voucher.voucher_mint
    monkeypatch.setattr(voucher, "voucher_mint", lambda wc, name, **kw: real(wc, name, version=1, **kw))
    alice, bob = join(make, sim)
    assert bob.state.chat("g").joining is None
    plaintexts = [p for _, p in sim.boxes.values()]
    assert not any(p[:1] == b"C" for p in plaintexts)
    assert any(p[:1] == b"\xa3" for p in plaintexts), "the MKEM reply, a CBOR map of three"
    alice.close()
    bob.close()


def versioned(tmp_path):
    """A sim recording each voucher payload minted, and clients writing a given wire version."""
    sim = SimBackend(max_plaintext=1000, real_vouchers=True)
    clock, minted = [0], []
    mint = sim.voucher_mint

    def recording(*a):
        m = mint(*a)
        minted.append(m.payload)
        return m

    sim.voucher_mint = recording

    def make(name, v):
        return SyncClient(str(tmp_path / name), name, sim, clock=clock, wire_version=v)

    return sim, minted, make


def chat_both_ways(alice, bob):
    alice.feed(eng.Send("g", "hello bob"))
    bob.feed(eng.Send("g", "hey alice"))
    settle([alice, bob], 30_000)
    assert "alice: hello bob" in texts(bob, "g")
    assert "bob: hey alice" in texts(alice, "g")


def group_boxes(sim):
    """The CBOR of every box holding a group message."""
    return [p[1:] for _, p in sim.boxes.values() if p[:1] == b"F" and wire.message_of(p) is not None]


@pytest.mark.parametrize("v", [wire.MAP_VERSION, wire.VERSION])
def test_wire_version_writes_and_mints_its_form(tmp_path, v):
    """Version 3 writes maps, as the v3 vectors encode them, mints the map payload and gets the
    unframed MKEM reply; version 4 writes arrays, mints the array payload, gets a framed reply."""
    sim, minted, make = versioned(tmp_path)
    alice, bob = join(lambda n: make(n, v), sim)
    chat_both_ways(alice, bob)
    major = 5 if v == wire.MAP_VERSION else 4
    assert [p[0] >> 5 for p in minted] == [major]
    boxes = group_boxes(sim)
    assert len(boxes) >= 4
    for cbor in boxes:
        assert cbor[0] >> 5 == major
        assert wire.box_of(wire.to_message(cbor), wire.stamp_of(cbor), v) == b"F" + cbor
    mkem = any(p[:1] == b"\xa3" for _, p in sim.boxes.values())
    assert mkem == (v == wire.MAP_VERSION)
    for c in (alice, bob):
        c.close()


@pytest.mark.parametrize("va,vb", [(3, 4), (4, 3)])
def test_mixed_wire_versions_join_and_chat(tmp_path, va, vb):
    sim, minted, make = versioned(tmp_path)
    alice, bob = join(lambda n: make(n, va if n == "alice" else vb), sim)
    chat_both_ways(alice, bob)
    assert [p[0] >> 5 for p in minted] == [5 if vb == 3 else 4]
    assert {cbor[0] >> 5 for cbor in group_boxes(sim)} == {4, 5}
    for c in (alice, bob):
        c.close()


def attachment_of(c, chat):
    return [l for l in c.lines(chat) if l.attachment is not None][0]


def test_file_larger_than_a_box_round_trips(world):
    """The file goes to a substream behind an I box; its bytes live in a file under each state
    directory, never in the message, and the sender's spool file goes once it is written."""
    sim, clock, make = world
    alice, bob = join(make, sim)
    data = bytes(i % 251 for i in range(5000))
    alice.feed(eng.SendFile("g", "a.bin", data))
    line = attachment_of(alice, "g")
    assert line.status == eng.PENDING and line.text == "[file a.bin, 5 KB]"
    assert open(os.path.join(alice.store.dir, line.attachment.file), "rb").read() == data
    assert os.listdir(os.path.join(alice.store.dir, "spool")) != []
    settle([alice, bob], 60_000)
    assert texts(bob, "g") == ["alice: [file a.bin, 5 KB]"]
    got = attachment_of(bob, "g")
    assert got.attachment.file.startswith("attachments/g/") and got.attachment.size == 5000
    assert open(os.path.join(bob.store.dir, got.attachment.file), "rb").read() == data
    assert attachment_of(alice, "g").status == eng.SENT
    assert os.listdir(os.path.join(alice.store.dir, "spool")) == []
    plaintexts = [p for _, p in sim.boxes.values()]
    assert any(p[:1] == b"I" for p in plaintexts) and any(p[:1] == b"C" for p in plaintexts)
    assert not any(data[:64] in p for p in plaintexts if p[:1] in (b"F", b"I")), "the bytes travel in the substream only"
    alice.close()
    bob.close()


def test_reader_steps_past_an_i_box_it_cannot_fetch(world):
    """A substream gone before it is read ends the fetch: the I box is stepped past, with a
    notice, and what comes after it is read."""
    sim, clock, make = world
    alice, bob = join(make, sim)
    before = set(sim.boxes)
    alice.feed(eng.SendFile("g", "b.bin", bytes(3000)))
    alice.feed(eng.Send("g", "after"))
    alice.run(60_000)
    for k in set(sim.boxes) - before:
        ep, p = sim.boxes[k]
        if p[:1] == b"C":  # the substream's, not the F box of "after" on alice's own stream
            sim.boxes[k] = (ep, b"")
    settle([alice, bob], 60_000)
    assert texts(bob, "g") == ["alice: after"]
    assert "not_fetched" in notices(bob, "g")
    alice.close()
    bob.close()


def test_restart_mid_upload_resumes(world):
    sim, clock, make = world
    alice, bob = join(make, sim)
    data = bytes(i % 7 for i in range(20000))
    alice.feed(eng.SendFile("g", "big.bin", data))
    # Three boxes of the first window fail and would be tried again in 5s: the upload stops there.
    sim.fail_writes(3)
    alice.run(0)
    job = alice.state.chat("g").jobs[0]
    assert job.upload is not None and job.upload.write_cap and job.upload.sent < job.upload.total
    written = sim.writes
    alice.close()
    alice = make("alice")
    alice.start()
    job = alice.state.chat("g").jobs[0]
    assert job.upload is not None and job.upload.sent < job.upload.total
    settle([alice, bob], 60_000)
    assert sim.writes > written
    assert alice.state.chat("g").jobs == []
    got = attachment_of(bob, "g")
    assert open(os.path.join(bob.store.dir, got.attachment.file), "rb").read() == data
    alice.close()
    bob.close()


def test_dropped_line_deletes_its_file(world, monkeypatch):
    sim, clock, make = world
    alice, bob = join(make, sim)
    alice.feed(eng.SendFile("g", "a.bin", bytes(100)))
    settle([alice, bob], 30_000)
    path = os.path.join(bob.store.dir, attachment_of(bob, "g").attachment.file)
    assert os.path.exists(path)
    bob.feed(eng.Clear("g"))
    bob.run(0)
    assert not os.path.exists(path)
    path = os.path.join(alice.store.dir, attachment_of(alice, "g").attachment.file)
    monkeypatch.setattr(eng, "MAX_LOG", 20)
    for _ in range(20):
        alice.feed(eng.Induct("g", "junk!"))
    alice.run(0)
    assert not os.path.exists(path) and all(l.attachment is None for l in alice.lines("g"))
    alice.close()
    bob.close()


def test_parse_voucher_code():
    code = eng.voucher_code(bytes(range(32)))
    assert eng.parse_voucher_code(code) == bytes(range(32))
    assert eng.parse_voucher_code(" ".join(code[i : i + 8] for i in range(0, len(code), 8))) == bytes(range(32))
    assert eng.parse_voucher_code(eng.voucher_code(bytes(16))) is None
    assert eng.parse_voucher_code("junk!") is None


@pytest.mark.parametrize("form", [1, 2])
def test_sim_vouchers(form):
    sim = SimBackend()
    joiner = sim.new_keypair()
    m = sim.voucher_mint(joiner.write_cap, "carol", form)
    assert m.version == form
    assert sim.voucher_derive_stream(m.voucher) == (m.write_cap, m.read_cap)
    i = sim.voucher_induct(m.voucher, m.payload, b"reply")
    assert (i.name, i.mutated_read_cap, i.sealed_reply, i.version) == ("carol", joiner.read_cap, b"reply", form)
    o = sim.voucher_open(m.secret_key, i.sealed_reply, joiner.write_cap)
    assert (o.who_reply, o.mutated_write_cap) == (b"reply", joiner.write_cap)
