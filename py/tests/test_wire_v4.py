# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The array form, version 4: against the shared vectors, and the rules the vectors do not
show: what is written by default, what each form costs, and that the map form still reads."""
import cbor2
import pytest

from pigeonhole_protocols.katzenqt1 import wire
from test_wire_vectors import load, message_json, read_message, unhex

V = load("groupchat_wire_vectors_v4.json")
H = bytes(32)
CAP = bytes(range(136))


@pytest.mark.parametrize("e", V["messages"], ids=[e["name"] for e in V["messages"]])
def test_message_reads_and_writes_back(e):
    cbor = unhex(e["cbor"])
    assert cbor[0] >> 5 == 4, "the array form"
    got = wire.to_message(cbor)
    assert message_json(got) == {k: v for k, v in e["message"].items() if k != "membership_hash"}
    assert wire.stamp_of(cbor) == unhex(e["message"]["membership_hash"])
    assert wire.of_message(got, wire.stamp_of(cbor), wire.ARRAY_VERSION).encode() == unhex(e["rewritten"])
    if unhex(e["rewritten"]) == cbor:
        assert wire.decode_gcm(cbor).encode() == cbor


@pytest.mark.parametrize("e", V["written"], ids=[e["name"] for e in V["written"]])
def test_message_is_written_in_the_array_form(e):
    m = read_message(e["message"])
    box = wire.box_of(m, unhex(e["message"]["membership_hash"]), wire.ARRAY_VERSION)
    assert box == unhex(e["box"])
    assert box[0:1] == b"F" and box[1] >> 5 == 4


@pytest.mark.parametrize("e", V["replies"], ids=[e["name"] for e in V["replies"]])
def test_reply_reads_in_both_forms(e):
    w = wire.reply_who_decode(unhex(e["cbor"]))
    assert w is not None
    r = wire.to_join_reply(w)
    want = e["join_reply"]
    if want is None:
        assert r is None
    else:
        assert r is not None and r.introducer == want["introducer"] and r.newcomer == want["newcomer"]
    again = wire.reply_who_decode(wire.reply_who_array(w.please_adds, w.rosters, w.introductions, w.introducer, w.newcomer))
    assert again == w


@pytest.mark.parametrize("e", V["malformed"], ids=[e["name"] for e in V["malformed"]])
def test_malformed_arrays_are_refused(e):
    assert wire.decode_gcm(unhex(e["cbor"])) is None


@pytest.mark.parametrize("e", V["unsupported"], ids=[e["name"] for e in V["unsupported"]])
def test_unsupported_names_version_and_type(e):
    want = (e["version"], e["msg_type"]) if e["version"] is not None else None
    assert wire.unsupported(unhex(e["cbor"])) == want


def test_default_is_the_array_form_and_the_map_form_still_reads():
    text = wire.text_content(H, "hello")
    assert text[0] >> 5 == 4 and wire.decode_gcm(text).version == wire.VERSION
    m3 = wire.Gcm(version=3, membership_hash=H, text="hello").encode()
    assert m3[0] >> 5 == 5 and wire.text_of(m3) == "hello" == wire.text_of(text)
    assert wire.to_message(m3).content == m3 and wire.to_message(text).content == text


def test_costs():
    # The fixed cost: array header 1, version 1, hash 2 + 32, type 1 = 37; then the body.
    assert len(wire.text_content(H, "")) == 37 + 1
    assert len(wire.text_content(H, "a" * 23)) == 37 + 1 + 23
    assert len(wire.text_content(H, "a" * 24)) == 37 + 2 + 24
    intro = wire.Gcm(membership_hash=H, msg_type=wire.MSG_INTRODUCTION, introduction=wire.Introduction("bob", CAP)).encode()
    assert len(intro) == 37 + 1 + (1 + 3) + (2 + 136)
    control = wire.Gcm(membership_hash=H, msg_type=wire.MSG_CONTROL, acks=bytes(10)).encode()
    assert len(control) == 37 + 1 + 1 + 10
    assert len(wire.Gcm(membership_hash=H, msg_type=wire.MSG_CONTROL).encode()) == 37 + 1
    # Against the map form.
    assert len(wire.text_content(H, "hello", 3)) == 76 + 5 and len(wire.text_content(H, "hello")) == 38 + 5


def test_bodies_round_trip():
    cases = [
        wire.Gcm(membership_hash=H, msg_type=wire.MSG_FILE_UPLOAD, other={"file_upload": {"payload": b"\x01\x02", "filetype": "image/png", "basename": "a.png"}}),
        wire.Gcm(membership_hash=H, msg_type=wire.MSG_WHO, other={"who": "w"}),
        wire.Gcm(membership_hash=H, msg_type=wire.MSG_REPLY_WHO, other={"reply_who": "r"}),
        wire.Gcm(membership_hash=H, msg_type=5, other={"tally": {"survey_id": b"s", "version": 1}}),
        wire.Gcm(membership_hash=H, msg_type=wire.MSG_CONTROL, numbers=b"\x04", introduced_at=bytes(105)),
    ]
    for g in cases:
        b = g.encode()
        back = wire.decode_gcm(b)
        assert back == g, g.msg_type
        assert cbor2.loads(b)[3] == g.body()
    assert cbor2.loads(cases[0].encode())[3] == [b"\x01\x02", "image/png", "a.png"]


def test_control_body_is_null_and_trailing_nulls_are_dropped():
    g = wire.Gcm(membership_hash=H, msg_type=wire.MSG_CONTROL, acks=b"\x00\x00" + bytes(8))
    assert cbor2.loads(g.encode()) == [wire.VERSION, H, 10, None, b"\x00\x00" + bytes(8)]
    assert wire.decode_gcm(g.encode()) == g


def test_reply_who_array_forms():
    one = wire.reply_who_array([("alice", CAP)])
    assert cbor2.loads(one) == [[["alice", CAP]]]
    w = wire.reply_who_decode(one)
    assert w.rosters is None and wire.without_rosters(w) is not None
    full = wire.reply_who_array([("alice", CAP), None], [[(0, 0), (1, None)], None], [(0, bytes(104), 1)], 0, 2)
    w = wire.reply_who_decode(full)
    assert w.introducer == 0 and w.newcomer == 2 and w.please_adds[1] is None
    assert wire.to_join_reply(w) is not None
    for bad in (cbor2.dumps([]), cbor2.dumps([["x"]]), cbor2.dumps([[["a", bytes(135)]]]), cbor2.dumps([[["a", CAP]], "r"]), b"\x00", cbor2.dumps([[["", CAP]]]), cbor2.dumps([[["a" * 31, CAP]]]), cbor2.dumps({"please_adds": [{"display_name": "", "read_cap": CAP}]})):
        assert wire.reply_who_decode(bad) is None, bad
