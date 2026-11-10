# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Version 5, text messages packed in one box: against the shared vectors."""
import pytest

from pigeonhole_protocols.katzenqt1 import wire
from test_wire_vectors import load, message_json, unhex

V = load("groupchat_wire_vectors_v5.json")


@pytest.mark.parametrize("e", V["packed"], ids=[e["name"] for e in V["packed"]])
def test_packed(e):
    cbor = unhex(e["start"])
    for t in e["added"]:
        cbor = wire.pack(cbor, t)
    assert cbor == unhex(e["cbor"])
    assert wire.texts_of(cbor) == e["texts"] and wire.text_of(cbor) == "\n".join(e["texts"])
    assert message_json(wire.to_message(cbor)) == {k: v for k, v in e["message"].items() if k != "membership_hash"}
    assert wire.decode_gcm(cbor).encode() == cbor and wire.unsupported(cbor) is None


@pytest.mark.parametrize("e", V["unsupported"], ids=[e["name"] for e in V["unsupported"]])
def test_unsupported_is_refused_and_named(e):
    assert wire.decode_gcm(unhex(e["cbor"])) is None and wire.unsupported(unhex(e["cbor"])) == (e["version"], e["msg_type"])


@pytest.mark.parametrize("e", V["malformed"], ids=[e["name"] for e in V["malformed"]])
def test_malformed_is_refused(e):
    assert wire.decode_gcm(unhex(e["cbor"])) is None and wire.unsupported(unhex(e["cbor"])) is None


def test_packs_only_text_of_the_array_form():
    h = bytes(32)
    assert wire.pack(wire.text_content(h, "a", wire.MAP_VERSION), "b") is None
    assert wire.pack(wire.file_content(h, b"x", "arbitrary", "x"), "b") is None
