# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The client scenarios the Go and Rust clients run: pigeonhole's own under
go/protocols/katzenqt1/client/testdata/scenarios, and the shared ones under
testdata/katzenqt1/client_scenarios."""

import glob
import os

import pytest

from pigeonhole_protocols.katzenqt1 import scenario

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
OWN = sorted(glob.glob(os.path.join(ROOT, "go", "protocols", "katzenqt1", "client", "testdata", "scenarios", "*.txt")))
SHARED = sorted(glob.glob(os.path.join(ROOT, "testdata", "katzenqt1", "client_scenarios", "*.txt")))

def check(path, tmp_path, plain=False):
    with open(path) as f:
        script = f.read()
    got, unsaved = scenario.run(script, str(tmp_path), plain)
    assert not unsaved, unsaved
    if got != script:
        a, e = got.splitlines(), script.splitlines()
        for i, (x, y) in enumerate(zip(a, e)):
            assert x == y, "%s line %d" % (os.path.basename(path), i + 1)
        assert len(a) == len(e)


def test_scenarios_present():
    assert len(OWN) == 13 and len(SHARED) == 8


@pytest.mark.parametrize("path", OWN, ids=[os.path.basename(p) for p in OWN])
def test_own_scenario(path, tmp_path):
    check(path, tmp_path)


@pytest.mark.parametrize("path", SHARED, ids=[os.path.basename(p) for p in SHARED])
def test_shared_scenario(path, tmp_path):
    check(path, tmp_path, plain=True)
