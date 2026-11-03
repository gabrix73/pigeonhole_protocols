"""Writes frames.json: frames and padding made by pigeonhole_rns (channel.py and client.py of
katzenpost/pigeonhole_rns#3), for tests/reticulum_rs.rs. Run with that checkout on PYTHONPATH:

    PYTHONPATH=/path/to/pigeonhole_rns python make_frames.py > frames.json
"""

import json

from pigeonhole_rns.channel import split
from pigeonhole_rns.client import pad


def data(n):
    return bytes((i * 31 + n) & 0xFF for i in range(n))


cases = []
for rid, n in ((0, 0), (1, 1), (0x0102, 421), (0xBEEF, 422), (0xFFFF, 1117), (7, 3 * 421)):
    cases.append({"request_id": rid, "data": data(n).hex(), "frames": [f.pack().hex() for f in split(rid, data(n), 421)]})
pads = [{"plaintext": data(n).hex(), "box_size": b, "padded": pad(data(n), b).hex()} for n, b in ((0, 4), (5, 5), (50, 1000))]
print(json.dumps({"piece_size": 421, "split": cases, "pad": pads}, indent=1))
