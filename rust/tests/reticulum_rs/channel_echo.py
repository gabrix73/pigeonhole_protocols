"""A Python RNS peer for tests/reticulum_rs.rs: a TCP server interface on
127.0.0.1:PORT, a destination rnsrs.echo that announces every two seconds,
and on each Link a Channel that sends every message back. Prints the
destination hash, then a line per second with the messages received and the
echoes the peer has proved."""

import os
import queue
import sys
import threading
import time

import RNS
from RNS.Channel import MessageBase

PORT = int(sys.argv[2])
CONFIG = """[reticulum]
  enable_transport = Yes
  share_instance = No
[logging]
  loglevel = 2
[interfaces]
  [[Hub]]
    type = TCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = %d
""" % PORT


class Raw(MessageBase):
    MSGTYPE = 0x0101

    def __init__(self, data=b""):
        self.data = data

    def pack(self):
        return self.data

    def unpack(self, raw):
        self.data = bytes(raw)


confdir = sys.argv[1]
os.makedirs(confdir, exist_ok=True)
with open(os.path.join(confdir, "config"), "w") as f:
    f.write(CONFIG)

RNS.Reticulum(configdir=confdir)
dest = RNS.Destination(RNS.Identity(), RNS.Destination.IN, RNS.Destination.SINGLE, "rnsrs", "echo")
received, sent, lock = [], [], threading.Lock()


def echo(channel, q):
    while True:
        data = q.get()
        while not channel.is_ready_to_send():
            time.sleep(0.005)
        env = channel.send(Raw(data))
        with lock:
            sent.append(env)


def on_link(link):
    ch = link.get_channel()
    ch.register_message_type(Raw)
    q = queue.Queue()
    threading.Thread(target=echo, args=(ch, q), daemon=True).start()

    def handler(msg):
        with lock:
            received.append(len(msg.data))
        q.put(msg.data)
        return True

    ch.add_message_handler(handler)
    print("mdu", ch.mdu, flush=True)


dest.set_link_established_callback(on_link)
print("dest", dest.hash.hex(), flush=True)
while True:
    dest.announce()
    for _ in range(2):
        time.sleep(1)
        with lock:
            proved = sum(1 for e in sent if e.packet.receipt and e.packet.receipt.status == RNS.PacketReceipt.DELIVERED)
            print("received", len(received), "proved", proved, flush=True)
