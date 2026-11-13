# Packing and receipts

On a slow link such as a LoRa mesh every box costs, so the katzenqt1 engine sends as few as it can.

## Packed boxes

A text message sent while the one before it still waits to be written goes into that box, as many
as fit in the box size the transport writes (256 bytes on a mesh, 1549 on the mixnet;
[`pack_box_sizes.txt`](../go/protocols/katzenqt1/client/testdata/scenarios/pack_box_sizes.txt) shows both). Such a box has msg_type 12:

```
[5, membership_hash, 12, [text, ...], acks, numbers, introduced_at]
```

with trailing nulls left out. msg_type 12 exists only in wire version 5, which is otherwise
version 4; version 5 is what this client writes. A reader of version 4 refuses msg_type 12 as a
type it does not know, and with it the messages and acknowledgements in the box; it tells the user
"~alice sent a message this app cannot show (type 12, version 5): update the app". A reader of
version 5 does the same for any version above 5 or type it does not know. There is no
negotiation. [`testdata/katzenqt1/groupchat_wire_vectors_v5.json`](../testdata/katzenqt1/groupchat_wire_vectors_v5.json)
holds the vectors.

## Receipts

What a member has read is acknowledged in its next message. When it has sent nothing 30 seconds
after reading something (`ReceiptDelay`), a control message carries the acknowledgements alone.
Boxes that carry no content, such as these, are not acknowledged on their own, so receipts do not
answer receipts.

`Pack` and `ReceiptDelay` on the engine turn either off (`pack`, `receipt_delay` in Rust and
Python); a client writing wire version 3 or 4 never packs.
