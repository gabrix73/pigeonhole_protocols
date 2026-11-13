# Push on the mesh

On Reticulum the katzenqt1 clients wait for a box instead of polling for it, when the replica
announces push (flag bit 4 of `pigeonhole_rns`, whose README gives the wire format under Push). A
read that finds no box subscribes to it on the open Link (mode 2 op 6), and the replica pushes the
box down that Link once it is written; the client then reads it from what was pushed, with no
query. A stream waiting for a push still reads again every 5 minutes (`PUSHED_POLL_MS`), in case
the push was lost, which also renews the subscription.

Against a replica that does not announce push, and on the mixnet, the client polls. Both mesh
transports do this (Python `MeshBackend.watch`, Rust `Backend::watch`); applications need no
change.
