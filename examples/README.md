# Examples

`chat` is a minimal group chat, in Go (`go/examples/chat`) and in Rust (`rust/examples/chat.rs`): one member of
katzenqt1 groups, typed at in a terminal. Run one per person; the Go and Rust versions can share
a group.

## The ideas

A group is a set of members who each write their messages to a stream of their own on
Pigeonhole, Katzenpost's storage, and read everyone else's. Nobody runs the group: a member who
founds it is just its first writer.

A new member joins with a **contact voucher**. They mint one and hand its code to someone already
in the group, out of band: in person, or over another messenger. That member **invites** the
code; the joiner then learns the group's streams and the group learns theirs, and everyone starts
reading the newcomer.

Members **acknowledge** what they have read in the next message they send, so a message shows as
read only once a reader has said something since.

The client keeps everything in its **state directory**: groups, messages, files received, and the
network work still under way. Every change is saved there before any of the work it leads to goes
out, so a client stopped at any moment and opened again on the same directory carries on.

## Using the client

The examples use all of it that a chat app needs:

- `Open` (Go) or `Client::open` (Rust) takes the state directory, our name, and a backend:
  `thinclient` for the mixnet through the Katzenpost client daemon, or `remote` for
  `pigeonhole-sim`, an in-memory Pigeonhole on this machine.
- `Create`, `Join`, `Invite`, `Send`, `SendFile` change something. Each returns once the change is
  saved; the network work it starts happens in the background, and can take minutes on the
  mixnet.
- `Subscribe` reports changes as events: which group, and which of its lines are new or changed.
  The examples then ask for what to show with `Chat` (the group: its members, and while joining
  its voucher code), `Lines` (its messages and notices, after a given line) and `FilePath` (where a
  file received is kept).
- An event that stops the client carries the error: it stops rather than send anything it could
  not save.

## Running it

Over the mixnet, with a client daemon running (`-daemon` names its socket, `@katzenpost` by
default), in two terminals:

```
cd go && go run ./examples/chat -name alice -state alice
cd rust && cargo run --release --example chat -- -name bob -state bob
```

On one machine without the mixnet, start `pigeonhole-sim` in a terminal of its own first, and give
both `-sim`:

```
cd go && go run ./cmd/pigeonhole-sim -socket ../pigeonhole.sock
cd go && go run ./examples/chat -name alice -state alice -sim ../pigeonhole.sock
cd rust && cargo run --release --example chat -- -name bob -state bob -sim ../pigeonhole.sock
```

Then, as Alice, found a group:

```
/create friends
```

As Bob, ask to join it, and give Alice the voucher code it prints:

```
/join friends
[friends] give this voucher code to a member of friends: 1oT8…=
```

As Alice, invite it:

```
/invite 1oT8…=
```

Once Bob sees `joined the group`, anything either types is said in the group. `/file PATH` sends
a file; the receiver is told where it is kept. `/groups` lists the groups and their members, and
`/to GROUP` picks which one typing goes to. Stop either with `/quit` and start it again with the
same `-state`: it shows the conversation so far and carries on.
