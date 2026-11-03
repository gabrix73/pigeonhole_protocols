# zulip-bridge

`zulip-bridge` joins one Pigeonhole group chat to one Zulip stream. It is a member of the group,
as a katzenqt or hushphone user is, and a bot in Zulip. What anyone says in the group it posts to a
topic in the stream as `**name**: text`; what anyone writes in that topic it says in the group as
`Name: text`. Text only: files and notices stay on their side.

## Setting up

1. **A Zulip bot.** In Zulip, open *Personal settings → Bots → Add a new bot*, type *Generic bot*,
   and download its `zuliprc`. The bridge subscribes the bot to the stream itself when it starts.
   On `katzenpost.zulipchat.com` that file looks like

   ```
   [api]
   email=pigeonhole-bot@katzenpost.zulipchat.com
   key=...
   site=https://katzenpost.zulipchat.com
   ```

2. **A client daemon** connected to the mixnet, as for any Katzenpost client: `kpclientd` listening
   on `@katzenpost` by default.

3. **The bridge:**

   ```
   cd rust && cargo build --release --features zulip --bin zulip-bridge
   target/release/zulip-bridge --data-dir ~/zulip-bridge --zuliprc ~/zuliprc --stream general --topic pigeonhole
   ```

   `--stream` is the Zulip stream; `--topic` the topic in it (`pigeonhole` by default); `--group`
   the group's name as members see it, the stream's by default; `--name` the bot's own name
   (`zulip`); `--daemon` the daemon's socket; `--idle-days` how long a member may write nothing
   (14 days) before the bridge drops them. The data directory holds the bot's key and the
   group's state, and is all it needs to carry on after a restart. A self-signed Zulip
   certificate goes in `SSL_CERT_FILE`.

## Joining the group

A group member mints their own voucher and someone already in the group invites it. The bridge
is that someone, and a short conversation with it is how it gets the code. The bridge advertises
itself in the mixnet's service directory, so no invitation is needed to reach it:

1. In katzenqt or hushphone, the newcomer opens a conversation with the bot from the service
   directory. The bot answers with instructions.
2. They ask to join a group, which shows a voucher code of their own, and send that code to the
   bot. The bot invites it and the group appears in their app once the invitation is read, a
   few minutes on the mixnet.

Anyone who can reach the directory can join, so the group is as open as the stream it mirrors.

## What to know

- Zulip sees everything said in the group, in the clear, under the bot's account; members of the
  group should know their words leave the mixnet.
- The bridge reads every member's stream, and nothing but a member's own messages tells it they
  are still there. So it stops reading a member who writes nothing for `--idle-days`, saying so
  in the group first, where the member still reads it; whoever it drops rejoins through the bot
  as before. The group has no membership of its own: other members go on reading the dropped
  one, and only what they write after that stops reaching Zulip.
- The bridge posts group lines from where it stopped, so a restart does not repeat them. Zulip
  messages written while the bridge was down are not relayed.
- `cd rust && cargo test --features zulip --test services_zulip` checks it against an in-memory Pigeonhole
  and an imitation of Zulip; `TestZulipBridge` in `go/services/interop` runs it on localnet against
  a real Zulip (see the top-level README).
