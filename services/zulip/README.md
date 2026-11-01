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
   cargo build --release --features zulip --bin zulip-bridge
   target/release/zulip-bridge --data-dir ~/zulip-bridge --zuliprc ~/zuliprc --stream general --topic pigeonhole
   ```

   `--stream` is the Zulip stream; `--topic` the topic in it (`pigeonhole` by default); `--group`
   the group's name as members see it, the stream's by default; `--name` the bot's own name
   (`zulip`); `--daemon` the daemon's socket. The data directory holds the bot's key, the group's
   state and its vouchers, and is all it needs to carry on after a restart. A self-signed Zulip
   certificate goes in `SSL_CERT_FILE`.

## Joining the group

A group member mints their own voucher and someone already in the group invites it. The bridge
is that someone, and a short conversation with it is how it gets the code:

1. The operator gives the newcomer one of the bot's voucher codes: the files in
   `<data-dir>/vouchers/`, each used once and replaced (`--vouchers` says how many to keep).
2. In katzenqt or hushphone, the newcomer pastes that code as a new contact. The bot answers
   with instructions.
3. They ask to join a group, which shows a voucher code of their own, and send that code to the
   bot. The bot invites it and the group appears in their app once the invitation is read, a
   few minutes on the mixnet.

Anyone with one of the bot's voucher codes can join, so hand them out as you would an invitation.

## What to know

- Zulip sees everything said in the group, in the clear, under the bot's account; members of the
  group should know their words leave the mixnet.
- The bridge posts group lines from where it stopped, so a restart does not repeat them. Zulip
  messages written while the bridge was down are not relayed.
- `cargo test --features zulip --test services_zulip` checks it against an in-memory Pigeonhole
  and an imitation of Zulip; `TestZulipBridge` in `services/interop` runs it on localnet against
  a real Zulip (see the top-level README).
