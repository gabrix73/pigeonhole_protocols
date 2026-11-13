# status-bot

`status-bot` (`rust/src/bin/status_bot.rs`) reports on the mixnet its client daemon is on. Each
epoch it tells every conversation it is in what changed in the PKI document, which Pigeonhole
services the directory lists and whether each answers, and how many routers it is linked with. It
is reached through the service directory and a voucher router. Anything other than `status` gets
an ELIZA answer. With `--group` and `--bridge` it also joins a katzenqt1 group through the bot
that invites into it, and says each report there.

```
cd rust && cargo build --release --bin status-bot
status-bot --data-dir status-bot
```

`--daemon` names the client daemon (`@katzenpost` by default); `--data-dir` holds the bot's key and
state. `status-bot --help` lists the rest.

The interop suite runs it when `STATUS_BOT_BIN` names the binary.
