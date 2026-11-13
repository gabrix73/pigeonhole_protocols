# pigeonhole-cp

`pigeonhole-cp` (`rust/src/bin/pigeonhole_cp.rs`) copies a file to and from a Pigeonhole channel
through the Katzenpost client daemon, like scp. `genkey` prints a channel's read capability, write
capability and first index; `send` writes a file; `receive` reads it into a directory, under the
name the sender gave it.

```
cd rust && cargo build --release --bin pigeonhole-cp
pigeonhole-cp genkey -c thinclient.toml
pigeonhole-cp send -c thinclient.toml -w WRITECAP -i INDEX -f notes.txt
pigeonhole-cp receive -c thinclient.toml -r READCAP -i INDEX -d inbox/
```

`-c` names a thin client config, as for [kp-fa](kp-fa.md). By default `send` uses the courier's
copy command, which is all or nothing at the destination but holds the whole file in memory and
takes about 9 MiB at most; `--no-copy` writes a box at a time, with no such limit.

The interop suite runs it in both modes when `PIGEONHOLE_CP_BIN` names the binary.
