# kp-fa: katzenpost finite audio

`kp-fa` (`go/cmd/kp-fa`) sends Ogg/Opus from stdin into a new Pigeonhole stream and prints the
stream's read capability. A listener with that capability tunes in live or from the start and gets
the original bytes back until the stream's end box. It runs through the Katzenpost client daemon.

```
cd go && go build ./cmd/kp-fa
```

`-c` names a thin client config; one that dials the daemon on its default socket is

```
[Dial]
  [Dial.Unix]
    Address = "@katzenpost"
```

Broadcast a file, or a microphone live, and tune in:

```
kp-fa -c thinclient.toml broadcast < show.opus
ffmpeg -f pulse -i default -c:a libopus -b:a 6k -ac 1 -f ogg - | kp-fa -c thinclient.toml on-air
kp-fa -c thinclient.toml tune-in READCAP | mpv -
```

`broadcast --readcap-file FILE` writes the read capability to a new file instead of stderr.
`tune-in` starts at the newest box; `--from-start` plays from the first, and `--back N` starts N
boxes behind the newest. `--window` sets how many boxes are in flight (4).

The interop suite (`go/services/interop`) broadcasts the three second public domain clip in
`go/cmd/kp-fa/testdata` over localnet and tunes in to it.
