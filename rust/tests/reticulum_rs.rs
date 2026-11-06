//! Reticulum-rs against Python RNS on loopback TCP. Needs Python 3 with the `rns` package, and
//! for the replica test `pigeonhole_rns` with Channel query mode (katzenpost/pigeonhole_rns#3)
//! and `hpqc`. Run with
//!
//! ```text
//! PYTHON=/path/to/venv/bin/python PYTHONPATH=/path/to/pigeonhole_rns \
//!     cargo test --features reticulum-rs --test reticulum_rs -- --ignored --test-threads 1
//! ```
#![cfg(feature = "reticulum-rs")]

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use reticulum::channel::Message;
use reticulum::destination::link::LinkStatus;
use reticulum::error::RnsError;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::transport::{Transport, TransportConfig};
use tokio::io::{AsyncBufReadExt, BufReader, Lines};
use tokio::process::{Child, ChildStdout, Command};
use tokio::time::{Instant, sleep, timeout};

fn python() -> String {
    std::env::var("PYTHON").unwrap_or_else(|_| "python3".into())
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/reticulum_rs").join(name)
}

async fn line_with(lines: &mut Lines<BufReader<ChildStdout>>, prefix: &str) -> String {
    timeout(Duration::from_secs(30), async {
        loop {
            let l = lines.next_line().await.unwrap().expect("python exited");
            if l.starts_with(prefix) {
                return l;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no {prefix:?} line from python"))
}

#[derive(Clone)]
struct Raw(Vec<u8>);

impl Message for Raw {
    fn unpack(packed: &[u8], message_type: u16) -> Result<Self, RnsError> {
        if message_type != 0x0101 {
            return Err(RnsError::ChannelError);
        }
        Ok(Raw(packed.to_vec()))
    }
    fn pack(&self) -> Vec<u8> {
        self.0.clone()
    }
    fn message_type(&self) -> u16 {
        0x0101
    }
}

/// A Python process under `timeout 600`, stopped when dropped, also on a failed assertion: TERM
/// through `timeout`, then KILL to whatever of Python is left, then to `timeout` itself.
struct Py(Child);

impl Drop for Py {
    fn drop(&mut self) {
        if let Some(pid) = self.0.id() {
            let pid = pid.to_string();
            let _ = std::process::Command::new("kill").arg(&pid).status();
            // Let Python save its state before its directory goes, then make sure it is gone.
            std::thread::sleep(Duration::from_millis(500));
            let _ = std::process::Command::new("pkill").args(["-KILL", "-P", &pid]).status();
        }
    }
}

fn spawn_py<S: AsRef<std::ffi::OsStr>>(args: &[S], piped: bool) -> Py {
    let mut c = Command::new("timeout");
    c.arg("600").arg(python()).arg("-u").args(args).kill_on_drop(true);
    if piped {
        c.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    Py(c.spawn().expect("start python"))
}

/// A Python process with stdout and stderr going to `out` and `err`.
fn spawn_logged<S: AsRef<std::ffi::OsStr>>(args: &[S], out: &std::path::Path, err: &std::path::Path) -> Py {
    let mut c = Command::new("timeout");
    c.arg("600").arg(python()).arg("-u").args(args).kill_on_drop(true);
    let o = std::fs::File::create(out).unwrap();
    let e = if out == err { o.try_clone().unwrap() } else { std::fs::File::create(err).unwrap() };
    c.stdout(o).stderr(e);
    Py(c.spawn().expect("start python"))
}

/// Prints the log at its path when the test fails, before the directory holding it goes.
struct DumpOnPanic(PathBuf);

impl Drop for DumpOnPanic {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let log = std::fs::read_to_string(&self.0).unwrap_or_default();
            eprintln!("---- {} ----\n{log}---- end ----", self.0.display());
        }
    }
}

fn spawn_echo(dir: &tempfile::TempDir, port: u16) -> Py {
    let rns = dir.path().join("rns");
    let port = port.to_string();
    spawn_py(&[fixture("channel_echo.py").as_os_str(), rns.as_os_str(), port.as_ref()], true)
}

/// Every Channel message size from 1 byte to the Channel MDU at the 500 byte MTU (425, so 431
/// with the envelope) goes to Python and comes back, each one proved both ways.
#[tokio::test]
#[ignore = "needs Python RNS; see the module doc"]
async fn channel_echo_against_python_rns() {
    let _ = env_logger::builder().is_test(true).try_init();
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let port = 42311;
    let mut child = spawn_echo(&dir, port);
    let mut lines = BufReader::new(child.0.stdout.take().unwrap()).lines();
    let dest = line_with(&mut lines, "dest ").await;
    let dest = dest.trim_start_matches("dest ").to_string();

    let transport = Transport::new(TransportConfig::default());
    sleep(Duration::from_secs(1)).await;
    transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new(format!("127.0.0.1:{port}")), TcpClient::spawn);
    let mut announces = transport.recv_announces().await;
    let desc = timeout(Duration::from_secs(30), async {
        loop {
            let a = announces.recv().await.unwrap();
            let d = a.destination.lock().await.desc;
            if hex::encode(d.address_hash.as_slice()) == dest {
                return d;
            }
        }
    })
    .await
    .expect("no announce");

    let link = transport.link(desc).await;
    let deadline = Instant::now() + Duration::from_secs(20);
    while link.lock().await.status() != LinkStatus::Active {
        assert!(Instant::now() < deadline, "link not active");
        sleep(Duration::from_millis(20)).await;
    }
    let (channel, mut rx) = transport.mk_channel::<Raw>(link).await.unwrap();
    assert!(line_with(&mut lines, "mdu ").await.ends_with(" 425"));

    let mut proofs = Vec::new();
    for n in 1..=425usize {
        let msg = Raw((0..n).map(|i| (i * 7 + n) as u8).collect());
        let deadline = Instant::now() + Duration::from_secs(20);
        let hash = loop {
            match channel.send(&msg).await {
                Ok(h) => break h,
                Err(RnsError::LinkNotReady) if Instant::now() < deadline => {
                    sleep(Duration::from_millis(5)).await
                }
                Err(e) => panic!("send {n}: {e:?}"),
            }
        };
        proofs.push(channel.watch_message_delivery(hash).await);
        let back = timeout(Duration::from_secs(20), rx.recv()).await.unwrap().unwrap();
        assert_eq!(back.0, msg.0, "echo of {n} bytes");
    }
    for (n, w) in proofs.into_iter().enumerate() {
        if let Some(mut w) = w {
            // Already delivered when no watch is left: the proof came before we asked.
            let got = timeout(Duration::from_secs(10), w.recv()).await;
            assert!(matches!(got, Ok(Ok(true)) | Ok(Err(_))), "proof of message {}", n + 1);
        }
    }
    let l = timeout(Duration::from_secs(10), async {
        loop {
            let l = line_with(&mut lines, "received ").await;
            if l == "received 425 proved 425" {
                return l;
            }
        }
    })
    .await;
    assert!(l.is_ok(), "python did not see all 425 messages and proofs");
}

fn unhex(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

/// Frames and padding as `pigeonhole_rns` makes them (tests/reticulum_rs/make_frames.py).
#[test]
fn frames_match_pigeonhole_rns() {
    use pigeonhole_protocols::transport::reticulum_rs::{Frame, Reassembler, pad, piece_size, split};
    let v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture("frames.json")).unwrap()).unwrap();
    assert_eq!(v["piece_size"].as_u64().unwrap() as usize, piece_size(500));
    for c in v["split"].as_array().unwrap() {
        let data = unhex(&c["data"]);
        let rid = c["request_id"].as_u64().unwrap() as u16;
        let want: Vec<Vec<u8>> = c["frames"].as_array().unwrap().iter().map(unhex).collect();
        let got: Vec<Vec<u8>> = split(rid, &data, piece_size(500)).unwrap().iter().map(Frame::to_bytes).collect();
        assert_eq!(got, want, "{} bytes", data.len());
        let mut r = Reassembler::default();
        let out: Vec<_> = want.iter().filter_map(|b| r.feed(Frame::from_bytes(b).unwrap())).collect();
        assert_eq!(out, vec![data]);
    }
    for p in v["pad"].as_array().unwrap() {
        let size = p["box_size"].as_u64().unwrap() as usize;
        assert_eq!(pad(&unhex(&p["plaintext"]), size).unwrap(), unhex(&p["padded"]));
    }
}

fn rns_config(dir: &std::path::Path, server: bool, port: u16) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    let iface = if server {
        format!("type = TCPServerInterface\n    listen_ip = 127.0.0.1\n    listen_port = {port}")
    } else {
        format!("type = TCPClientInterface\n    target_host = 127.0.0.1\n    target_port = {port}")
    };
    let transport = if server { "Yes" } else { "No" };
    std::fs::write(
        dir.join("config"),
        format!(
            "[reticulum]\n  enable_transport = {transport}\n  share_instance = No\n[logging]\n  loglevel = 3\n[interfaces]\n  [[Tcp]]\n    enabled = yes\n    {iface}\n"
        ),
    )
    .unwrap();
    dir.to_path_buf()
}

/// Runs the pigeonhole_rns client and returns its stdout. A query left unanswered is asked again,
/// as a client polls: Python RNS registers a Link request's receipt only after sending it, so a
/// reply arriving first on loopback is dropped and the client gives up after its 60 s timeout,
/// printing `code None` for a write or `code 7` for a read.
async fn cli(dir: &std::path::Path, port: u16, args: &[&str]) -> String {
    let cfg = rns_config(&dir.join("rns-client"), false, port);
    let mut a: Vec<std::ffi::OsString> = vec!["-m".into(), "pigeonhole_rns.cli".into(), "--config".into(), cfg.into()];
    a.extend(["--box-size", "1000"].iter().chain(args).map(Into::into));
    let (o, e) = (dir.join("cli.out"), dir.join("cli.err"));
    for attempt in 1..=3 {
        let mut p = spawn_logged(&a, &o, &e);
        let t = std::time::Instant::now();
        let status = timeout(Duration::from_secs(120), p.0.wait()).await;
        let elapsed = t.elapsed();
        drop(p);
        let out = std::fs::read_to_string(&o).unwrap_or_default();
        let err = std::fs::read_to_string(&e).unwrap_or_default();
        if matches!(status, Ok(Ok(s)) if s.success()) {
            return out;
        }
        let report = format!("pigeonhole_rns {args:?} after {elapsed:?}: {status:?}\nstdout:\n{out}\nstderr:\n{err}");
        let unanswered = out.lines().any(|l| l.ends_with(" code None")) || err.lines().any(|l| l == "code 7");
        assert!(unanswered && attempt < 3, "{report}");
        eprintln!("{report}\nasking again");
    }
    unreachable!()
}

/// The backend against a `pigeonhole_rns` replica in Channel mode: write, read, delete, read
/// the tombstone and a box never written; then boxes crossing with the Python client, which
/// queries in request mode.
#[tokio::test]
#[ignore = "needs Python RNS and pigeonhole_rns with Channel mode; see the module doc"]
async fn backend_against_pigeonhole_rns_replica() {
    use hpqc::bacap::MessageBoxIndex;
    use pigeonhole_protocols::transport::reticulum_rs::ReticulumRsBackend;
    use pigeonhole_protocols::transport::{Backend, Read};

    let _ = env_logger::builder().is_test(true).try_init();
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let port = 42312;
    let cfg = rns_config(&dir.path().join("rns-replica"), true, port);
    let store = dir.path().join("store");
    let log = dir.path().join("replica.log");
    let _replica = spawn_logged(
        &[
            "-m".as_ref(),
            "pigeonhole_rns.cli".as_ref(),
            "--config".as_ref(),
            cfg.as_os_str(),
            // Any size: the backend writes boxes of the mesh size and of 1000 bytes.
            "--box-size".as_ref(),
            "0".as_ref(),
            "-vv".as_ref(),
            "replica".as_ref(),
            "--storage".as_ref(),
            store.as_os_str(),
            "--announce-interval".as_ref(),
            std::ffi::OsStr::new("3"),
        ],
        &log,
        &log,
    );
    let _dump = DumpOnPanic(log);
    sleep(Duration::from_secs(3)).await;
    let b = ReticulumRsBackend::connect(&format!("127.0.0.1:{port}"), 1000, Duration::from_secs(60))
        .await
        .expect("no replica");
    assert!(b.entry().is_some());
    let next = |i: &[u8]| MessageBoxIndex::from_bytes(i).unwrap().next_index().unwrap().to_bytes().to_vec();

    let k = b.new_keypair().await.unwrap();
    // Three frames each way at the 500 byte MTU.
    let text: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
    b.write_box(&k.write_cap, &k.first, &text).await.unwrap();
    assert_eq!(b.read_box(&k.read_cap, &k.first).await.unwrap(), Read::Data(text));
    b.write_box(&k.write_cap, &k.first, &[]).await.unwrap();
    assert_eq!(b.read_box(&k.read_cap, &k.first).await.unwrap(), Read::Tombstone);
    assert_eq!(b.read_box(&k.read_cap, &next(&k.first)).await.unwrap(), Read::NotFound);
    assert_eq!(b.max_plaintext().await.unwrap(), 256, "boxes are written at the mesh size");

    // The Python client writes index 0, we read it; we write index 2, it reads it.
    let k = b.new_keypair().await.unwrap();
    cli(dir.path(), port, &["write", "--writecap", &hex::encode(&*k.write_cap), "--index", "0", "from python"]).await;
    assert_eq!(b.read_box(&k.read_cap, &k.first).await.unwrap(), Read::Data(b"from python".to_vec()));
    let third = next(&next(&k.first));
    b.write_box(&k.write_cap, &third, b"from rust").await.unwrap();
    let out = cli(dir.path(), port, &["read", "--readcap", &hex::encode(&*k.read_cap), "--index", "2"]).await;
    assert_eq!(out.trim(), "from rust");
}
