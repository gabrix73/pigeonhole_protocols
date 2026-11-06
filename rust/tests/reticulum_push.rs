//! Push against a real `pigeonhole_rns` replica on loopback: two clients join a group, sit idle
//! until their polls have backed off, then each sends one line. A replica serving push hands each
//! line over at once, to the Python transport and to Reticulum-rs; one that does not push (its
//! announce without bit 4) still gets them through by polling. Run with
//!
//! ```text
//! PYTHON=/path/to/venv/bin/python VIRTUAL_ENV=/path/to/venv PYTHONPATH=$PWD/../py:/path/to/pigeonhole_rns \
//!   cargo test --features reticulum-rs,reticulum-py --test reticulum_push -- --ignored
//! ```

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use pigeonhole_protocols::protocols::katzenqt1::client::{Client, Config};
use pigeonhole_protocols::transport::Backend;
use pigeonhole_protocols::transport::reticulum_py::ReticulumPyBackend;
use pigeonhole_protocols::transport::reticulum_rs::ReticulumRsBackend;

const BOX: usize = 1530;
/// Long enough for a poll's backoff to reach 32 s.
const IDLE: Duration = Duration::from_secs(40);

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn config(dir: &std::path::Path, server: bool, port: u16) {
    std::fs::create_dir_all(dir).unwrap();
    let (t, iface) = if server {
        ("Yes", format!("type = TCPServerInterface\n    listen_ip = 127.0.0.1\n    listen_port = {port}"))
    } else {
        ("No", format!("type = TCPClientInterface\n    target_host = 127.0.0.1\n    target_port = {port}"))
    };
    std::fs::write(
        dir.join("config"),
        format!("[reticulum]\n  enable_transport = {t}\n  share_instance = No\n[logging]\n  loglevel = 3\n[interfaces]\n  [[Tcp]]\n    enabled = yes\n    {iface}\n"),
    )
    .unwrap();
}

/// A replica serving the TCP hub on `port`; with `push` false it announces no push.
fn replica(run: &std::path::Path, port: u16, push: bool) -> Kill {
    let hub = run.join("rns-replica");
    config(&hub, true, port);
    let log = std::fs::File::create(run.join("replica.log")).unwrap();
    let mut c = Command::new(std::env::var("PYTHON").unwrap_or("python3".into()));
    if push {
        c.args(["-m", "pigeonhole_rns.cli"]);
    } else {
        c.args([
            "-c",
            "import sys, pigeonhole_rns.replica as r, pigeonhole_rns.cli as cli; r.PUSH_FLAG = 0; sys.exit(cli.main(sys.argv[1:]))",
        ]);
    }
    c.arg("--config")
        .arg(&hub)
        .args(["--box-size", "0", "replica", "--storage"])
        .arg(run.join("store"))
        .args(["--announce-interval", "3"])
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    Kill(c.spawn().unwrap())
}

async fn wait_for<F: std::future::Future<Output = bool>>(what: &str, limit: Duration, mut ok: impl FnMut() -> F) -> Duration {
    let start = Instant::now();
    while !ok().await {
        assert!(start.elapsed() < limit, "waited {limit:?} for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    start.elapsed()
}

async fn has(c: &Client, id: &str, text: &str) -> bool {
    c.lines(id, None).await.unwrap().iter().any(|l| l.line.notice.is_none() && l.line.text == text)
}

async fn open<B: Backend>(be: B, dir: &std::path::Path, name: &str) -> Client {
    let cfg = Config {
        state_dir: dir.into(),
        name: name.into(),
        epoch_poll: Duration::from_secs(1),
        no_sync: false,
        key: None,
        wire_version: 4,
    };
    Client::open(cfg, be).await.unwrap()
}

/// `joiner` joins `owner`'s group; after `IDLE`, the time each takes to read a line the other
/// sends.
async fn idle_then_send(owner: &Client, joiner: &Client) -> (Duration, Duration) {
    let long = Duration::from_secs(300);
    let og = owner.create("g").await.unwrap();
    let jg = joiner.join("g").await.unwrap();
    wait_for("a voucher code", long, || async { !joiner.chat(&jg).await.unwrap().code.is_empty() }).await;
    let code = joiner.chat(&jg).await.unwrap().code;
    wait_for("the owner's group", long, || async { owner.chat(&og).await.unwrap().joined }).await;
    owner.invite(&og, &code).await.unwrap();
    wait_for("the join", long, || async { joiner.chat(&jg).await.unwrap().joined }).await;
    tokio::time::sleep(IDLE).await;
    owner.send(&og, "to the joiner").await.unwrap();
    let to_joiner = wait_for("the joiner to read", long, || has(joiner, &jg, "to the joiner")).await;
    tokio::time::sleep(IDLE).await;
    joiner.send(&jg, "to the owner").await.unwrap();
    let to_owner = wait_for("the owner to read", long, || has(owner, &og, "to the owner")).await;
    (to_joiner, to_owner)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Python RNS, pigeonhole_rns with push and hpqc; see the module doc"]
async fn pushed_at_once_over_both_transports() {
    let port = 42460;
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| std::env::temp_dir().display().to_string());
    let run = tempfile::TempDir::new_in(tmp).unwrap();
    let _replica = replica(run.path(), port, true);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let leaf = run.path().join("rns-client");
    config(&leaf, false, port);
    let py = ReticulumPyBackend::connect(Some(&leaf), BOX, Duration::from_secs(60)).await.unwrap();
    let rs = ReticulumRsBackend::connect(&format!("127.0.0.1:{port}"), BOX, Duration::from_secs(60)).await.unwrap();
    let alice = open(py, &run.path().join("py"), "alice").await;
    let bob = open(rs, &run.path().join("rs"), "bob").await;
    let (to_bob, to_alice) = idle_then_send(&alice, &bob).await;
    eprintln!("push: to bob on Reticulum-rs {to_bob:?}, to alice on the Python transport {to_alice:?}");
    // Polling would wait out a backoff of 32 s or more.
    assert!(to_bob < Duration::from_secs(10) && to_alice < Duration::from_secs(10));
    alice.close().await;
    bob.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Python RNS, pigeonhole_rns and hpqc; see the module doc"]
async fn polled_when_the_replica_does_not_push() {
    let port = 42461;
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| std::env::temp_dir().display().to_string());
    let run = tempfile::TempDir::new_in(tmp).unwrap();
    let _replica = replica(run.path(), port, false);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let addr = format!("127.0.0.1:{port}");
    let a = ReticulumRsBackend::connect(&addr, BOX, Duration::from_secs(60)).await.unwrap();
    let b = ReticulumRsBackend::connect(&addr, BOX, Duration::from_secs(60)).await.unwrap();
    let k = a.new_keypair().await.unwrap();
    assert!(a.watch(&k.read_cap, &k.first).await.is_none(), "no push without bit 4");
    let alice = open(a, &run.path().join("a"), "alice").await;
    let bob = open(b, &run.path().join("b"), "bob").await;
    let (to_bob, to_alice) = idle_then_send(&alice, &bob).await;
    eprintln!("polling: to bob {to_bob:?}, to alice {to_alice:?}");
    alice.close().await;
    bob.close().await;
}
