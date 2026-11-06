//! Voucher joins between the Rust transport and the Python `MeshBackend`, through one
//! `pigeonhole_rns` replica on loopback port 42450: the Rust client joins the Python client's
//! group, then the Python client joins the Rust client's. Run with
//!
//! ```text
//! PYTHON=/path/to/venv/bin/python VIRTUAL_ENV=/path/to/venv PYTHONPATH=$PWD/../py:/path/to/pigeonhole_rns \
//!   cargo test --features reticulum-rs,reticulum-py --test reticulum_rs_join -- --ignored
//! ```

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use pigeonhole_protocols::protocols::katzenqt1::client::{Client, Config};
use pigeonhole_protocols::transport::Backend;
use pigeonhole_protocols::transport::reticulum_py::ReticulumPyBackend;
use pigeonhole_protocols::transport::reticulum_rs::ReticulumRsBackend;

const BOX: usize = 1530;
const PORT: u16 = 42450;

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn config(dir: &std::path::Path, server: bool) {
    std::fs::create_dir_all(dir).unwrap();
    let (t, iface) = if server {
        ("Yes", format!("type = TCPServerInterface\n    listen_ip = 127.0.0.1\n    listen_port = {PORT}"))
    } else {
        ("No", format!("type = TCPClientInterface\n    target_host = 127.0.0.1\n    target_port = {PORT}"))
    };
    std::fs::write(
        dir.join("config"),
        format!("[reticulum]\n  enable_transport = {t}\n  share_instance = No\n[logging]\n  loglevel = 3\n[interfaces]\n  [[Tcp]]\n    enabled = yes\n    {iface}\n"),
    )
    .unwrap();
}

async fn wait_for<F: std::future::Future<Output = bool>>(what: &str, mut ok: impl FnMut() -> F) {
    let deadline = Instant::now() + Duration::from_secs(300);
    while !ok().await {
        assert!(Instant::now() < deadline, "waited five minutes for {what}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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

/// `joiner` joins `owner`'s new group `g` and each reads what the other sends.
async fn join(owner: &Client, joiner: &Client, g: &str) {
    let og = owner.create(g).await.unwrap();
    let jg = joiner.join(g).await.unwrap();
    wait_for("a voucher code", || async { !joiner.chat(&jg).await.unwrap().code.is_empty() }).await;
    let code = joiner.chat(&jg).await.unwrap().code;
    wait_for("the owner's group", || async { owner.chat(&og).await.unwrap().joined }).await;
    owner.invite(&og, &code).await.unwrap();
    wait_for("the join", || async { joiner.chat(&jg).await.unwrap().joined }).await;
    joiner.send(&jg, "from the joiner").await.unwrap();
    owner.send(&og, "from the owner").await.unwrap();
    wait_for("each to read the other", || async {
        has(owner, &og, "from the joiner").await && has(joiner, &jg, "from the owner").await
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Python RNS, pigeonhole_rns and hpqc; see the module doc"]
async fn rust_and_python_join_each_other() {
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| std::env::temp_dir().display().to_string());
    let run = tempfile::TempDir::new_in(tmp).unwrap();
    let hub = run.path().join("rns-replica");
    config(&hub, true);
    let log = std::fs::File::create(run.path().join("replica.log")).unwrap();
    let _replica = Kill(
        Command::new(std::env::var("PYTHON").unwrap_or("python3".into()))
            .args(["-m", "pigeonhole_rns.cli", "--config"])
            .arg(&hub)
            // Any size: boxes are written at the mesh size, a voucher's first at BOX.
            .args(["--box-size", "0", "replica", "--storage"])
            .arg(run.path().join("store"))
            .args(["--announce-interval", "3"])
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    let leaf = run.path().join("rns-client");
    config(&leaf, false);
    let py = ReticulumPyBackend::connect(Some(&leaf), BOX, Duration::from_secs(60)).await.unwrap();
    let rs = ReticulumRsBackend::connect(&format!("127.0.0.1:{PORT}"), BOX, Duration::from_secs(60))
        .await
        .unwrap();
    let (pd, rd) = (run.path().join("py"), run.path().join("rs"));
    let alice = open(py, &pd, "alice").await;
    let bob = open(rs, &rd, "bob").await;
    join(&alice, &bob, "py-owned").await;
    join(&bob, &alice, "rs-owned").await;
    alice.close().await;
    bob.close().await;
}
