//! The Reticulum transport over a real Reticulum network on this host: a `pigeonhole_rns` replica
//! process serving a TCP hub on loopback, and this process attached to it as a leaf. Its own test
//! binary, since Reticulum starts only on the thread that first used Python. Ignored by default,
//! as it spawns a process and binds a port. Run it with
//!
//! ```text
//! PYTHON=/path/to/venv/bin/python VIRTUAL_ENV=/path/to/venv PYTHONPATH=$PWD/../py \
//!   cargo test --features reticulum-py --test transport_reticulum_py_mesh -- --ignored
//! ```
//!
//! `PYTHON` runs the replica (default `python3`) and needs `pigeonhole_rns` and `hpqc`.

use std::process::{Child, Command};
use std::time::Duration;

use pigeonhole_protocols::protocols::katzenqt1::member::next_index;
use pigeonhole_protocols::transport::reticulum_py::ReticulumPyBackend;
use pigeonhole_protocols::transport::{Backend, Error, Read};

/// The replicas' size, read as well as the mesh size written; the replica takes any.
const BOX: usize = 1549;

fn config(dir: &std::path::Path, transport: bool, iface: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let t = if transport { "Yes" } else { "No" };
    std::fs::write(
        dir.join("config"),
        format!("[reticulum]\n  enable_transport = {t}\n  share_instance = No\n[logging]\n  loglevel = 3\n[interfaces]\n{iface}"),
    )
    .unwrap();
}

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore]
async fn real_mesh() {
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| std::env::temp_dir().display().to_string());
    let run = tempfile::TempDir::new_in(tmp).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let hub = run.path().join("rns-replica");
    config(
        &hub,
        true,
        &format!("  [[Hub]]\n    type = TCPServerInterface\n    enabled = yes\n    listen_ip = 127.0.0.1\n    listen_port = {port}\n"),
    );
    let log = std::fs::File::create(run.path().join("replica.log")).unwrap();
    let _replica = Kill(
        Command::new(std::env::var("PYTHON").unwrap_or("python3".into()))
            .args(["-m", "pigeonhole_rns.cli", "--config"])
            .arg(&hub)
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
    config(
        &leaf,
        false,
        &format!("  [[ToHub]]\n    type = TCPClientInterface\n    enabled = yes\n    target_host = 127.0.0.1\n    target_port = {port}\n"),
    );
    let be = ReticulumPyBackend::connect(Some(&leaf), BOX, Duration::from_secs(60)).await.unwrap();
    eprintln!("{}", be.entry().await.unwrap());
    assert_eq!(be.max_plaintext().await, Ok(256), "boxes are written at the mesh size");
    let kp = be.new_keypair().await.unwrap();
    assert_eq!(be.read_box(&kp.read_cap, &kp.first).await, Ok(Read::NotFound));
    be.write_box(&kp.write_cap, &kp.first, b"over the mesh").await.unwrap();
    assert_eq!(be.read_box(&kp.read_cap, &kp.first).await, Ok(Read::Data(b"over the mesh".to_vec())));
    assert_eq!(be.write_box(&kp.write_cap, &kp.first, b"other").await, Err(Error::BoxAlreadyExists));
    let next = next_index(&kp.first).unwrap();
    be.write_box(&kp.write_cap, &next, b"").await.unwrap();
    assert_eq!(be.read_box(&kp.read_cap, &next).await, Ok(Read::Tombstone));
    be.close().await.unwrap();
}
