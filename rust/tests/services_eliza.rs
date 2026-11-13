#![cfg(feature = "std")]

use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pigeonhole_protocols::services::eliza;
use pigeonhole_protocols::pigeonservice::pigeonhole::write;
use pigeonhole_protocols::pigeonservice::testkit::*;
use pigeonhole_protocols::pigeonservice::{Config, Conn, Keypair, Service, induct};
use pigeonhole_protocols::transport::Backend;
use pigeonhole_protocols::transport::sim::World;

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/services/katzenqt_boxes.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn h(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), f).await.expect("timed out")
}

async fn reply(conn: &Conn<World>) -> String {
    loop {
        if let Some(t) = within(eliza::recv_text(conn)).await.unwrap() {
            return t;
        }
    }
}

/// Waits for a voucher file and returns its code.
async fn voucher(dir: &std::path::Path) -> (std::path::PathBuf, String) {
    within(async {
        loop {
            if let Some(e) = std::fs::read_dir(dir).ok().and_then(|mut d| d.next()) {
                let path = e.unwrap().path();
                return (path.clone(), std::fs::read_to_string(path).unwrap().trim().to_string());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn katzenqt_peer_talks_with_eliza() {
    let net = world();
    let data = tempfile::tempdir().unwrap();
    let mut cfg = Config::new(Keypair::generate(&net).await.unwrap(), data.path().join("state"));
    cfg.display_name = "Eliza".into();
    cfg.poll_interval = POLL;
    let svc = Service::new(cfg, Arc::new(net.clone())).unwrap();
    let s = svc.clone();
    tokio::spawn(async move { s.run(eliza::chat).await.unwrap() });
    let vouchers = data.path().join("vouchers");
    tokio::spawn(eliza::keep_vouchers(svc.clone(), vouchers.clone(), 1));

    // A katzenqt user pastes the voucher into a new conversation, which
    // inducts it.
    let (file, code) = voucher(&vouchers).await;
    let token = STANDARD.decode(&code).unwrap();
    let ph = Arc::new(net.clone());
    let user = within(induct(ph.clone(), &token, "alice", POLL)).await.unwrap();
    assert_eq!(reply(&user).await, eliza::engine::GREETING);

    // katzenqt's own control traffic is skipped.
    let v = vectors();
    user.send(&h(&v["control"])).await.unwrap();
    user.send(&h(&v["introduction"])).await.unwrap();
    user.send(&eliza::text_box("I am sad", 4)).await.unwrap();
    assert_eq!(reply(&user).await, "I am sorry to hear that you are sad.");

    // A long message comes through a substream.
    let sub = ph.new_keypair().await.unwrap();
    let mut idx = sub.first.clone();
    let chunks: Vec<Vec<u8>> = v["long_substream"].as_array().unwrap().iter().map(h).collect();
    for c in &chunks {
        idx = write(&*ph, &sub.write_cap, &idx, c).await.unwrap();
    }
    let mut ind = vec![b'I'];
    ind.extend_from_slice(&(chunks.len() as u32).to_be_bytes());
    ind.extend_from_slice(&sub.read_cap);
    user.send(&ind).await.unwrap();
    assert!(!reply(&user).await.is_empty());

    // The used voucher's file goes and a fresh one takes its place.
    within(async {
        while file.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let (_, fresh) = voucher(&vouchers).await;
    assert_ne!(fresh, code);
    svc.close().await;
}
