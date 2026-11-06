//! Box sizes against testdata/box_sizes.json: the mesh size's fit in one Link packet, a stream of
//! boxes of mixed sizes, and a group whose members write boxes of different sizes, as one spanning
//! a mesh and the mixnet does.

use std::time::{Duration, Instant};

use pigeonhole_protocols::protocols::katzenqt1::client::{Client, Config};
use pigeonhole_protocols::protocols::katzenqt1::wire::{MIN_BOX, assemble, chunk_count, substream_box};
use pigeonhole_protocols::transport::sim::World;
use pigeonhole_protocols::transport::{BOX_SIZES, MAX_BOX_SIZE, MIN_BOX_SIZE, allowed_sizes, box_size, fit_size};

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/box_sizes.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn unhex(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn num(v: &serde_json::Value, k: &str) -> usize {
    v[k].as_u64().unwrap() as usize
}

#[test]
fn sizes_match_vectors() {
    let v = vectors();
    let want: Vec<(String, usize)> = v["sizes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["name"].as_str().unwrap().to_string(), num(s, "plaintext")))
        .collect();
    let got: Vec<(String, usize)> = BOX_SIZES.iter().map(|(n, s)| (n.to_string(), *s)).collect();
    assert_eq!(got, want);
    assert_eq!((num(&v, "min"), num(&v, "max")), (MIN_BOX_SIZE, MAX_BOX_SIZE));
    assert_eq!(MIN_BOX_SIZE, MIN_BOX);
    assert_eq!(box_size("mesh"), Some(256));
    assert_eq!(box_size("mixnet"), Some(1549));
    assert_eq!(box_size("1000"), Some(1000));
    for bad in ["huge", "140", "16385", "0"] {
        assert_eq!(box_size(bad), None, "{bad}");
    }
    assert_eq!(allowed_sizes(&[512, 256]), Some(vec![256, 512, 1549]));
    assert_eq!(allowed_sizes(&[100]), None);
    assert_eq!(fit_size(&[256, 1549], 256, 200), Some(256));
    assert_eq!(fit_size(&[256, 1549], 256, 373), Some(1549));
    assert_eq!(fit_size(&[256, 1549], 256, 1550), None);
}

#[test]
fn substreams_match_vectors() {
    for c in vectors()["substreams"].as_array().unwrap() {
        let size = box_size(c["size"].as_str().unwrap()).unwrap();
        let blob = unhex(&c["message"]);
        let want: Vec<Vec<u8>> = c["boxes"].as_array().unwrap().iter().map(unhex).collect();
        let got: Vec<Vec<u8>> = (0..chunk_count(blob.len(), size)).map(|i| substream_box(&blob, size, i)).collect();
        assert_eq!(got, want, "{} bytes at {size}", blob.len());
        assert_eq!(assemble(&want).unwrap(), blob);
    }
}

#[cfg(feature = "reticulum-rs")]
mod sealed {
    use super::*;
    use hpqc::bacap::{MessageBoxIndex, ReadCap, WriteCap};
    use hpqc::rand_core::UnwrapErr;
    use pigeonhole_protocols::transport::reticulum_rs::{
        HEADROOM, MTU, REQUEST_FRAMING, WRITE_OVERHEAD, link_mdu, mesh_box_size, pad, piece_size, unpad, unpad_allowed,
    };

    const CTX: &[u8] = b"pigeonhole context";

    /// Only the payload differs: a box sealed at any size has the same box ID and signature sizes.
    #[test]
    fn sealed_sizes_match_vectors() {
        let wc = WriteCap::generate(&mut UnwrapErr(getrandom::SysRng));
        let rc = wc.read_cap();
        let idx = MessageBoxIndex::from_bytes(&rc.to_bytes()[32..]).unwrap();
        for s in vectors()["sizes"].as_array().unwrap() {
            let plaintext = unhex(&s["pad"]["plaintext"]);
            let padded = pad(&plaintext, num(s, "plaintext")).unwrap();
            assert_eq!(padded, unhex(&s["pad"]["padded"]));
            assert_eq!(padded.len(), num(s, "padded"));
            let (box_id, ct, sig) = wc.position_at(&idx).unwrap().encrypt(CTX, &padded).unwrap();
            assert_eq!((box_id.len(), sig.len(), ct.len()), (num(s, "box_id"), num(s, "signature"), num(s, "ciphertext")));
            assert_eq!(WRITE_OVERHEAD + num(s, "plaintext"), num(s, "write_query"));
            assert_eq!(REQUEST_FRAMING + num(s, "write_query"), num(s, "link_request"));
            let opened = rc.position_at(&idx).unwrap().open(CTX, &box_id, &ct, &sig).unwrap();
            assert_eq!(unpad(&opened).unwrap(), plaintext);
        }
    }

    /// A mesh-size write is one Link packet with headroom to spare, as a Channel frame or a Link
    /// request; 16 bytes more would not be.
    #[test]
    fn mesh_size_fits_one_link_packet() {
        let v = vectors();
        assert_eq!(mesh_box_size(MTU), box_size("mesh").unwrap());
        assert_eq!((num(&v, "link_mdu"), num(&v, "headroom")), (link_mdu(MTU), HEADROOM));
        let mesh = v["sizes"].as_array().unwrap().iter().find(|s| s["name"] == "mesh").unwrap();
        let room = link_mdu(MTU) - HEADROOM;
        assert!(num(mesh, "channel_message") <= room && num(mesh, "link_request") <= room);
        assert!(num(mesh, "link_request") + 16 > room);
        assert!(num(mesh, "write_query") <= piece_size(MTU));
    }

    /// One stream whose boxes are of different sizes reads through, with the extra size allowed;
    /// without it, that box is refused.
    #[test]
    fn mixed_stream_reads_every_allowed_size() {
        let m = &vectors()["mixed_stream"];
        let rc = ReadCap::from_bytes(&unhex(&m["read_cap"])).unwrap();
        let extra: Vec<usize> = m["extra_sizes"].as_array().unwrap().iter().map(|n| n.as_u64().unwrap() as usize).collect();
        let with = allowed_sizes(&extra).unwrap();
        let without = allowed_sizes(&[]).unwrap();
        let mut got = Vec::new();
        for b in m["boxes"].as_array().unwrap() {
            let idx = MessageBoxIndex::from_bytes(&unhex(&b["index"])).unwrap();
            let box_id: [u8; 32] = unhex(&b["box_id"]).try_into().unwrap();
            let opened = rc.position_at(&idx).unwrap().open(CTX, &box_id, &unhex(&b["ciphertext"]), &unhex(&b["signature"])).unwrap();
            got.push(unpad_allowed(&opened, &with).unwrap());
            assert_eq!(unpad_allowed(&opened, &without).is_ok(), !extra.contains(&num(b, "size")));
        }
        let want: Vec<Vec<u8>> = m["plaintexts"].as_array().unwrap().iter().map(unhex).collect();
        assert_eq!(got, want);
        assert_eq!(assemble(&got).unwrap(), unhex(&m["message"]));
    }
}

fn tmp() -> tempfile::TempDir {
    tempfile::TempDir::new_in(
        std::env::var("TMPDIR").unwrap_or_else(|_| format!("{}/scratch/tmp", std::env::var("HOME").unwrap())),
    )
    .unwrap()
}

async fn open(w: World, dir: &std::path::Path, name: &str) -> Client {
    let cfg = Config {
        state_dir: dir.into(),
        name: name.into(),
        epoch_poll: Duration::from_secs(1),
        no_sync: false,
        key: None,
        wire_version: 4,
    };
    Client::open(cfg, w).await.unwrap()
}

async fn wait_for<F: std::future::Future<Output = bool>>(what: &str, mut ok: impl FnMut() -> F) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !ok().await {
        assert!(Instant::now() < deadline, "waited a minute for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn reads(c: &Client, id: &str, text: &str, file: &str, data: &[u8]) -> bool {
    let lines = c.lines(id, None).await.unwrap();
    let a = lines.iter().find_map(|l| l.line.attachment.clone().filter(|a| a.name == file));
    lines.iter().any(|l| l.line.text == text) && a.is_some_and(|a| *c.read_file(&a).unwrap() == data)
}

/// A member on a mesh writes boxes of the mesh size, one on the mixnet of the mixnet's, and each
/// reads the other's long message and file: substreams cut to either size.
#[tokio::test(flavor = "multi_thread")]
async fn group_across_box_sizes() {
    let w = World::default();
    let (mesh, mixnet) = (box_size("mesh").unwrap(), box_size("mixnet").unwrap());
    let (ad, bd) = (tmp(), tmp());
    let alice = open(w.writing(mesh), ad.path(), "alice").await;
    let bob = open(w.writing(mixnet), bd.path(), "bob").await;
    let g = alice.create("g").await.unwrap();
    let bg = bob.join("g").await.unwrap();
    wait_for("a voucher code and alice's group", || async {
        !bob.chat(&bg).await.unwrap().code.is_empty() && alice.chat(&g).await.unwrap().joined
    })
    .await;
    let code = bob.chat(&bg).await.unwrap().code;
    alice.invite(&g, &code).await.unwrap();
    wait_for("bob to join", || async { bob.chat(&bg).await.unwrap().joined }).await;
    let before = w.plaintexts().len();
    let text = "a long message ".repeat(100);
    let data: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
    alice.send(&g, &text).await.unwrap();
    alice.send_file(&g, "alice.bin", data.clone()).await.unwrap();
    bob.send(&bg, &text).await.unwrap();
    bob.send_file(&bg, "bob.bin", data.clone()).await.unwrap();
    wait_for("each to read the other's text and file", || async {
        reads(&bob, &bg, &text, "alice.bin", &data).await && reads(&alice, &g, &text, "bob.bin", &data).await
    })
    .await;
    let sizes: Vec<usize> = w.plaintexts().iter().map(Vec::len).collect();
    assert!(sizes.len() - before > 20);
    assert!(sizes.iter().any(|n| *n > mesh) && sizes.iter().filter(|n| **n == mesh).count() > 15);
    alice.close().await;
    bob.close().await;
}
