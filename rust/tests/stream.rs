#![cfg(feature = "std")]

use std::sync::Arc;
use std::time::Duration;

use pigeonhole_protocols::protocols::katzenqt1::member::next_index;
use pigeonhole_protocols::protocols::stream::{self, Link, Tuning, decode, encode};
use pigeonhole_protocols::transport::Backend;
use pigeonhole_protocols::transport::sim::World;
use rand::RngCore;

fn tuning() -> Tuning {
    Tuning { window: 4, reads: 6, flush: Duration::from_millis(2), poll_min: Duration::from_millis(1), poll_max: Duration::from_millis(20), hot: Duration::from_millis(5) }
}

fn bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

#[test]
fn framing() {
    assert_eq!(encode(b"hi", false), b"\0hi");
    assert_eq!(decode(&encode(b"hi", true)).unwrap(), (&b"hi"[..], true));
    assert_eq!(decode(&encode(b"", true)).unwrap(), (&b""[..], true));
    assert_eq!(decode(&encode(b"", false)).unwrap(), (&b""[..], false));
    assert!(decode(b"").is_err());
    assert!(decode(b"\x02x").is_err());
}

async fn session(w: &Arc<World>, a: &mut Link, b: &mut Link, to_b: &[u8], to_a: &[u8]) {
    let (mut got_a, mut got_b) = (Vec::new(), Vec::new());
    let t = tuning();
    let (ra, rb) = tokio::join!(
        stream::run(w.clone(), a, to_b, &mut got_a, &t, None),
        stream::run(w.clone(), b, to_a, &mut got_b, &t, None),
    );
    ra.unwrap();
    rb.unwrap();
    assert_eq!(got_b, to_b);
    assert_eq!(got_a, to_a);
}

#[tokio::test]
async fn both_ways_and_again() {
    let w = Arc::new(World::default());
    w.state().max_plaintext = 64;
    let (mut a, mut b) = stream::new_link(&*w).await.unwrap();
    let (x, y) = (bytes(5000), bytes(300));
    session(&w, &mut a, &mut b, &x, &y).await;
    // Boxes of 63 bytes, the end marked on the last.
    assert_eq!(w.state().writes, 5000usize.div_ceil(63) + 300usize.div_ceil(63));
    assert_eq!(a.write_index, b.read_index);
    assert_eq!(b.write_index, a.read_index);
    // The link carries on from where the first session ended.
    session(&w, &mut a, &mut b, &y, b"").await;
    session(&w, &mut a, &mut b, b"", b"").await;
}

#[tokio::test]
async fn delivered_in_index_order() {
    let w = Arc::new(World::default());
    let (a, mut b) = stream::new_link(&*w).await.unwrap();
    let mut idx = vec![a.write_index.clone()];
    for _ in 0..9 {
        idx.push(next_index(idx.last().unwrap()).unwrap());
    }
    let w2 = w.clone();
    let cap = a.write_cap.clone();
    let writer = tokio::spawn(async move {
        // The boxes land last first.
        for (k, i) in idx.iter().enumerate().rev() {
            let data = format!("{k},");
            w2.write_box(&cap, i, &encode(data.as_bytes(), k == 9)).await.unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    let mut out = Vec::new();
    let mut t = tuning();
    t.window = 10;
    t.reads = 10;
    stream::run(w.clone(), &mut b, &b""[..], &mut out, &t, None).await.unwrap();
    writer.await.unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "0,1,2,3,4,5,6,7,8,9,");
}

#[tokio::test]
async fn end_of_stream_only() {
    let w = Arc::new(World::default());
    let (mut a, mut b) = stream::new_link(&*w).await.unwrap();
    session(&w, &mut a, &mut b, b"", b"").await;
    assert_eq!(w.plaintexts(), vec![vec![1u8], vec![1u8]]);
}

#[tokio::test]
async fn accept_waits_for_the_first_box() {
    let w = Arc::new(World::default());
    let (mut a, mut b) = stream::new_link(&*w).await.unwrap();
    let t = tuning();
    let w2 = w.clone();
    let client = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut out = Vec::new();
        stream::run(w2, &mut a, &b"ping"[..], &mut out, &tuning(), None).await.unwrap();
        out
    });
    let first = stream::accept(&*w, &b, &t).await.unwrap();
    let mut out = Vec::new();
    stream::run(w.clone(), &mut b, &b"pong"[..], &mut out, &t, Some(first)).await.unwrap();
    assert_eq!(out, b"ping");
    assert_eq!(client.await.unwrap(), b"pong");
}
