//! Two clients over the in-memory Pigeonhole, in real time, with their state synced to disk.

#![cfg(feature = "std")]

use std::time::{Duration, Instant};

use pigeonhole_protocols::protocols::katzenqt1::client::{Client, ClientError, Config, RETRY_MS};
use pigeonhole_protocols::protocols::katzenqt1::wire::{
    MAP_VERSION, ReplyWho, box_of, message_from_cbor,
};
use pigeonhole_protocols::transport::sim::World;
use pigeonhole_protocols::transport::{self as transport, Backend, Read};

fn tmp() -> tempfile::TempDir {
    tempfile::TempDir::new_in(
        std::env::var("TMPDIR")
            .unwrap_or_else(|_| format!("{}/scratch/tmp", std::env::var("HOME").unwrap())),
    )
    .unwrap()
}

async fn open(w: &World, dir: &std::path::Path, name: &str) -> Client {
    open_v(w, dir, name, 4).await
}

async fn open_v(w: &World, dir: &std::path::Path, name: &str, wire_version: u64) -> Client {
    Client::open(
        Config {
            state_dir: dir.into(),
            name: name.into(),
            epoch_poll: Duration::from_secs(1),
            no_sync: false,
            key: None,
            wire_version,
        },
        w.clone(),
    )
    .await
    .unwrap()
}

async fn wait_for<F: std::future::Future<Output = bool>>(what: &str, mut ok: impl FnMut() -> F) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !ok().await {
        assert!(Instant::now() < deadline, "waited a minute for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn has(c: &Client, id: &str, text: &str) -> bool {
    c.lines(id, None)
        .await
        .unwrap()
        .iter()
        .any(|l| l.line.notice.is_none() && l.line.text == text)
}

/// Leave a group while reading for a voucher never published: the client reads for it no more.
#[tokio::test(flavor = "multi_thread")]
async fn leave_stops_reading() {
    let w = World::default();
    let dir = tmp();
    let alice = open(&w, dir.path(), "alice").await;
    let g = alice.create("g").await.unwrap();
    wait_for("alice's group", || {
        let (alice, g) = (&alice, &g);
        async move { alice.chat(g).await.unwrap().joined }
    })
    .await;
    alice
        .invite(&g, &pigeonhole_protocols::protocols::katzenqt1::engine::voucher_code(&[0; 32]))
        .await
        .unwrap();
    let before = w.state().reads;
    wait_for("the voucher to be read for again", || {
        let w = &w;
        async move { w.state().reads > before + 1 }
    })
    .await;
    alice.leave(&g).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let left = w.state().reads;
    tokio::time::sleep(Duration::from_millis(2 * RETRY_MS)).await;
    assert_eq!(w.state().reads, left, "reads after leaving");
    alice.close().await;
}

/// A voucher of the wrong size fails at once rather than being read for forever.
#[tokio::test(flavor = "multi_thread")]
async fn withdrawn_voucher_fails() {
    let w = World::default();
    let dir = tmp();
    let alice = open(&w, dir.path(), "alice").await;
    let g = alice.create("g").await.unwrap();
    wait_for("alice's group", || async { alice.chat(&g).await.unwrap().joined }).await;
    let voucher = [9; 32];
    let (wc, rc) = w.voucher_derive_stream(&voucher).await.unwrap();
    w.write_box(&wc, pigeonhole_protocols::protocols::katzenqt1::wire::start_of(&rc), b"").await.unwrap();
    let code = pigeonhole_protocols::protocols::katzenqt1::engine::voucher_code(&voucher);
    alice.invite(&g, &code).await.unwrap();
    wait_for("the failure", || async {
        alice.lines(&g, None).await.unwrap().iter().any(|l| l.line.notice.as_ref().is_some_and(|n| n.args == ["that voucher was withdrawn"]))
    })
    .await;
    alice.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn short_voucher_is_not_a_voucher() {
    let w = World::default();
    let dir = tmp();
    let alice = open(&w, dir.path(), "alice").await;
    let g = alice.create("g").await.unwrap();
    wait_for("alice's group", || async { alice.chat(&g).await.unwrap().joined }).await;
    let code = pigeonhole_protocols::protocols::katzenqt1::engine::voucher_code(&[0; 3]);
    assert_eq!(alice.invite(&g, &code).await, Err(ClientError::NotAVoucher));
    alice.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn client() {
    let w = World::default();
    let (alice_dir, bob_dir) = (tmp(), tmp());
    let alice = open(&w, alice_dir.path(), "alice").await;
    let bob = open(&w, bob_dir.path(), "bob").await;
    let mut events = alice.subscribe();
    let g = alice.create("g").await.unwrap();
    assert_eq!(alice.create("g").await, Err(ClientError::NameTaken));
    assert_eq!(alice.send("nope", "x").await, Err(ClientError::NoSuchChat));
    let bg = bob.join("g").await.unwrap();
    let mut code = String::new();
    wait_for("a voucher code", || {
        let (bob, bg) = (&bob, &bg);
        async move { !bob.chat(bg).await.unwrap().code.is_empty() }
    })
    .await;
    code.push_str(&bob.chat(&bg).await.unwrap().code);
    wait_for("alice's group", || async {
        alice.chat(&g).await.unwrap().joined
    })
    .await;
    assert_eq!(
        alice.invite(&g, "abc!").await,
        Err(ClientError::NotAVoucher)
    );
    alice.invite(&g, &code).await.unwrap();
    wait_for("bob to join", || async {
        bob.chat(&bg).await.unwrap().joined
    })
    .await;
    bob.send(&bg, "hi alice").await.unwrap();
    alice.send(&g, "hi bob").await.unwrap();
    wait_for("each to read the other", || async {
        has(&alice, &g, "hi alice").await && has(&bob, &bg, "hi bob").await
    })
    .await;
    assert_eq!(events.try_recv().unwrap().chat, g);
    let bob_key = alice.member_named(&g, "bob").await.unwrap();
    assert!(!bob_key.is_empty());
    let me = alice.chat(&g).await.unwrap().me;
    assert_eq!(alice.remove(&g, me).await, Err(ClientError::RemoveSelf));
    assert_eq!(
        alice.remove(&g, b"nobody".to_vec()).await,
        Err(ClientError::NoSuchMember)
    );
    // Alice closes, and opens again where she was.
    alice.close().await;
    assert_eq!(alice.send(&g, "closed").await, Err(ClientError::Closed));
    let alice = open(&w, alice_dir.path(), "alice").await;
    assert!(
        has(&alice, &g, "hi alice").await,
        "alice forgets what she read"
    );
    alice.send(&g, "back again").await.unwrap();
    bob.send(&bg, "read you").await.unwrap();
    wait_for("the conversation to carry on", || async {
        has(&bob, &bg, "back again").await && has(&alice, &g, "read you").await
    })
    .await;
    wait_for("bob to acknowledge", || async {
        alice
            .lines(&g, None)
            .await
            .unwrap()
            .iter()
            .any(|l| l.line.text == "hi bob" && l.mine && l.acked)
    })
    .await;
    assert!(w.state().refused.is_empty());
    alice.close().await;
    bob.close().await;
}

/// A Pigeonhole whose next `failing` reads fail, as reads over the mixnet sometimes do, and
/// whose vouchers are of version 1, the map form, when `v1` is set.
#[derive(Clone)]
struct Flaky {
    world: World,
    failing: std::sync::Arc<std::sync::atomic::AtomicIsize>,
    v1: bool,
}

impl Flaky {
    fn fail_next_reads(&self, n: isize) {
        self.failing.store(n, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Backend for Flaky {
    async fn new_keypair(&self) -> transport::Result<transport::Keypair> {
        self.world.new_keypair().await
    }
    async fn write_box(&self, w: &[u8], i: &[u8], p: &[u8]) -> transport::Result<()> {
        self.world.write_box(w, i, p).await
    }
    async fn read_box(&self, r: &[u8], i: &[u8]) -> transport::Result<Read> {
        if self
            .failing
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst)
            > 0
        {
            return Err(transport::Error::Other("read timed out".into()));
        }
        self.world.read_box(r, i).await
    }
    async fn replica_epoch(&self) -> transport::Result<u64> {
        self.world.replica_epoch().await
    }
    async fn max_plaintext(&self) -> transport::Result<usize> {
        self.world.max_plaintext().await
    }
    async fn voucher_mint(
        &self,
        w: &[u8],
        n: &str,
        f: u8,
    ) -> transport::Result<transport::Minted> {
        let mut m = self.world.voucher_mint(w, n, f).await?;
        if self.v1 {
            m.version = 1;
        }
        Ok(m)
    }
    async fn voucher_derive_stream(
        &self,
        v: &[u8],
    ) -> transport::Result<(transport::Secret, transport::Secret)> {
        self.world.voucher_derive_stream(v).await
    }
    async fn voucher_induct(
        &self,
        v: &[u8],
        p: &[u8],
        r: &[u8],
    ) -> transport::Result<transport::Inducted> {
        let mut i = self.world.voucher_induct(v, p, r).await?;
        if self.v1 {
            i.version = 1;
        }
        Ok(i)
    }
    async fn voucher_open(
        &self,
        s: &[u8],
        r: &[u8],
        w: &[u8],
    ) -> transport::Result<transport::Opened> {
        self.world.voucher_open(s, r, w).await
    }
}

/// A joiner whose reads of the voucher's reply fail for a while still joins once they succeed;
/// so does an introducer whose reads of the voucher fail.
#[tokio::test(flavor = "multi_thread")]
async fn voucher_reads_that_fail_are_retried() {
    let w = World::default();
    let (alice_dir, bob_dir) = (tmp(), tmp());
    let alice_net = Flaky {
        world: w.clone(),
        failing: Default::default(),
        v1: false,
    };
    let bob_net = Flaky {
        world: w.clone(),
        failing: Default::default(),
        v1: false,
    };
    let cfg = |dir: &std::path::Path, name: &str| Config {
        state_dir: dir.into(),
        name: name.into(),
        epoch_poll: Duration::from_secs(1),
        no_sync: false,
        key: None,
        wire_version: 4,
    };
    let alice = Client::open(cfg(alice_dir.path(), "alice"), alice_net.clone())
        .await
        .unwrap();
    let bob = Client::open(cfg(bob_dir.path(), "bob"), bob_net.clone())
        .await
        .unwrap();
    let g = alice.create("g").await.unwrap();
    let bg = bob.join("g").await.unwrap();
    wait_for("a voucher code and alice's group", || async {
        !bob.chat(&bg).await.unwrap().code.is_empty() && alice.chat(&g).await.unwrap().joined
    })
    .await;
    let code = bob.chat(&bg).await.unwrap().code;
    bob_net.fail_next_reads(3);
    alice_net.fail_next_reads(3);
    alice.invite(&g, &code).await.unwrap();
    wait_for("bob to join", || async {
        bob.chat(&bg).await.unwrap().joined
    })
    .await;
    alice.close().await;
    bob.close().await;
}

/// A reply larger than a box is framed over boxes 1 on, in C pieces then an F piece, and the
/// joiners still join.
#[tokio::test(flavor = "multi_thread")]
async fn reply_spans_boxes() {
    let w = World::default();
    w.state().max_plaintext = 200;
    let dirs = [tmp(), tmp(), tmp()];
    let alice = open(&w, dirs[0].path(), "alice").await;
    let g = alice.create("g").await.unwrap();
    wait_for("alice's group", || async { alice.chat(&g).await.unwrap().joined }).await;
    let mut others = Vec::new();
    for (i, name) in ["bob", "carol"].into_iter().enumerate() {
        let c = open(&w, dirs[i + 1].path(), name).await;
        let cg = c.join("g").await.unwrap();
        wait_for("a voucher code", || async { !c.chat(&cg).await.unwrap().code.is_empty() }).await;
        let code = c.chat(&cg).await.unwrap().code;
        alice.invite(&g, &code).await.unwrap();
        wait_for("the joiner to join", || async { c.chat(&cg).await.unwrap().joined }).await;
        others.push(c);
    }
    assert!(
        w.plaintexts().iter().any(|p| p.first() == Some(&b'C')),
        "no reply was split into C pieces"
    );
    alice.close().await;
    for c in others {
        c.close().await;
    }
}

/// A voucher of version 1 is answered unframed in box 1 alone, and the joiner reads it there.
#[tokio::test(flavor = "multi_thread")]
async fn version_1_reply_is_unframed() {
    assert_eq!(transport::voucher_version(&[0xa3, 1]), 1);
    assert_eq!(transport::voucher_version(&[0x83, 1]), 2);
    assert_eq!(transport::voucher_version(&[]), 2);
    let w = World::default();
    let (alice_dir, bob_dir) = (tmp(), tmp());
    let net = Flaky {
        world: w.clone(),
        failing: Default::default(),
        v1: true,
    };
    let cfg = |dir: &std::path::Path, name: &str| Config {
        state_dir: dir.into(),
        name: name.into(),
        epoch_poll: Duration::from_secs(1),
        no_sync: false,
        key: None,
        wire_version: 4,
    };
    let alice = Client::open(cfg(alice_dir.path(), "alice"), net.clone()).await.unwrap();
    let bob = Client::open(cfg(bob_dir.path(), "bob"), net.clone()).await.unwrap();
    let g = alice.create("g").await.unwrap();
    let bg = bob.join("g").await.unwrap();
    wait_for("a voucher code and alice's group", || async {
        !bob.chat(&bg).await.unwrap().code.is_empty() && alice.chat(&g).await.unwrap().joined
    })
    .await;
    let code = bob.chat(&bg).await.unwrap().code;
    alice.invite(&g, &code).await.unwrap();
    wait_for("bob to join", || async { bob.chat(&bg).await.unwrap().joined }).await;
    // The sim's sealed reply is the ReplyWho itself: unframed, it is a box's whole plaintext.
    let boxes = w.plaintexts();
    assert!(boxes.iter().any(|p| ReplyWho::from_bytes(p).is_some()), "no unframed reply");
    let framed = |p: &Vec<u8>| {
        matches!(p.first(), Some(b'C') | Some(b'F')) && ReplyWho::from_bytes(&p[1..]).is_some()
    };
    assert!(!boxes.iter().any(framed), "a framed reply");
    alice.close().await;
    bob.close().await;
}

/// A client with a sealed state carries on as one without, and what it keeps opens only with its
/// key.
#[tokio::test(flavor = "multi_thread")]
async fn sealed_state() {
    let w = World::default();
    let (alice_dir, bob_dir) = (tmp(), tmp());
    let sealed = |key: Option<u8>| Config {
        state_dir: alice_dir.path().into(),
        name: "alice".into(),
        epoch_poll: Duration::from_secs(1),
        no_sync: false,
        key: key.map(|k| transport::Secret::new(&[k; 32])),
        wire_version: 4,
    };
    let alice = Client::open(sealed(Some(1)), w.clone()).await.unwrap();
    let bob = open(&w, bob_dir.path(), "bob").await;
    let g = alice.create("g").await.unwrap();
    let bg = bob.join("g").await.unwrap();
    wait_for("a voucher code and alice's group", || async {
        !bob.chat(&bg).await.unwrap().code.is_empty() && alice.chat(&g).await.unwrap().joined
    })
    .await;
    let code = bob.chat(&bg).await.unwrap().code;
    alice.invite(&g, &code).await.unwrap();
    wait_for("bob to join", || async {
        bob.chat(&bg).await.unwrap().joined
    })
    .await;
    let bytes = b"a picture, as it were".to_vec();
    bob.send_file(&bg, "pic.bin", bytes.clone()).await.unwrap();
    bob.send(&bg, "did you get it").await.unwrap();
    wait_for("alice to read both", || async {
        has(&alice, &g, "did you get it").await
            && alice
                .lines(&g, None)
                .await
                .unwrap()
                .iter()
                .any(|l| l.line.attachment.is_some())
    })
    .await;
    let lines = alice.lines(&g, None).await.unwrap();
    let a = lines
        .iter()
        .find_map(|l| l.line.attachment.clone())
        .unwrap();
    assert_eq!(*alice.read_file(&a).unwrap(), bytes);
    assert_ne!(std::fs::read(alice.file_path(&a)).unwrap(), bytes);
    alice.close().await;
    assert_eq!(
        Client::open(sealed(None), w.clone()).await.err(),
        Some(ClientError::Locked)
    );
    assert_eq!(
        Client::open(sealed(Some(2)), w.clone()).await.err(),
        Some(ClientError::Locked)
    );
    let alice = Client::open(sealed(Some(1)), w.clone()).await.unwrap();
    assert!(has(&alice, &g, "did you get it").await);
    alice.close().await;
    bob.close().await;
}

/// Alice on wire version `va` founds a group, bob on `vb` joins it, and each reads the other.
/// Returns every box written.
async fn join_and_chat(va: u64, vb: u64) -> Vec<Vec<u8>> {
    let w = World::default();
    let (alice_dir, bob_dir) = (tmp(), tmp());
    let alice = open_v(&w, alice_dir.path(), "alice", va).await;
    let bob = open_v(&w, bob_dir.path(), "bob", vb).await;
    let g = alice.create("g").await.unwrap();
    let bg = bob.join("g").await.unwrap();
    wait_for("a voucher code and alice's group", || async {
        !bob.chat(&bg).await.unwrap().code.is_empty() && alice.chat(&g).await.unwrap().joined
    })
    .await;
    let code = bob.chat(&bg).await.unwrap().code;
    alice.invite(&g, &code).await.unwrap();
    wait_for("bob to join", || async { bob.chat(&bg).await.unwrap().joined }).await;
    alice.send(&g, "hi bob").await.unwrap();
    bob.send(&bg, "hi alice").await.unwrap();
    wait_for("each to read the other", || async {
        has(&alice, &g, "hi alice").await && has(&bob, &bg, "hi bob").await
    })
    .await;
    alice.close().await;
    bob.close().await;
    w.plaintexts()
}

/// The CBOR of every box holding a group message.
fn group_boxes(boxes: &[Vec<u8>]) -> Vec<&[u8]> {
    boxes
        .iter()
        .filter(|p| p.first() == Some(&b'F') && message_from_cbor(&p[1..]).is_some())
        .map(|p| &p[1..])
        .collect()
}

/// Version 3 writes maps, as the version 3 vectors encode them, mints the map form and gets the
/// reply unframed; version 4 writes arrays, mints the array form and gets the reply framed.
#[tokio::test(flavor = "multi_thread")]
async fn wire_version_writes_and_mints_its_form() {
    for v in [3, 4] {
        let boxes = join_and_chat(v, v).await;
        let major = if v == MAP_VERSION { 5 } else { 4 };
        let sim_payload = |p: &Vec<u8>| p.starts_with(b"bob\0");
        let map_payload = boxes.iter().any(|p| p.first() == Some(&0xa0) && p[1..].starts_with(b"bob\0"));
        assert_eq!(map_payload, v == 3, "version {v}: the payload's form");
        assert_eq!(boxes.iter().any(sim_payload), v == 4, "version {v}: the payload's form");
        let gb = group_boxes(&boxes);
        assert!(gb.len() >= 4, "version {v}: {} group boxes", gb.len());
        for cbor in gb {
            assert_eq!(cbor[0] >> 5, major, "version {v}: a box in the other form");
            let m = message_from_cbor(cbor).unwrap();
            assert_eq!(box_of(&m, v).unwrap()[1..], *cbor, "version {v}: written otherwise");
        }
        let unframed = boxes.iter().any(|p| ReplyWho::from_bytes(p).is_some());
        let framed = boxes
            .iter()
            .any(|p| p.first() == Some(&b'F') && ReplyWho::from_bytes(&p[1..]).is_some());
        assert_eq!((unframed, framed), (v == 3, v == 4), "version {v}: the reply's framing");
    }
}

/// A member on version 3 and one on 4 join each other's groups and read each other.
#[tokio::test(flavor = "multi_thread")]
async fn mixed_wire_versions_join_and_chat() {
    for (va, vb) in [(3, 4), (4, 3)] {
        let boxes = join_and_chat(va, vb).await;
        let mut majors: Vec<u8> = group_boxes(&boxes).iter().map(|c| c[0] >> 5).collect();
        majors.sort();
        majors.dedup();
        assert_eq!(majors, [4, 5], "{va} with {vb}");
    }
}
