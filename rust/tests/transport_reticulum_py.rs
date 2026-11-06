//! The Reticulum transport through the embedded Python: `MeshBackend` over a stand-in for the box
//! client, kept in the interpreter, so every call crosses the FFI as it would on a mesh. Needs
//! `pigeonhole_protocols`, `pigeonhole_rns` and `hpqc` importable (see `reticulum_py`).

use std::time::{Duration, Instant};

use pigeonhole_protocols::protocols::katzenqt1::client::{Client, Config};
use pigeonhole_protocols::transport::reticulum_py::{ReticulumPyBackend, init_python};
use pigeonhole_protocols::transport::{Backend, Error, Read, voucher_version};
use pyo3::prelude::*;

const FAKE: &std::ffi::CStr = cr#"
from pigeonhole_rns import wire as rw
from pigeonhole_protocols.transport.reticulum import MeshBackend

class FakeBoxes:
    """Stores boxes by Box ID as a replica would, verifying nothing; the transport verifies."""

    def __init__(self, size):
        self.box_plaintext_size = size
        self.boxes = {}
        self.answer = True
        self.closed = False

    def write_box(self, box_id, signature, ciphertext):
        if not self.answer:
            return None
        if box_id in self.boxes:
            return rw.SUCCESS if self.boxes[box_id] == (signature, ciphertext) else rw.ALREADY_EXISTS
        self.boxes[box_id] = (signature, ciphertext)
        return rw.SUCCESS

    def read_box(self, box_id):
        if not self.answer:
            return None
        if box_id not in self.boxes:
            return rw.Reply(rw.NOT_FOUND)
        sig, ct = self.boxes[box_id]
        if not ct:
            return rw.Reply(rw.TOMBSTONE)
        return rw.Reply(rw.SUCCESS, sig, ct)

    def close(self):
        self.closed = True

    def entry(self):
        return None

    def wait_for_replica(self, timeout):
        return self.answer
"#;

/// A fresh store of `size` byte boxes.
fn fake(size: usize) -> Py<PyAny> {
    init_python().unwrap();
    Python::attach(|py| {
        PyModule::from_code(py, FAKE, c"fake.py", c"fake")
            .unwrap()
            .getattr("FakeBoxes")
            .unwrap()
            .call1((size,))
            .unwrap()
            .unbind()
    })
}

/// A transport over the store `boxes`.
fn mesh(boxes: &Py<PyAny>) -> ReticulumPyBackend {
    Python::attach(|py| {
        let m = py
            .import("pigeonhole_protocols.transport.reticulum")
            .unwrap()
            .getattr("MeshBackend")
            .unwrap()
            .call1((boxes.clone_ref(py),))
            .unwrap();
        ReticulumPyBackend::from_object(m.unbind())
    })
}

fn set(boxes: &Py<PyAny>, attr: &str, v: bool) {
    Python::attach(|py| boxes.bind(py).setattr(attr, v).unwrap());
}

fn get(boxes: &Py<PyAny>, attr: &str) -> bool {
    Python::attach(|py| boxes.bind(py).getattr(attr).unwrap().extract().unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn boxes() {
    let boxes = fake(200);
    let be = mesh(&boxes);
    let kp = be.new_keypair().await.unwrap();
    assert_eq!((kp.write_cap.len(), kp.read_cap.len(), kp.first.len()), (168, 136, 104));
    assert_eq!(be.max_plaintext().await, Ok(256), "boxes are written at the mesh size");
    let e = be.replica_epoch().await.unwrap();
    assert!(400 < e && e < 10000, "weeks since the Katzenpost epoch: {e}");
    assert_eq!(be.read_box(&kp.read_cap, &kp.first).await, Ok(Read::NotFound));
    be.write_box(&kp.write_cap, &kp.first, b"hello").await.unwrap();
    assert_eq!(be.read_box(&kp.read_cap, &kp.first).await, Ok(Read::Data(b"hello".to_vec())));
    be.write_box(&kp.write_cap, &kp.first, b"hello").await.unwrap();
    assert_eq!(be.write_box(&kp.write_cap, &kp.first, b"other").await, Err(Error::BoxAlreadyExists));
    let next = pigeonhole_protocols::protocols::katzenqt1::member::next_index(&kp.first).unwrap();
    be.write_box(&kp.write_cap, &next, b"").await.unwrap();
    assert_eq!(be.read_box(&kp.read_cap, &next).await, Ok(Read::Tombstone));
    // A box too large for every allowed size is a ValueError: not a transport error, but named.
    match be.write_box(&kp.write_cap, &kp.first, &[0; 1550]).await {
        Err(Error::Other(m)) => assert!(m.contains("ValueError") && m.contains("exceeds every allowed size"), "{m}"),
        r => panic!("{r:?}"),
    }
    set(&boxes, "answer", false);
    assert_eq!(
        be.write_box(&kp.write_cap, &kp.first, b"x").await,
        Err(Error::Other("no replica answered".into()))
    );
    assert_eq!(
        be.read_box(&kp.read_cap, &kp.first).await,
        Err(Error::Other("no replica answered".into()))
    );
    set(&boxes, "answer", true);
    assert_eq!(be.entry().await, Ok("no replica reachable".into()));
    be.close().await.unwrap();
    assert!(get(&boxes, "closed"));
}

#[tokio::test(flavor = "multi_thread")]
async fn vouchers() {
    let be = mesh(&fake(1530));
    let kp = be.new_keypair().await.unwrap();
    let who = be.new_keypair().await.unwrap();
    for form in [1, 2] {
        let m = be.voucher_mint(&kp.write_cap, "bob", form).await.unwrap();
        assert_eq!((m.version, voucher_version(&m.payload)), (form, form));
        assert_eq!(be.voucher_derive_stream(&m.voucher).await.unwrap(), (m.write_cap.clone(), m.read_cap.clone()));
        let i = be.voucher_induct(&m.voucher, &m.payload, &who.read_cap).await.unwrap();
        assert_eq!((i.name.as_str(), i.version), ("bob", form));
        let o = be.voucher_open(&m.secret_key, &i.sealed_reply, &kp.write_cap).await.unwrap();
        assert_eq!(&o.who_reply[..], &who.read_cap[..]);
    }
    match be.voucher_derive_stream(b"short").await {
        Err(Error::Other(m)) => assert!(m.starts_with("python: "), "{m}"),
        r => panic!("{r:?}"),
    }
}

async fn wait_for<F: std::future::Future<Output = bool>>(what: &str, mut ok: impl FnMut() -> F) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while !ok().await {
        assert!(Instant::now() < deadline, "waited two minutes for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn has(c: &Client, id: &str, text: &str) -> bool {
    c.lines(id, None).await.unwrap().iter().any(|l| l.line.notice.is_none() && l.line.text == text)
}

async fn open(be: ReticulumPyBackend, dir: &std::path::Path, name: &str) -> Client {
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

/// Two clients, each with its own `MeshBackend` over one store: alice makes a group, bob joins
/// it through a voucher, and each reads what the other sends.
#[tokio::test(flavor = "multi_thread")]
async fn join_and_chat() {
    let boxes = fake(1530);
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| std::env::temp_dir().display().to_string());
    let (ad, bd) = (tempfile::TempDir::new_in(&tmp).unwrap(), tempfile::TempDir::new_in(&tmp).unwrap());
    let alice = open(mesh(&boxes), ad.path(), "alice").await;
    let bob = open(mesh(&boxes), bd.path(), "bob").await;
    let g = alice.create("g").await.unwrap();
    let bg = bob.join("g").await.unwrap();
    wait_for("a voucher code", || async { !bob.chat(&bg).await.unwrap().code.is_empty() }).await;
    let code = bob.chat(&bg).await.unwrap().code;
    wait_for("alice's group", || async { alice.chat(&g).await.unwrap().joined }).await;
    alice.invite(&g, &code).await.unwrap();
    wait_for("bob to join", || async { bob.chat(&bg).await.unwrap().joined }).await;
    bob.send(&bg, "hi alice").await.unwrap();
    alice.send(&g, "hi bob").await.unwrap();
    wait_for("each to read the other", || async {
        has(&alice, &g, "hi alice").await && has(&bob, &bg, "hi bob").await
    })
    .await;
    alice.close().await;
    bob.close().await;
}
