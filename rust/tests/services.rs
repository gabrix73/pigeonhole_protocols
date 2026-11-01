use std::sync::Arc;
use std::time::Duration;

use pigeonhole_protocols::services::testkit::*;
use pigeonhole_protocols::transport::sim::World;
use pigeonhole_protocols::services::{Config, Keypair, Service, dial, induct, mint};

async fn config(net: &World, dir: &std::path::Path) -> Config {
    let mut cfg = Config::new(Keypair::load_or_generate(net, dir, "service").await.unwrap(), dir);
    cfg.display_name = "echo".into();
    cfg.poll_interval = POLL;
    cfg
}

fn echo(net: &World, cfg: Config) -> Service<World> {
    let svc = Service::new(cfg, Arc::new(net.clone())).unwrap();
    let s = svc.clone();
    tokio::spawn(async move {
        s.run(|session| async move {
            while let Ok(msg) = session.recv().await {
                let mut reply = b"echo: ".to_vec();
                reply.extend_from_slice(&msg);
                if session.send(&reply).await.is_err() {
                    return;
                }
            }
        })
        .await
        .unwrap();
    });
    svc
}

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), f).await.expect("timed out")
}

#[tokio::test(flavor = "multi_thread")]
async fn handshake_opens_a_two_way_connection() {
    let net = Arc::new(World::default());
    let pending = mint(&*net, "client").await.unwrap();
    let restored = pigeonhole_protocols::services::Pending::decode(&pending.encode()).unwrap();
    assert_eq!(restored, pending);
    let n = net.clone();
    let v = pending.voucher.clone();
    let inductor = tokio::spawn(async move { induct(n, &v, "service", POLL).await.unwrap() });
    let joiner = within(restored.wait(net.clone(), POLL)).await.unwrap();
    let inductor = inductor.await.unwrap();

    joiner.send(b"hello service").await.unwrap();
    assert_eq!(within(inductor.recv()).await.unwrap(), b"hello service");
    inductor.send(b"hello client").await.unwrap();
    assert_eq!(within(joiner.recv()).await.unwrap(), b"hello client");
    for i in 1..=5u8 {
        joiner.send(&[i]).await.unwrap();
    }
    for i in 1..=5u8 {
        assert_eq!(within(inductor.recv()).await.unwrap(), [i], "messages arrive in order");
    }
    assert!(induct(net.clone(), &pending.voucher, "again", POLL).await.is_err(), "a voucher inducts once");
}

#[tokio::test(flavor = "multi_thread")]
async fn service_end_to_end() {
    let net = world();
    let dir = tempfile::tempdir().unwrap();
    let svc = echo(&net, config(&net, dir.path()).await);
    let d = lookup_linked(&net, svc.id(), 2).await;
    let conn = within(dial(Arc::new(net.clone()), &d, "alice", POLL)).await.unwrap();
    for m in ["hello", "again"] {
        conn.send(m.as_bytes()).await.unwrap();
        assert_eq!(within(conn.recv()).await.unwrap(), format!("echo: {m}").as_bytes());
    }
    svc.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn offered_voucher_opens_a_session() {
    let net = world();
    let dir = tempfile::tempdir().unwrap();
    let svc = echo(&net, config(&net, dir.path()).await);
    lookup_linked(&net, svc.id(), 2).await;
    let voucher = within(svc.offer()).await.unwrap();
    assert_eq!(svc.offers(), vec![voucher.clone()]);

    let conn = within(induct(Arc::new(net.clone()), &voucher, "bob", POLL)).await.unwrap();
    conn.send(b"hi").await.unwrap();
    assert_eq!(within(conn.recv()).await.unwrap(), b"echo: hi");
    assert!(svc.offers().is_empty(), "a used offer is forgotten");
    svc.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn service_resumes_after_restart() {
    let net = world();
    let dir = tempfile::tempdir().unwrap();
    let svc = echo(&net, config(&net, dir.path()).await);
    let d = lookup_linked(&net, svc.id(), 2).await;
    let conn = within(dial(Arc::new(net.clone()), &d, "alice", POLL)).await.unwrap();
    conn.send(b"one").await.unwrap();
    assert_eq!(within(conn.recv()).await.unwrap(), b"echo: one");
    let offered = within(svc.offer()).await.unwrap();
    svc.close().await;

    // The links, the session and the offer come back without registering
    // or dialling again.
    let writes = net.state().writes;
    let svc = echo(&net, config(&net, dir.path()).await);
    conn.send(b"two").await.unwrap();
    assert_eq!(within(conn.recv()).await.unwrap(), b"echo: two");
    let late = within(induct(Arc::new(net.clone()), &offered, "late", POLL)).await.unwrap();
    late.send(b"three").await.unwrap();
    assert_eq!(within(late.recv()).await.unwrap(), b"echo: three");
    assert!(net.state().writes > writes);
    assert_eq!(svc.descriptor().routers.len(), 2);
    svc.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dial_falls_back_to_another_router() {
    let net = world();
    let dir = tempfile::tempdir().unwrap();
    let svc = echo(&net, config(&net, dir.path()).await);
    let mut d = lookup_linked(&net, svc.id(), 2).await;
    // A router the service never linked with answers UnknownService.
    add_router(&net, [0xee; 32]);
    // One the PKI does not list, as a lying directory might name, is
    // skipped: this one would acknowledge the voucher and drop it.
    net.add_service("evil", [0xbb; 32], "evil", Default::default(), std::sync::Arc::new(|_| {
        Box::pin(async { pigeonhole_protocols::services::wire::encode_router_reply(pigeonhole_protocols::services::wire::Status::Ok) })
    }));
    use pigeonhole_protocols::services::wire::RouterRef;
    d.routers.insert(0, RouterRef { node_id_hash: [0xee; 32], endpoint: "voucher_router".into() });
    d.routers.insert(0, RouterRef { node_id_hash: [0xbb; 32], endpoint: "evil".into() });
    let conn = within(dial(Arc::new(net.clone()), &d, "carol", POLL)).await.unwrap();
    conn.send(b"x").await.unwrap();
    assert_eq!(within(conn.recv()).await.unwrap(), b"echo: x");
    svc.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bogus_voucher_does_not_hold_a_slot() {
    let net = world();
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&net, dir.path()).await;
    cfg.max_concurrent_sessions = 1;
    cfg.handshake_timeout = Duration::from_secs(2);
    let svc = echo(&net, cfg);
    let d = lookup_linked(&net, svc.id(), 2).await;
    // Nobody ever writes box 0 for this voucher.
    within(pigeonhole_protocols::services::route(&net, &d, &[0; 32])).await.unwrap();
    let conn = within(dial(Arc::new(net.clone()), &d, "alice", POLL)).await.unwrap();
    conn.send(b"hi").await.unwrap();
    assert_eq!(within(conn.recv()).await.unwrap(), b"echo: hi");
    svc.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn voucher_survives_restart() {
    let net = Arc::new(world());
    let dir = tempfile::tempdir().unwrap();
    let svc = Service::new(config(&net, dir.path()).await, net.clone()).unwrap();
    svc.listen().unwrap();
    let d = lookup_linked(&net, svc.id(), 2).await;
    let pending = mint(&*net, "alice").await.unwrap();
    within(pigeonhole_protocols::services::route(&*net, &d, &pending.voucher)).await.unwrap();
    // Read from the link but never handled.
    let _ = within(svc.accept()).await.unwrap();
    svc.close().await;

    let svc = echo(&net, config(&net, dir.path()).await);
    let conn = within(pending.wait(net.clone(), POLL)).await.unwrap();
    conn.send(b"hi").await.unwrap();
    assert_eq!(within(conn.recv()).await.unwrap(), b"echo: hi");
    svc.close().await;
}
