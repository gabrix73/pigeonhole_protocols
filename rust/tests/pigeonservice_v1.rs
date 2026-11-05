//! v1 end to end on the in-memory network, next to v0: version mismatches, registering with a key and a
//! signature, a client finding and reaching the service, and what the plugins refuse.

use std::sync::Arc;
use std::time::Duration;

use pigeonhole_protocols::pigeonservice::lease::{lease_expiry, next_seq, now};
use pigeonhole_protocols::pigeonservice::nike::{self, Keypair};
use pigeonhole_protocols::pigeonservice::v1::testkit::{POLL, world};
use pigeonhole_protocols::pigeonservice::v1::wire::*;
use pigeonhole_protocols::pigeonservice::v1::{self, Directory, Identity, link};
use pigeonhole_protocols::pigeonservice::version::{self, Kind, V0, V1};
use pigeonhole_protocols::pigeonservice::{Error, MAX_ENTRY_TTL, MAX_LINK_TTL, induct};
use pigeonhole_protocols::transport::Backend;
use pigeonhole_protocols::transport::sim::World;

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), f).await.expect("timed out")
}

#[tokio::test]
async fn a_client_speaks_one_version() {
    let net = world();
    let v1 = version::nodes(&net, Kind::VoucherRouter, V1).await.unwrap();
    assert_eq!(v1.len(), 2);
    assert!(v1.iter().all(|n| n.endpoint == b"voucher_router/v1"));
    let v0 = version::nodes(&net, Kind::VoucherRouter, V0).await.unwrap();
    assert!(v0.iter().all(|n| n.endpoint == b"voucher_router"));

    // A v1 client on a network of v0 plugins only.
    let v0_net = pigeonhole_protocols::pigeonservice::testkit::world();
    let e = version::nodes(&v0_net, Kind::VoucherRouter, V1).await.unwrap_err();
    assert_eq!(
        e.to_string(),
        "pigeonservice: version mismatch with voucher_router/v1: the client speaks v1, the service supports v0; upgrade the client or app, or use a service that offers v1"
    );
    // A v0 client on a network of v1 directories only.
    let v1_net = World::default();
    v1_net.add_service("discovery/v1", [1; 32], "discovery/v1", Default::default(), Arc::new(|_| Box::pin(async { vec![] })));
    let e = version::nodes(&v1_net, Kind::Discovery, V0).await.unwrap_err();
    assert_eq!(
        e.to_string(),
        "pigeonservice: version mismatch with discovery/v0: the client speaks v0, the service supports v1; upgrade the client or app, or use a service that offers v0"
    );
    // A plugin of a version this crate does not know is named in the error.
    let future = World::default();
    future.add_service("voucher_router/v2", [1; 32], "voucher_router/v2", Default::default(), Arc::new(|_| Box::pin(async { vec![] })));
    match version::nodes(&future, Kind::VoucherRouter, V1).await {
        Err(Error::VersionMismatch { requested, supported, .. }) => assert_eq!((requested, supported), (1, vec![2])),
        other => panic!("{other:?}"),
    }
}

/// A v1 request to a v0 plugin, and a v0 request to a v1 one, fail plainly.
#[tokio::test]
async fn versions_are_refused_across() {
    let net = world();
    let v0_router = net.services("voucher_router").await.unwrap().remove(0);
    let req = Request::Lookup(ServiceId([0; 32])).encode();
    let raw = net.request(&v0_router.node_id_hash, &v0_router.endpoint, &req).await.unwrap();
    assert!(matches!(Reply::decode(&raw), Err(Error::VersionMismatch { requested: 1, supported, .. }) if supported == [0]));

    let v1_router = link::routers(&net).await.unwrap().remove(0);
    let v0_req = pigeonhole_protocols::pigeonservice::wire::RouterRequest::Route(pigeonhole_protocols::pigeonservice::wire::RouteRequest {
        service_id: ServiceId([0; 32]),
        ciphertext: vec![1],
    })
    .encode();
    let raw = net.request(&v1_router.node_id_hash, &v1_router.endpoint, &v0_req).await.unwrap();
    // A v0 client reads the status, UnsupportedVersion, which v0 has no name for.
    assert_eq!(pigeonhole_protocols::pigeonservice::wire::decode_status(&raw).unwrap(), Status::UnsupportedVersion as u8);
    // The reply names the versions the plugin serves.
    assert!(matches!(Reply::decode(&raw), Err(Error::VersionMismatch { supported, .. }) if supported == [V1]));
    // Through the client API the error names the service type.
    let v0_ep = v0_router.endpoint.clone();
    let e = link::request(&net, &v0_router.node_id_hash, &v0_ep, &Request::Lookup(ServiceId([0; 32]))).await.unwrap_err();
    assert_eq!(
        e.to_string(),
        "pigeonservice: version mismatch with voucher_router: the client speaks v1, the service supports v0; upgrade the client or app, or use a service that offers v1"
    );
}

struct V1Service {
    id: Identity,
    key: Keypair,
}

/// Registers with every v1 router and advertises in the v1 directory, then echoes each client
/// that routes a voucher to it.
async fn start(net: &World) -> V1Service {
    let ph = Arc::new(net.clone());
    let svc = V1Service { id: Identity::generate(), key: Keypair::generate(net).await.unwrap() };
    let mut routers = vec![];
    for node in link::routers(net).await.unwrap() {
        let pending = within(v1::register(net, &svc.id, &node, lease_expiry(MAX_LINK_TTL))).await.unwrap();
        let link = within(pending.wait(ph.clone(), POLL)).await.unwrap();
        routers.push(RouterRef { node_id_hash: node.node_id_hash, endpoint: String::from_utf8(node.endpoint.clone()).unwrap() });
        let (ph, key) = (ph.clone(), svc.key.clone());
        tokio::spawn(async move {
            while let Ok(msg) = link.recv().await {
                let voucher = link::open_forward(&*ph, &key, &msg).await.unwrap();
                let conn = induct(ph.clone(), &voucher, "echo", POLL).await.unwrap();
                tokio::spawn(async move {
                    while let Ok(m) = conn.recv().await {
                        conn.send(&[b"echo: ", &m[..]].concat()).await.unwrap();
                    }
                });
            }
        });
    }
    let d = Descriptor { nike_scheme: nike::SCHEME.into(), nike_public_key: svc.key.public.to_bytes(), routers };
    for dir in Directory::all(ph, POLL).await.unwrap() {
        let expiry = lease_expiry(MAX_ENTRY_TTL);
        assert_eq!(within(dir.advertise(&svc.id, &d, expiry)).await.unwrap(), expiry);
    }
    svc
}

#[tokio::test(flavor = "multi_thread")]
async fn register_advertise_and_dial() {
    let net = world();
    let svc = start(&net).await;
    let ph = Arc::new(net.clone());
    let sid = ServiceId::from_public_key(&svc.id.public_key());
    let dir = Directory::all(ph.clone(), POLL).await.unwrap().remove(0);
    let record = within(dir.lookup(sid)).await.unwrap();
    assert_eq!(record.descriptor.as_ref().unwrap().routers.len(), 2);
    let listed = within(dir.list()).await.unwrap();
    assert_eq!(listed, vec![record.clone()]);

    let conn = within(v1::dial(ph.clone(), &record, "alice", POLL)).await.unwrap();
    conn.send(b"hi").await.unwrap();
    assert_eq!(within(conn.recv()).await.unwrap(), b"echo: hi");

    // A record whose routers someone changed no longer checks.
    let mut steered = record.clone();
    steered.descriptor.as_mut().unwrap().routers.truncate(1);
    assert!(matches!(dir.check(&steered), Err(Error::BadSignature)));

    // Withdrawn, the service is gone, and the old advertisement cannot bring it back.
    within(dir.withdraw(&svc.id)).await.unwrap();
    assert!(matches!(within(dir.lookup(sid)).await, Err(Error::Status(s)) if s == Status::UnknownService as u8));
    let node = net.services("discovery/v1").await.unwrap().remove(0);
    let replay = Request::Signed(record.clone()).encode();
    let raw = net.request(&node.node_id_hash, &node.endpoint, &replay).await.unwrap();
    assert_eq!(Reply::decode(&raw).unwrap().status, Status::Stale as u8);

    let routers = link::routers(&net).await.unwrap();
    within(v1::renew(&net, &svc.id, &routers[0], lease_expiry(MAX_LINK_TTL))).await.unwrap();
    for node in &routers {
        within(v1::unregister(&net, &svc.id, node)).await.unwrap();
    }
    let unlinked = within(v1::route(&net, &record, &[0; 32])).await;
    assert!(matches!(unlinked, Err(Error::Status(s)) if s == Status::UnknownService as u8), "{unlinked:?}");
}

/// What the router refuses, over the network.
#[tokio::test(flavor = "multi_thread")]
async fn router_refuses_forged_replayed_and_misaddressed() {
    let net = world();
    let id = Identity::generate();
    let routers = link::routers(&net).await.unwrap();
    let (a, b) = (&routers[0], &routers[1]);
    let send = |node: &pigeonhole_protocols::transport::ServiceNode, s: &Signed| {
        let (net, node, raw) = (net.clone(), node.clone(), Request::Signed(s.clone()).encode());
        async move { Reply::decode(&net.request(&node.node_id_hash, &node.endpoint, &raw).await.unwrap()).unwrap().status }
    };
    let pending = v1::register(&net, &id, a, lease_expiry(MAX_LINK_TTL)).await.unwrap();
    within(pending.wait(Arc::new(net.clone()), POLL)).await.unwrap();

    let renew = Signed::new(&id, Ctx::Renew, registrar_id(&a.node_id_hash, &a.endpoint), now(), next_seq(), lease_expiry(MAX_LINK_TTL), vec![], None).unwrap();
    assert_eq!(send(a, &renew).await, Status::Ok as u8);
    assert_eq!(send(a, &renew).await, Status::Ok as u8, "a retransmission");
    let newer = Signed::new(&id, Ctx::Renew, renew.registrar, now(), next_seq(), lease_expiry(MAX_LINK_TTL), vec![], None).unwrap();
    assert_eq!(send(a, &newer).await, Status::Ok as u8);
    assert_eq!(send(a, &renew).await, Status::Stale as u8, "a replay");
    assert_eq!(send(b, &newer).await, Status::WrongRegistrar as u8, "signed for another router");
    let mut forged = Signed::new(&id, Ctx::Renew, newer.registrar, now(), next_seq(), lease_expiry(MAX_LINK_TTL), vec![], None).unwrap();
    forged.expiry += 1;
    assert_eq!(send(a, &forged).await, Status::BadSignature as u8);
    let impostor = Signed::new(&Identity::generate(), Ctx::Unregister, newer.registrar, now(), next_seq(), 0, vec![], None).unwrap();
    let as_service = Signed { public_key: id.public_key(), ..impostor };
    assert_eq!(send(a, &as_service).await, Status::BadSignature as u8, "another key cannot unregister the service");
}

/// A mixnet whose packets are smaller than v1 needs is refused before anything is sent.
#[tokio::test]
async fn oversize_is_refused_before_sending() {
    let net = world();
    net.0.lock().unwrap().max_request = 1200;
    let node = link::routers(&net).await.unwrap().remove(0);
    let before = net.0.lock().unwrap().writes;
    match v1::register(&net, &Identity::generate(), &node, lease_expiry(MAX_LINK_TTL)).await {
        Err(Error::Oversize(e)) => {
            println!("{e}");
            assert!(e.contains("Advertise") && e.contains("is 1200 B"), "{e}");
        }
        Ok(_) => panic!("registered"),
        Err(e) => panic!("{e}"),
    }
    assert_eq!(net.0.lock().unwrap().writes, before, "no voucher was minted");
    // A request too long for the packet, though within its type's bound, is refused too.
    net.0.lock().unwrap().max_request = 300;
    let dir = Directory::all(Arc::new(net.clone()), POLL).await.unwrap().remove(0);
    assert!(matches!(dir.withdraw(&Identity::generate()).await, Err(Error::Oversize(_))));
}
