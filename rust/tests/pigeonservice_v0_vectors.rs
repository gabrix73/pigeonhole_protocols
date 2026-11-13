//! Checks the crate against vectors the Go implementation wrote; see
//! go/cmd/pigeonservice-vectors.

#![cfg(feature = "std")]

use pigeonhole_protocols::pigeonservice::auth;
use pigeonhole_protocols::pigeonservice::nike::{Keypair, PrivateKey, PublicKey};
use pigeonhole_protocols::pigeonservice::wire::*;

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/pigeonservice/v0/vectors.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn h(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

struct Fixture {
    v: serde_json::Value,
    service: Keypair,
    plugin: Keypair,
    descriptor: ServiceDescriptor,
    /// The service's and the plugin's shared secret, as Go derived it: the client daemon derives
    /// it here.
    ss: Vec<u8>,
}

fn fixture() -> Fixture {
    let v = vectors();
    let service_priv = PrivateKey::from_bytes(&h(&v["service_private_key"])).unwrap();
    let service = Keypair { public: PublicKey::from_bytes(&h(&v["service_public_key"])).unwrap(), private: service_priv };
    let plugin_priv = PrivateKey::from_bytes(&h(&v["plugin_private_key"])).unwrap();
    let plugin = Keypair { public: PublicKey::from_bytes(&h(&v["plugin_public_key"])).unwrap(), private: plugin_priv };
    let routers = v["routers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| RouterRef {
            node_id_hash: h(&r["node_id_hash"]).try_into().unwrap(),
            endpoint: r["endpoint"].as_str().unwrap().to_string(),
        })
        .collect();
    let descriptor = ServiceDescriptor {
        nike_scheme: v["nike_scheme"].as_str().unwrap().to_string(),
        public_key: service.public.to_bytes(),
        routers,
    };
    let ss = h(&v["shared_secret"]);
    Fixture { v, service, plugin, descriptor, ss }
}

#[test]
fn keys() {
    let f = fixture();
    assert_eq!(f.service.private.as_bytes(), h(&f.v["service_private_key"]), "Go's key sizes are ours");
    assert_eq!(ServiceId::from_public_key(&f.service.public.to_bytes()).0.to_vec(), h(&f.v["service_id"]));
}

#[test]
fn register() {
    let f = fixture();
    let mut r = RegisterRequest {
        nike_scheme: pigeonhole_protocols::pigeonservice::nike::SCHEME.to_string(),
        public_key: f.service.public.to_bytes(),
        voucher: h(&f.v["voucher"]),
        seq: f.v["register"]["seq"].as_u64().unwrap(),
        expiry: f.v["register"]["expiry"].as_u64().unwrap(),
        mac: None,
    };
    assert_eq!(pigeonhole_protocols::pigeonservice::cbor::encode(&r.clone_unsigned()), h(&f.v["register"]["unsigned"]));
    auth::sign_register(&f.ss, &f.plugin.public.to_bytes(), &mut r).unwrap();
    assert_eq!(r.mac.clone().unwrap(), h(&f.v["register"]["mac"]));
    assert_eq!(RouterRequest::Register(r).encode(), h(&f.v["register"]["router_request"]));
}

#[test]
fn renew_and_unregister() {
    let f = fixture();
    let scheme = pigeonhole_protocols::pigeonservice::nike::SCHEME.to_string();
    let mut r = RenewRequest {
        nike_scheme: scheme.clone(),
        public_key: f.service.public.to_bytes(),
        seq: f.v["renew"]["seq"].as_u64().unwrap(),
        expiry: f.v["renew"]["expiry"].as_u64().unwrap(),
        mac: None,
    };
    auth::sign_renew(&f.ss, &f.plugin.public.to_bytes(), &mut r).unwrap();
    assert_eq!(r.mac.clone().unwrap(), h(&f.v["renew"]["mac"]));
    assert_eq!(RouterRequest::Renew(r.clone()).encode(), h(&f.v["renew"]["router_request"]));
    let RouterRequest::Renew(decoded) = RouterRequest::decode(&h(&f.v["renew"]["router_request"])).unwrap() else { panic!() };
    assert_eq!(decoded, r);
    auth::verify_renew(&f.ss, &f.plugin.public.to_bytes(), &decoded).unwrap();

    let mut u = UnregisterRequest { nike_scheme: scheme, public_key: f.service.public.to_bytes(), seq: f.v["unregister"]["seq"].as_u64().unwrap(), mac: None };
    auth::sign_unregister(&f.ss, &f.plugin.public.to_bytes(), &mut u).unwrap();
    assert_eq!(u.mac.clone().unwrap(), h(&f.v["unregister"]["mac"]));
    assert_eq!(RouterRequest::Unregister(u.clone()).encode(), h(&f.v["unregister"]["router_request"]));
    let RouterRequest::Unregister(decoded) = RouterRequest::decode(&h(&f.v["unregister"]["router_request"])).unwrap() else { panic!() };
    assert_eq!(decoded, u);
    auth::verify_unregister(&f.ss, &f.plugin.public.to_bytes(), &decoded).unwrap();

    let lease = RouterReply::decode(&h(&f.v["router_reply_lease"])).unwrap();
    assert_eq!(lease, RouterReply { status: 0, expiry: f.v["register"]["expiry"].as_u64().unwrap() });
    assert_eq!(lease.encode(), h(&f.v["router_reply_lease"]));
    let adv = DirectoryReply::decode(&h(&f.v["advertise_reply"])).unwrap();
    assert_eq!(adv.expiry, f.v["advertise"]["expiry"].as_u64().unwrap());
    assert_eq!(adv.encode(), h(&f.v["advertise_reply"]));
}

#[test]
fn route() {
    let f = fixture();
    let req = RouterRequest::Route(RouteRequest { service_id: f.descriptor.id(), ciphertext: h(&f.v["route"]["ciphertext"]) });
    assert_eq!(req.encode(), h(&f.v["route"]["router_request"]));
}

#[test]
fn advertise_and_withdraw() {
    let f = fixture();
    let mut a = AdvertiseRequest {
        descriptor: f.descriptor.clone(),
        seq: f.v["advertise"]["seq"].as_u64().unwrap(),
        expiry: f.v["advertise"]["expiry"].as_u64().unwrap(),
        mac: None,
    };
    auth::sign_advertise(&f.ss, &f.plugin.public.to_bytes(), &mut a).unwrap();
    assert_eq!(a.mac.clone().unwrap(), h(&f.v["advertise"]["mac"]));
    assert_eq!(DirectoryRequest::Advertise(a).encode(), h(&f.v["advertise"]["directory_request"]));

    let mut w = WithdrawRequest { service_id: f.descriptor.id(), seq: f.v["withdraw"]["seq"].as_u64().unwrap(), mac: None };
    auth::sign_withdraw(&f.ss, &f.plugin.public.to_bytes(), &f.service.public.to_bytes(), &mut w).unwrap();
    assert_eq!(w.mac.clone().unwrap(), h(&f.v["withdraw"]["mac"]));
    assert_eq!(DirectoryRequest::Withdraw(w).encode(), h(&f.v["withdraw"]["directory_request"]));

    assert_eq!(DirectoryRequest::Lookup(f.descriptor.id()).encode(), h(&f.v["lookup_request"]));
    assert_eq!(DirectoryRequest::List.encode(), h(&f.v["list_request"]));
}

#[test]
fn replies() {
    let f = fixture();
    assert_eq!(decode_status(&h(&f.v["router_reply_busy"])).unwrap(), Status::Busy as u8);
    let mut padded = h(&f.v["router_reply_busy"]);
    padded.extend_from_slice(&[0; 100]);
    assert_eq!(decode_status(&padded).unwrap(), Status::Busy as u8);
    padded.push(1);
    assert!(decode_status(&padded).is_err());

    let lookup = DirectoryReply::decode(&h(&f.v["lookup_reply"])).unwrap();
    assert_eq!(lookup.status, 0);
    assert_eq!(lookup.descriptor.unwrap(), f.descriptor);
    let list = DirectoryReply::decode(&h(&f.v["list_reply"])).unwrap();
    assert_eq!((list.read_cap, list.start_index), (vec![1, 2, 3], vec![4, 5]));
    let snap = Snapshot::decode(&h(&f.v["snapshot"])).unwrap();
    assert_eq!((snap.seq, snap.descriptors), (3, vec![f.descriptor.clone()]));
    assert_eq!(decode_link_message(&h(&f.v["link_message"])).unwrap(), h(&f.v["route"]["ciphertext"]));
}

#[test]
fn plugin_side_accepts_go_requests() {
    let f = fixture();
    let RouterRequest::Register(r) = RouterRequest::decode(&h(&f.v["register"]["router_request"])).unwrap() else { panic!() };
    let plugin_pub = f.plugin.public.to_bytes();
    auth::verify_register(&f.ss, &plugin_pub, &r).unwrap();
    let mut forged = r.clone();
    forged.voucher[0] ^= 1;
    assert!(auth::verify_register(&f.ss, &plugin_pub, &forged).is_err());
    assert!(auth::verify_register(&f.ss, &f.service.public.to_bytes(), &r).is_err(), "the MAC binds the plugin key");
    let mut other = f.ss.clone();
    other[0] ^= 1;
    assert!(auth::verify_register(&other, &plugin_pub, &r).is_err(), "and the shared secret");

    let DirectoryRequest::Advertise(a) = DirectoryRequest::decode(&h(&f.v["advertise"]["directory_request"])).unwrap() else { panic!() };
    assert_eq!(a.descriptor, f.descriptor);
    auth::verify_advertise(&f.ss, &plugin_pub, &a).unwrap();
    let DirectoryRequest::Withdraw(w) = DirectoryRequest::decode(&h(&f.v["withdraw"]["directory_request"])).unwrap() else { panic!() };
    auth::verify_withdraw(&f.ss, &plugin_pub, &f.service.public.to_bytes(), &w).unwrap();
    assert_eq!(DirectoryRequest::decode(&h(&f.v["lookup_request"])).unwrap(), DirectoryRequest::Lookup(f.descriptor.id()));
    assert_eq!(DirectoryRequest::decode(&h(&f.v["list_request"])).unwrap(), DirectoryRequest::List);

    assert_eq!(encode_router_reply(Status::Busy), h(&f.v["router_reply_busy"]));
    assert_eq!(encode_link_message(&h(&f.v["route"]["ciphertext"])), h(&f.v["link_message"]));
    let lookup = DirectoryReply { status: 0, expiry: 0, descriptor: Some(f.descriptor.clone()), read_cap: vec![], start_index: vec![] };
    assert_eq!(lookup.encode(), h(&f.v["lookup_reply"]));
}

/// Compares `got` with the golden file at `path` under testdata, or writes it there when
/// PIGEONSERVICE_WRITE_VECTORS is set.
fn golden(path: &str, got: serde_json::Value) {
    let path = format!("{}/../testdata/{path}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("PIGEONSERVICE_WRITE_VECTORS").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
    }
    let want: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(got, want, "{path} differs; PIGEONSERVICE_WRITE_VECTORS=1 rewrites it");
}

/// Every v0 message as this crate encodes it, captured in testdata/pigeonservice/v0/messages.json
/// so a change to the v0 wire fails here; each decodes back to what made it.
#[test]
fn golden_messages() {
    let f = fixture();
    let scheme = pigeonhole_protocols::pigeonservice::nike::SCHEME.to_string();
    let plugin_pub = f.plugin.public.to_bytes();
    let mut register = RegisterRequest {
        nike_scheme: scheme.clone(),
        public_key: f.service.public.to_bytes(),
        voucher: h(&f.v["voucher"]),
        seq: 1,
        expiry: 1767225600,
        mac: None,
    };
    auth::sign_register(&f.ss, &plugin_pub, &mut register).unwrap();
    let mut renew = RenewRequest { nike_scheme: scheme.clone(), public_key: f.service.public.to_bytes(), seq: 2, expiry: 1767225600, mac: None };
    auth::sign_renew(&f.ss, &plugin_pub, &mut renew).unwrap();
    let mut unregister = UnregisterRequest { nike_scheme: scheme, public_key: f.service.public.to_bytes(), seq: 3, mac: None };
    auth::sign_unregister(&f.ss, &plugin_pub, &mut unregister).unwrap();
    let route = RouteRequest { service_id: f.descriptor.id(), ciphertext: h(&f.v["route"]["ciphertext"]) };
    let mut advertise = AdvertiseRequest { descriptor: f.descriptor.clone(), seq: 4, expiry: 1767225600, mac: None };
    auth::sign_advertise(&f.ss, &plugin_pub, &mut advertise).unwrap();
    let mut withdraw = WithdrawRequest { service_id: f.descriptor.id(), seq: 5, mac: None };
    auth::sign_withdraw(&f.ss, &plugin_pub, &f.service.public.to_bytes(), &mut withdraw).unwrap();

    let router_requests = [
        ("register", RouterRequest::Register(register)),
        ("renew", RouterRequest::Renew(renew)),
        ("unregister", RouterRequest::Unregister(unregister)),
        ("route", RouterRequest::Route(route)),
    ];
    let directory_requests = [
        ("advertise", DirectoryRequest::Advertise(advertise)),
        ("withdraw", DirectoryRequest::Withdraw(withdraw)),
        ("lookup", DirectoryRequest::Lookup(f.descriptor.id())),
        ("list", DirectoryRequest::List),
    ];
    let mut router_replies = vec![("lease".to_string(), RouterReply { status: 0, expiry: 1767225600 })];
    let mut directory_replies = vec![
        ("advertise".to_string(), DirectoryReply { status: 0, expiry: 1767225600, descriptor: None, read_cap: vec![], start_index: vec![] }),
        ("lookup".to_string(), DirectoryReply { status: 0, expiry: 0, descriptor: Some(f.descriptor.clone()), read_cap: vec![], start_index: vec![] }),
        ("list".to_string(), DirectoryReply { status: 0, expiry: 0, descriptor: None, read_cap: vec![1; 136], start_index: vec![2; 104] }),
    ];
    for n in 0..=6u8 {
        let s = Status::from_u8(n).unwrap();
        router_replies.push((format!("{s:?}"), RouterReply { status: n, expiry: 0 }));
        directory_replies.push((format!("{s:?}"), DirectoryReply { status: n, expiry: 0, descriptor: None, read_cap: vec![], start_index: vec![] }));
    }
    assert!(Status::from_u8(7).is_none(), "v0 has seven statuses");

    let mut out = serde_json::Map::new();
    let mut section = serde_json::Map::new();
    for (name, r) in &router_requests {
        let raw = r.encode();
        assert_eq!(&RouterRequest::decode(&raw).unwrap(), r);
        section.insert(name.to_string(), hex::encode(raw).into());
    }
    out.insert("router_request".into(), section.into());
    let mut section = serde_json::Map::new();
    for (name, r) in &directory_requests {
        let raw = r.encode();
        assert_eq!(&DirectoryRequest::decode(&raw).unwrap(), r);
        section.insert(name.to_string(), hex::encode(raw).into());
    }
    out.insert("directory_request".into(), section.into());
    let mut section = serde_json::Map::new();
    for (name, r) in &router_replies {
        let raw = r.encode();
        assert_eq!(&RouterReply::decode(&raw).unwrap(), r);
        section.insert(name.clone(), hex::encode(raw).into());
    }
    out.insert("router_reply".into(), section.into());
    let mut section = serde_json::Map::new();
    for (name, r) in &directory_replies {
        let raw = r.encode();
        assert_eq!(&DirectoryReply::decode(&raw).unwrap(), r);
        section.insert(name.clone(), hex::encode(raw).into());
    }
    out.insert("directory_reply".into(), section.into());
    let link = encode_link_message(&h(&f.v["route"]["ciphertext"]));
    assert_eq!(decode_link_message(&link).unwrap(), h(&f.v["route"]["ciphertext"]));
    out.insert("link_message".into(), hex::encode(link).into());
    out.insert("inputs".into(), serde_json::json!({
        "keys_and_shared_secret": "vectors.json",
        "voucher": f.v["voucher"],
        "route_ciphertext": f.v["route"]["ciphertext"],
    }));
    golden("pigeonservice/v0/messages.json", out.into());
}
