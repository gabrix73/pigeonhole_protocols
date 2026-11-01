//! Checks the crate against vectors the Go implementation wrote; see
//! go/cmd/testvectors.

use pigeonhole_protocols::services::auth;
use pigeonhole_protocols::services::nike::{Keypair, PrivateKey, PublicKey};
use pigeonhole_protocols::services::wire::*;

fn vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/services/vectors.json");
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
        nike_scheme: pigeonhole_protocols::services::nike::SCHEME.to_string(),
        public_key: f.service.public.to_bytes(),
        voucher: h(&f.v["voucher"]),
        mac: None,
    };
    assert_eq!(pigeonhole_protocols::services::cbor::encode(&r.clone_unsigned()), h(&f.v["register"]["unsigned"]));
    auth::sign_register(&f.ss, &f.plugin.public.to_bytes(), &mut r).unwrap();
    assert_eq!(r.mac.clone().unwrap(), h(&f.v["register"]["mac"]));
    assert_eq!(RouterRequest::Register(r).encode(), h(&f.v["register"]["router_request"]));
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
    let mut a = AdvertiseRequest { descriptor: f.descriptor.clone(), seq: f.v["advertise"]["seq"].as_u64().unwrap(), mac: None };
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
    let lookup = DirectoryReply { status: 0, descriptor: Some(f.descriptor.clone()), read_cap: vec![], start_index: vec![] };
    assert_eq!(lookup.encode(), h(&f.v["lookup_reply"]));
}
