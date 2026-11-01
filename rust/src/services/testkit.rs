//! A voucher router and a service directory on [`crate::transport::sim`], enough to run
//! services end to end in tests.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::services::conn::Conn;
use crate::transport::sim::{Handler, World};
use crate::services::nike::{self, Keypair, PrivateKey, PublicKey};
use crate::transport::Backend;
use crate::services::wire::*;
use crate::services::{auth, induct};

/// The poll interval the test router uses.
pub const POLL: Duration = Duration::from_millis(10);

/// What a plugin with `key` publishes in the PKI.
pub fn params(key: &Keypair) -> BTreeMap<String, serde_cbor::Value> {
    BTreeMap::from([
        (PARAM_NIKE_SCHEME.to_string(), serde_cbor::Value::Text(nike::SCHEME.into())),
        (PARAM_PUBLIC_KEY.to_string(), serde_cbor::Value::Bytes(key.public.to_bytes())),
    ])
}

/// A key for a plugin on the sim, made without the sim's async calls.
fn plugin_key() -> Keypair {
    let (public, private) = crate::transport::sim::nike_keypair();
    Keypair { public: PublicKey::from_bytes(&public).unwrap(), private: PrivateKey::from_bytes(&private).unwrap() }
}

/// The plugin's shared secret with the service whose public key is `service_pub`.
async fn plugin_secret(net: &World, key: &Keypair, service_pub: &[u8]) -> Option<crate::transport::Secret> {
    net.nike_derive_secret(nike::SCHEME, key.private.as_bytes(), service_pub).await.ok()
}

/// Adds a router at `node`.
pub fn add_router(net: &World, node: [u8; 32]) {
    let key = plugin_key();
    let links: Arc<Mutex<HashMap<ServiceId, Arc<Conn<World>>>>> = Arc::default();
    let net2 = net.clone();
    let k = key.clone();
    let h: Handler = Arc::new(move |payload: Vec<u8>| {
        let (net, key, links) = (net2.clone(), k.clone(), links.clone());
        Box::pin(async move {
            let status = match RouterRequest::decode(&payload) {
                Ok(RouterRequest::Register(r)) => {
                    let ss = plugin_secret(&net, &key, &r.public_key).await;
                    if ss.is_none_or(|ss| auth::verify_register(&ss, &key.public.to_bytes(), &r).is_err()) {
                        Status::BadMac
                    } else {
                        let id = ServiceId::from_public_key(&r.public_key);
                        tokio::spawn(async move {
                            if let Ok(conn) = induct(Arc::new(net), &r.voucher, "router", POLL).await {
                                links.lock().unwrap().insert(id, Arc::new(conn));
                            }
                        });
                        Status::Ok
                    }
                }
                Ok(RouterRequest::Route(r)) => {
                    let link = links.lock().unwrap().get(&r.service_id).cloned();
                    match link {
                        Some(c) => match c.send(&encode_link_message(&r.ciphertext)).await {
                            Ok(()) => Status::Ok,
                            Err(_) => Status::InternalError,
                        },
                        None => Status::UnknownService,
                    }
                }
                Err(_) => Status::InvalidRequest,
            };
            encode_router_reply(status)
        })
    });
    net.add_service(ROUTER_CAPABILITY, node, ROUTER_CAPABILITY, params(&key), h);
}

/// Adds a directory at `node`.
pub fn add_directory(net: &World, node: [u8; 32]) {
    let key = plugin_key();
    let descs: Arc<Mutex<HashMap<ServiceId, (u64, ServiceDescriptor)>>> = Arc::default();
    let (k, net2) = (key.clone(), net.clone());
    let h: Handler = Arc::new(move |payload: Vec<u8>| {
        let (net, key, descs) = (net2.clone(), k.clone(), descs.clone());
        Box::pin(async move {
            let mut reply = DirectoryReply { status: Status::Ok as u8, descriptor: None, read_cap: vec![], start_index: vec![] };
            match DirectoryRequest::decode(&payload) {
                Ok(DirectoryRequest::Advertise(a)) => {
                    let ss = plugin_secret(&net, &key, &a.descriptor.public_key).await;
                    let bad = ss.is_none_or(|ss| auth::verify_advertise(&ss, &key.public.to_bytes(), &a).is_err());
                    let mut d = descs.lock().unwrap();
                    let id = a.descriptor.id();
                    if bad {
                        reply.status = Status::BadMac as u8;
                    } else if d.get(&id).is_some_and(|(seq, _)| *seq >= a.seq) {
                        reply.status = Status::Stale as u8;
                    } else {
                        d.insert(id, (a.seq, a.descriptor));
                    }
                }
                Ok(DirectoryRequest::Lookup(id)) => match descs.lock().unwrap().get(&id) {
                    Some((_, d)) => reply.descriptor = Some(d.clone()),
                    None => reply.status = Status::UnknownService as u8,
                },
                _ => reply.status = Status::InvalidRequest as u8,
            }
            reply.encode()
        })
    });
    net.add_service(DIRECTORY_CAPABILITY, node, DIRECTORY_CAPABILITY, params(&key), h);
}

/// A network with two routers and a directory.
pub fn world() -> World {
    let net = World::default();
    add_router(&net, [0xa0; 32]);
    add_router(&net, [0xa1; 32]);
    add_directory(&net, [0xdd; 32]);
    net
}

/// Waits until the directory lists the service with `n` routers.
pub async fn lookup_linked(net: &World, id: ServiceId, n: usize) -> ServiceDescriptor {
    let dir = crate::services::Directory::all(Arc::new(net.clone()), None, POLL).await.unwrap().remove(0);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(d) = dir.lookup(id).await
            && d.routers.len() == n
        {
            return d;
        }
        assert!(tokio::time::Instant::now() < deadline, "service never linked with {n} routers");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
