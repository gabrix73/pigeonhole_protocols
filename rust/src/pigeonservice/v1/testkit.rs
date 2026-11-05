//! A v1 voucher router and service directory on [`crate::transport::sim`], for tests, checking
//! requests with [`Registrar`] as a real plugin would.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::pigeonservice::conn::Conn;
use crate::pigeonservice::handshake::{induct, mint};
use crate::pigeonservice::lease::{MAX_ENTRY_TTL, MAX_LINK_TTL, now};
use crate::pigeonservice::v0::wire::encode_link_message;
use crate::pigeonservice::v1::registrar::{Admitted, Registrar};
use crate::pigeonservice::v1::wire::*;
use crate::pigeonservice::version::{Kind, V1};
use crate::pigeonservice::{Error, v0};
use crate::transport::sim::{Handler, World};

pub use v0::testkit::POLL;

fn reply_to(payload: &[u8], f: impl FnOnce(Request) -> Reply) -> Vec<u8> {
    match Request::decode(payload) {
        Ok(req) => f(req),
        Err(Error::UnsupportedVersion { .. }) => Reply { versions: vec![V1], ..Reply::status(Status::UnsupportedVersion) },
        Err(_) => Reply::status(Status::InvalidRequest),
    }
    .encode()
}

/// Adds a v1 router at `node`, as `voucher_router/v1`.
pub fn add_router(net: &World, node: [u8; 32]) {
    let cap = Kind::VoucherRouter.capability(V1);
    let registrar = Arc::new(Mutex::new(Registrar::new(registrar_id(&node, cap.as_bytes()), MAX_LINK_TTL)));
    let links: Arc<Mutex<HashMap<ServiceId, (Arc<Conn<World>>, u64)>>> = Arc::default();
    let net2 = net.clone();
    let h: Handler = Arc::new(move |payload: Vec<u8>| {
        let (net, registrar, links) = (net2.clone(), registrar.clone(), links.clone());
        Box::pin(async move {
            let mut send = None;
            let out = reply_to(&payload, |req| match req {
                Request::Signed(s) => {
                    let admitted = match registrar.lock().unwrap().admit(&s, now()) {
                        Ok(a) => a,
                        Err(st) => return Reply::status(st),
                    };
                    let id = s.id();
                    let ok = Reply { expiry: s.expiry, ..Reply::status(Status::Ok) };
                    match (s.ctx, admitted) {
                        (_, Admitted::Repeat) => ok,
                        (Ctx::Register, _) => {
                            let (net, links) = (net.clone(), links.clone());
                            tokio::spawn(async move {
                                if let Ok(conn) = induct(Arc::new(net), &s.voucher, "router", POLL).await {
                                    links.lock().unwrap().insert(id, (Arc::new(conn), s.expiry));
                                }
                            });
                            ok
                        }
                        (Ctx::Renew, _) => match links.lock().unwrap().get_mut(&id) {
                            Some((_, expiry)) if *expiry > now() => {
                                *expiry = s.expiry;
                                ok
                            }
                            _ => Reply::status(Status::UnknownService),
                        },
                        (Ctx::Unregister, _) => match links.lock().unwrap().remove(&id) {
                            Some(_) => Reply::status(Status::Ok),
                            None => Reply::status(Status::UnknownService),
                        },
                        _ => Reply::status(Status::InvalidRequest),
                    }
                }
                Request::Route { service_id, ciphertext } => {
                    match links.lock().unwrap().get(&service_id).filter(|(_, e)| *e > now()) {
                        Some((c, _)) => {
                            send = Some((c.clone(), ciphertext));
                            Reply::status(Status::Ok)
                        }
                        None => Reply::status(Status::UnknownService),
                    }
                }
                _ => Reply::status(Status::InvalidRequest),
            });
            if let Some((c, ciphertext)) = send
                && c.send(&encode_link_message(&ciphertext)).await.is_err()
            {
                return Reply::status(Status::InternalError).encode();
            }
            out
        })
    });
    net.add_service(&cap, node, &cap, Default::default(), h);
}

/// Adds a v1 directory at `node`, as `discovery/v1`.
pub fn add_directory(net: &World, node: [u8; 32]) {
    let cap = Kind::Discovery.capability(V1);
    let registrar = Arc::new(Mutex::new(Registrar::new(registrar_id(&node, cap.as_bytes()), MAX_ENTRY_TTL)));
    let records: Arc<Mutex<HashMap<ServiceId, Signed>>> = Arc::default();
    let net2 = net.clone();
    let h: Handler = Arc::new(move |payload: Vec<u8>| {
        let (net, registrar, records) = (net2.clone(), registrar.clone(), records.clone());
        Box::pin(async move {
            if matches!(Request::decode(&payload), Ok(Request::List)) {
                let held: Vec<_> = records.lock().unwrap().values().cloned().collect();
                return list(net, held).await.encode();
            }
            reply_to(&payload, |req| match req {
                Request::Signed(s) => {
                    let admitted = match registrar.lock().unwrap().admit(&s, now()) {
                        Ok(a) => a,
                        Err(st) => return Reply::status(st),
                    };
                    let mut records = records.lock().unwrap();
                    match (s.ctx, admitted) {
                        (Ctx::Advertise, a) => {
                            let expiry = s.expiry;
                            if a == Admitted::Fresh {
                                records.insert(s.id(), s);
                            }
                            Reply { expiry, ..Reply::status(Status::Ok) }
                        }
                        (Ctx::Withdraw, Admitted::Repeat) => Reply::status(Status::Ok),
                        (Ctx::Withdraw, _) => match records.remove(&s.id()) {
                            Some(_) => Reply::status(Status::Ok),
                            None => Reply::status(Status::UnknownService),
                        },
                        _ => Reply::status(Status::InvalidRequest),
                    }
                }
                Request::Lookup(id) => match records.lock().unwrap().get(&id).filter(|r| r.expiry > now()) {
                    Some(r) => Reply { record: Some(r.clone()), ..Reply::status(Status::Ok) },
                    None => Reply::status(Status::UnknownService),
                },
                _ => Reply::status(Status::InvalidRequest),
            })
        })
    });
    net.add_service(&cap, node, &cap, Default::default(), h);
}

/// Mints a voucher for a connection that carries `records`, and serves it in the background.
async fn list(net: World, records: Vec<Signed>) -> Reply {
    let Ok(pending) = mint(&net, "directory").await else { return Reply::status(Status::InternalError) };
    let voucher = pending.voucher.clone();
    tokio::spawn(async move {
        let Ok(conn) = pending.wait(Arc::new(net), POLL).await else { return };
        let snap = Snapshot { seq: 1, records }.encode();
        let Ok(max) = conn.max_message().await else { return };
        for chunk in snap.chunks(max) {
            if conn.send(chunk).await.is_err() {
                return;
            }
        }
    });
    Reply { voucher, ..Reply::status(Status::Ok) }
}

/// A network with v0's two routers and directory, and on the same nodes v1's.
pub fn world() -> World {
    let net = v0::testkit::world();
    add_router(&net, [0xa0; 32]);
    add_router(&net, [0xa1; 32]);
    add_directory(&net, [0xdd; 32]);
    net
}
