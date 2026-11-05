//! A v1 voucher router and service directory on [`crate::transport::sim`], for tests, checking
//! requests with [`Registrar`] and records as a real plugin would.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::pigeonservice::conn::Conn;
use crate::pigeonservice::handshake::{induct, mint};
use crate::pigeonservice::lease::{MAX_ENTRY_TTL, MAX_LINK_TTL, now};
use crate::pigeonservice::v0::wire::encode_link_message;
use crate::pigeonservice::v1::address::{Address, period};
use crate::pigeonservice::v1::directory::{recv_framed, send_framed};
use crate::pigeonservice::v1::registrar::{Admitted, Registrar};
use crate::pigeonservice::v1::wire::*;
use crate::pigeonservice::version::{Kind, V1};
use crate::pigeonservice::{Error, v0};
use crate::transport::sim::{Handler, World};

pub use v0::testkit::POLL;

/// A link and its lease.
type Links = Arc<Mutex<HashMap<ServiceId, (Arc<Conn<World>>, u64)>>>;

fn reply_to(payload: &[u8], f: impl FnOnce(Request) -> Reply) -> Vec<u8> {
    match Request::decode(payload) {
        Ok(req) => f(req),
        Err(Error::VersionMismatch { .. }) => Reply { versions: vec![V1], ..Reply::status(Status::UnsupportedVersion) },
        Err(_) => Reply::status(Status::InvalidRequest),
    }
    .encode()
}

/// Adds a v1 router at `node`, as `voucher_router/v1`.
pub fn add_router(net: &World, node: [u8; 32]) {
    let cap = Kind::VoucherRouter.capability(V1);
    let registrar = Arc::new(Mutex::new(Registrar::new(registrar_id(&node, cap.as_bytes()), MAX_LINK_TTL)));
    let links: Links = Arc::default();
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

/// What the directory holds of each service: its entry, none once withdrawn, the lease, and the
/// revision of the request that set them, so that an entry read late never replaces a newer one.
type Entries = Arc<Mutex<HashMap<ServiceId, (Option<Entry>, u64, u64)>>>;

/// Adds a v1 directory at `node`, as `discovery/v1`.
pub fn add_directory(net: &World, node: [u8; 32]) {
    let cap = Kind::Discovery.capability(V1);
    let registrar = Arc::new(Mutex::new(Registrar::new(registrar_id(&node, cap.as_bytes()), MAX_ENTRY_TTL)));
    let entries: Entries = Arc::default();
    let net2 = net.clone();
    let h: Handler = Arc::new(move |payload: Vec<u8>| {
        let (net, registrar, entries) = (net2.clone(), registrar.clone(), entries.clone());
        Box::pin(async move {
            let t = now();
            let answer = match Request::decode(&payload) {
                Ok(Request::Resolve(lookup)) => {
                    let p = period(t);
                    let held = entries.lock().unwrap().iter().find_map(|(id, (e, expiry, _))| {
                        e.as_ref().filter(|_| *expiry > t && (p.saturating_sub(1)..=p + 1).any(|p| Address(*id).lookup(p) == lookup)).map(Entry::encode)
                    });
                    match held {
                        Some(body) => serve(net, body).await,
                        None => Reply::status(Status::UnknownService),
                    }
                }
                Ok(Request::Search { name, kind }) => {
                    let held: Vec<_> = entries
                        .lock()
                        .unwrap()
                        .values()
                        .filter(|(_, expiry, _)| *expiry > t)
                        .filter_map(|(e, _, _)| e.as_ref()?.listing.clone())
                        .filter(|l| l.matches(&name, &kind))
                        .collect();
                    serve(net, encode_listings(&held)).await
                }
                _ => return reply_to(&payload, |req| advertise(&net, &registrar, &entries, req)),
            };
            answer.encode()
        })
    });
    net.add_service(&cap, node, &cap, Default::default(), h);
}

fn advertise(net: &World, registrar: &Mutex<Registrar>, entries: &Entries, req: Request) -> Reply {
    let Request::Signed(s) = req else { return Reply::status(Status::InvalidRequest) };
    let admitted = match registrar.lock().unwrap().admit(&s, now()) {
        Ok(a) => a,
        Err(st) => return Reply::status(st),
    };
    match (s.ctx, admitted) {
        (Ctx::Advertise, a) => {
            if a == Admitted::Fresh {
                // Read the service's entry over its voucher, and take it if it is what it signed for.
                let (net, entries, s) = (net.clone(), entries.clone(), s.clone());
                tokio::spawn(async move {
                    let Ok(conn) = induct(Arc::new(net), &s.voucher, "directory", POLL).await else { return };
                    let Ok(raw) = recv_framed(&conn).await else { return };
                    let Ok(entry) = Entry::decode(&raw) else { return };
                    if entry.verify().is_err() || entry.descriptor.public_key != s.public_key || Some(entry.digest()) != s.record {
                        return;
                    }
                    let mut entries = entries.lock().unwrap();
                    if entries.get(&s.id()).is_none_or(|(_, _, r)| *r < s.revision) {
                        entries.insert(s.id(), (Some(entry), s.expiry, s.revision));
                    }
                });
            }
            Reply { expiry: s.expiry, ..Reply::status(Status::Ok) }
        }
        (Ctx::Withdraw, Admitted::Repeat) => Reply::status(Status::Ok),
        (Ctx::Withdraw, _) => match entries.lock().unwrap().insert(s.id(), (None, 0, s.revision)) {
            Some((Some(_), ..)) => Reply::status(Status::Ok),
            _ => Reply::status(Status::UnknownService),
        },
        _ => Reply::status(Status::InvalidRequest),
    }
}

/// Mints a one-time voucher for a connection that carries `body`, and serves it in the
/// background.
async fn serve(net: World, body: Vec<u8>) -> Reply {
    let Ok(pending) = mint(&net, "directory").await else { return Reply::status(Status::InternalError) };
    let voucher = pending.voucher.clone();
    tokio::spawn(async move {
        if let Ok(conn) = pending.wait(Arc::new(net), POLL).await {
            let _ = send_framed(&conn, &body).await;
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
