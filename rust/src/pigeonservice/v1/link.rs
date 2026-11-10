//! Talking to v1 voucher routers: a service registers with its signing key to open a link, and a
//! client routes a sealed voucher to a service by its address.

use std::sync::Arc;
use std::time::Duration;

use crate::pigeonservice::Error;
use crate::pigeonservice::conn::Conn;
use crate::pigeonservice::handshake::{self, Pending};
use crate::pigeonservice::lease::{next_seq, now};
use crate::pigeonservice::nike::{self, Keypair, PublicKey};
use crate::pigeonservice::v1::sign::Identity;
use crate::pigeonservice::v1::size;
use crate::pigeonservice::v1::wire::*;
use crate::pigeonservice::version::{self, Kind, V1};
use crate::transport::{Backend, ServiceNode};

/// How long a client waits for one router before trying the next.
const ROUTE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Sends `req` to the plugin at `node` and returns its reply, refusing first a request that
/// does not fit the mixnet's packets.
pub async fn request<B: Backend>(ph: &B, node: &[u8; 32], endpoint: &[u8], req: &Request) -> Result<Reply, Error> {
    let raw = req.encode();
    size::fits(req.name(), req.max(), raw.len(), ph.max_request().await?)?;
    let reply = Reply::decode(&ph.request(node, endpoint, &raw).await?).map_err(|e| match e {
        Error::VersionMismatch { requested, supported, .. } => {
            Error::VersionMismatch { service: String::from_utf8_lossy(endpoint).into(), requested, supported }
        }
        e => e,
    })?;
    match reply.status {
        0 => Ok(reply),
        s => Err(Error::Status(s)),
    }
}

/// The v1 routers in the PKI.
pub async fn routers<B: Backend>(ph: &B) -> Result<Vec<ServiceNode>, Error> {
    version::nodes(ph, Kind::VoucherRouter, V1).await
}

async fn signed<B: Backend>(ph: &B, node: &ServiceNode, s: Signed) -> Result<Reply, Error> {
    request(ph, &node.node_id_hash, &node.endpoint, &Request::Signed(s)).await
}

fn registrar(node: &ServiceNode) -> [u8; 32] {
    registrar_id(&node.node_id_hash, &node.endpoint)
}

/// Starts a link between the service `id` signs for and the router at `node`, leased until
/// `expiry`: checks every v1 message fits the mixnet's packets, mints a voucher for the
/// service→router stream and registers it. [`Pending::wait`] then yields the service's end of
/// the link.
pub async fn register<B: Backend>(ph: &B, id: &Identity, node: &ServiceNode, expiry: u64) -> Result<Pending, Error> {
    size::check_geometry(ph.max_request().await?)?;
    let pending = handshake::mint(ph, "service").await?;
    let s = Signed::new(id, Ctx::Register, registrar(node), now(), next_seq(), expiry, pending.voucher.clone(), None)?;
    signed(ph, node, s).await?;
    Ok(pending)
}

/// Moves the expiry of the service's link with the router at `node`, returning the expiry
/// granted.
pub async fn renew<B: Backend>(ph: &B, id: &Identity, node: &ServiceNode, expiry: u64) -> Result<u64, Error> {
    let s = Signed::new(id, Ctx::Renew, registrar(node), now(), next_seq(), expiry, vec![], None)?;
    Ok(signed(ph, node, s).await?.expiry)
}

/// Closes the service's link with the router at `node`.
pub async fn unregister<B: Backend>(ph: &B, id: &Identity, node: &ServiceNode) -> Result<(), Error> {
    let s = Signed::new(id, Ctx::Unregister, registrar(node), now(), next_seq(), 0, vec![], None)?;
    signed(ph, node, s).await.map(|_| ())
}

/// Seals `voucher` to the service a checked descriptor describes and hands it to one of the
/// service's routers, trying each in turn until one accepts it.
pub async fn route<B: Backend>(ph: &B, d: &Descriptor, voucher: &[u8]) -> Result<(), Error> {
    if d.nike_scheme != nike::SCHEME {
        return Err(Error::Other(format!("service seals with {}, not {}", d.nike_scheme, nike::SCHEME)));
    }
    let service_pub = PublicKey::from_bytes(&d.nike_public_key)?;
    let ciphertext = ph.box_seal(nike::SCHEME, &service_pub.to_bytes(), voucher).await?;
    let req = Request::Route { service_id: d.address().0, ciphertext };
    let in_pki: Vec<_> = routers(ph).await?.into_iter().map(|n| (n.node_id_hash, n.endpoint)).collect();
    let mut last = Error::NoRouter;
    for r in d.routers.iter().filter(|r| in_pki.contains(&(r.node_id_hash, r.endpoint.as_bytes().to_vec()))) {
        match tokio::time::timeout(ROUTE_TIMEOUT, request(ph, &r.node_id_hash, r.endpoint.as_bytes(), &req)).await {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => last = e,
            Err(_) => last = Error::Transport("router did not answer".into()),
        }
    }
    Err(last)
}

/// Connects a client to the service a checked descriptor describes ([`super::resolve`]): mints a
/// voucher, routes it sealed to the service, and waits for the service's reply.
pub async fn dial<B: Backend>(ph: Arc<B>, d: &Descriptor, display_name: &str, poll: Duration) -> Result<Conn<B>, Error> {
    let pending = handshake::mint(&*ph, display_name).await?;
    route(&*ph, d, &pending.voucher).await?;
    pending.wait(ph, poll).await
}

/// Opens a sealed voucher a router forwarded on a link, with the service's NIKE key. Links carry
/// the same messages as in v0.
pub async fn open_forward<B: Backend>(ph: &B, key: &Keypair, msg: &[u8]) -> Result<Vec<u8>, Error> {
    crate::pigeonservice::v0::link::open_forward(ph, key, msg).await
}
