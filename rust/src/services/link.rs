//! Talking to voucher routers: a service registers to open a link, and a
//! client routes a sealed voucher to a service.

use std::sync::Arc;
use std::time::Duration;

use crate::services::Error;
use crate::services::conn::Conn;
use crate::services::handshake::{self, Pending};
use crate::services::nike::{self, Keypair, PublicKey};
use crate::transport::Backend;
use crate::transport::ServiceNode;
use crate::services::wire::*;

/// How long a client waits for one router before trying the next.
const ROUTE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Reads a router's or a directory's public key from what it published in
/// the PKI.
pub fn plugin_public_key(node: &ServiceNode) -> Result<PublicKey, Error> {
    match node.params.get(PARAM_NIKE_SCHEME) {
        Some(serde_cbor::Value::Text(s)) if s == nike::SCHEME => {}
        _ => return Err(Error::Other(format!("service node publishes no {} key", nike::SCHEME))),
    }
    match node.params.get(PARAM_PUBLIC_KEY) {
        Some(serde_cbor::Value::Bytes(b)) => PublicKey::from_bytes(b),
        _ => Err(Error::Other("service node publishes no public key".into())),
    }
}

pub(crate) async fn router_request<B: Backend>(ph: &B, node: &[u8; 32], endpoint: &[u8], req: &RouterRequest) -> Result<(), Error> {
    let raw = ph.request(node, endpoint, &req.encode()).await?;
    match decode_status(&raw)? {
        0 => Ok(()),
        s => Err(Error::Status(s)),
    }
}

/// Starts a link between a service and the voucher router at `node`: mints
/// a voucher for the service→router stream and registers it. The router
/// inducts it; [`Pending::wait`] then yields the service's end of the link.
pub async fn register<B: Backend>(ph: &B, key: &Keypair, node: &ServiceNode) -> Result<Pending, Error> {
    let router_pub = plugin_public_key(node)?;
    let pending = handshake::mint(ph, "service").await?;
    let mut req = RegisterRequest {
        nike_scheme: nike::SCHEME.to_string(),
        public_key: key.public.to_bytes(),
        voucher: pending.voucher.clone(),
        mac: None,
    };
    let ss = key.private.derive_secret(ph, &router_pub).await?;
    crate::services::auth::sign_register(&ss, &router_pub.to_bytes(), &mut req)?;
    router_request(ph, &node.node_id_hash, &node.endpoint, &RouterRequest::Register(req)).await?;
    Ok(pending)
}

/// Seals `voucher` to the service `d` describes and hands it to one of the
/// service's routers, trying each in turn until one accepts it.
pub async fn route<B: Backend>(ph: &B, d: &ServiceDescriptor, voucher: &[u8]) -> Result<(), Error> {
    let service_pub = PublicKey::from_bytes(&d.public_key)?;
    let ciphertext = ph.box_seal(nike::SCHEME, &service_pub.to_bytes(), voucher).await?;
    let req = RouterRequest::Route(RouteRequest { service_id: d.id(), ciphertext });
    // Descriptors come from untrusted directories: only try routers the PKI lists.
    let in_pki: Vec<_> = ph.services(ROUTER_CAPABILITY).await?.into_iter().map(|n| (n.node_id_hash, n.endpoint)).collect();
    let mut last = Error::NoRouter;
    for r in d.routers.iter().filter(|r| in_pki.contains(&(r.node_id_hash, r.endpoint.as_bytes().to_vec()))) {
        match tokio::time::timeout(ROUTE_TIMEOUT, router_request(ph, &r.node_id_hash, r.endpoint.as_bytes(), &req)).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(e)) => last = e,
            Err(_) => last = Error::Transport("router did not answer".into()),
        }
    }
    Err(last)
}

/// Connects a client to the service `d` describes: mints a voucher, routes
/// it sealed to the service, and waits for the service's reply.
pub async fn dial<B: Backend>(ph: Arc<B>, d: &ServiceDescriptor, display_name: &str, poll: Duration) -> Result<Conn<B>, Error> {
    let pending = handshake::mint(&*ph, display_name).await?;
    route(&*ph, d, &pending.voucher).await?;
    pending.wait(ph, poll).await
}

/// Opens a sealed voucher a router forwarded.
pub(crate) async fn open_forward<B: Backend>(ph: &B, key: &Keypair, msg: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(ph.box_open(nike::SCHEME, key.private.as_bytes(), &decode_link_message(msg)?).await?)
}
