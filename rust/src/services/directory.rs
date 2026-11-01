//! A client of the service directory: services advertise themselves, and
//! clients look services up.

use std::sync::Arc;
use std::time::Duration;

use crate::services::Error;
use crate::services::lease::next_seq;
use crate::services::link::plugin_public_key;
use crate::services::nike::{Keypair, PublicKey};
use crate::transport::Backend;
use crate::services::pigeonhole::read_wait;
use crate::transport::ServiceNode;
use crate::services::wire::*;

const MAX_SNAPSHOT: usize = 10 << 20;

/// A client of one service directory.
pub struct Directory<B: Backend> {
    ph: Arc<B>,
    node: ServiceNode,
    public: PublicKey,
    key: Option<Keypair>,
    poll: Duration,
}

impl<B: Backend> Directory<B> {
    /// A client of the directory at `node`. `key` is the service's key,
    /// needed to advertise and withdraw; clients that only look services up
    /// pass None.
    pub fn new(ph: Arc<B>, node: ServiceNode, key: Option<Keypair>, poll: Duration) -> Result<Self, Error> {
        let public = plugin_public_key(&node)?;
        Ok(Directory { ph, node, public, key, poll })
    }

    /// Clients of every directory in the PKI.
    pub async fn all(ph: Arc<B>, key: Option<Keypair>, poll: Duration) -> Result<Vec<Self>, Error> {
        let nodes = ph.services(DIRECTORY_CAPABILITY).await?;
        if nodes.is_empty() {
            return Err(Error::Other("no service directory in the PKI".into()));
        }
        nodes.into_iter().map(|n| Directory::new(ph.clone(), n, key.clone(), poll)).collect()
    }

    async fn request(&self, req: &DirectoryRequest) -> Result<DirectoryReply, Error> {
        let raw = self.ph.request(&self.node.node_id_hash, &self.node.endpoint, &req.encode()).await?;
        let reply = DirectoryReply::decode(&raw)?;
        if reply.status != Status::Ok as u8 {
            return Err(Error::Status(reply.status));
        }
        Ok(reply)
    }

    fn service_key(&self, id: ServiceId) -> Result<&Keypair, Error> {
        match &self.key {
            Some(k) if ServiceId::from_public_key(&k.public.to_bytes()) == id => Ok(k),
            _ => Err(Error::Other("only the service's own key can advertise or withdraw it".into())),
        }
    }

    /// Publishes or replaces the service's descriptor until `expiry` (see
    /// [`crate::services::lease_expiry`]) and returns the expiry granted.
    pub async fn advertise(&self, d: &ServiceDescriptor, expiry: u64) -> Result<u64, Error> {
        let key = self.service_key(d.id())?;
        let mut req = AdvertiseRequest { descriptor: d.clone(), seq: next_seq(), expiry, mac: None };
        let ss = key.private.derive_secret(&*self.ph, &self.public).await?;
        crate::services::auth::sign_advertise(&ss, &self.public.to_bytes(), &mut req)?;
        self.request(&DirectoryRequest::Advertise(req)).await.map(|r| r.expiry)
    }

    /// Removes the service's descriptor.
    pub async fn withdraw(&self, id: ServiceId) -> Result<(), Error> {
        let key = self.service_key(id)?;
        let mut req = WithdrawRequest { service_id: id, seq: next_seq(), mac: None };
        let ss = key.private.derive_secret(&*self.ph, &self.public).await?;
        crate::services::auth::sign_withdraw(&ss, &self.public.to_bytes(), &key.public.to_bytes(), &mut req)?;
        self.request(&DirectoryRequest::Withdraw(req)).await.map(|_| ())
    }

    /// Returns one service's descriptor.
    pub async fn lookup(&self, id: ServiceId) -> Result<ServiceDescriptor, Error> {
        let reply = self.request(&DirectoryRequest::Lookup(id)).await?;
        match reply.descriptor {
            Some(d) if d.id() == id => Ok(d),
            _ => Err(Error::Other("directory reply names another service".into())),
        }
    }

    /// Returns every descriptor the directory holds, read from its current
    /// snapshot stream.
    pub async fn list(&self) -> Result<Vec<ServiceDescriptor>, Error> {
        loop {
            let reply = self.request(&DirectoryRequest::List).await?;
            match self.read_snapshot(&reply.read_cap, &reply.start_index).await {
                // The directory replaced the snapshot while we read it.
                Err(Error::Tombstone(_)) => continue,
                r => return r.map(|s| s.descriptors),
            }
        }
    }

    async fn read_snapshot(&self, read_cap: &[u8], start: &[u8]) -> Result<Snapshot, Error> {
        let mut buf = Vec::new();
        let mut want = None;
        let mut idx = start.to_vec();
        while want.is_none_or(|w| buf.len() < 4 + w) {
            let (chunk, next) = read_wait(&*self.ph, read_cap, &idx, self.poll).await?;
            buf.extend_from_slice(&chunk);
            idx = next;
            if want.is_none() && buf.len() >= 4 {
                let w = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
                if w > MAX_SNAPSHOT {
                    return Err(Error::Decode("snapshot too large".into()));
                }
                want = Some(w);
            }
        }
        Snapshot::decode(&buf[4..4 + want.unwrap()])
    }
}
