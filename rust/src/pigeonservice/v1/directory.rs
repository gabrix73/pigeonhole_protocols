//! A client of a v1 service directory. A service advertises a descriptor signed with its key; a
//! client checks every record it gets against that key, so a directory can withhold a service
//! but not change where it is reached.

use std::sync::Arc;
use std::time::Duration;

use crate::pigeonservice::Error;
use crate::pigeonservice::handshake::induct;
use crate::pigeonservice::lease::{next_seq, now};
use crate::pigeonservice::v1::link::request;
use crate::pigeonservice::v1::sign::Identity;
use crate::pigeonservice::v1::wire::*;
use crate::pigeonservice::version::{self, Kind, V1};
use crate::transport::{Backend, ServiceNode};

const MAX_SNAPSHOT: usize = 10 << 20;

/// A client of one v1 directory.
pub struct Directory<B: Backend> {
    ph: Arc<B>,
    node: ServiceNode,
    registrar: [u8; 32],
    poll: Duration,
}

impl<B: Backend> Directory<B> {
    pub fn new(ph: Arc<B>, node: ServiceNode, poll: Duration) -> Self {
        let registrar = registrar_id(&node.node_id_hash, &node.endpoint);
        Directory { ph, node, registrar, poll }
    }

    /// Clients of every v1 directory in the PKI.
    pub async fn all(ph: Arc<B>, poll: Duration) -> Result<Vec<Self>, Error> {
        let nodes = version::nodes(&*ph, Kind::Discovery, V1).await?;
        Ok(nodes.into_iter().map(|n| Directory::new(ph.clone(), n, poll)).collect())
    }

    async fn request(&self, req: &Request) -> Result<Reply, Error> {
        request(&*self.ph, &self.node.node_id_hash, &self.node.endpoint, req).await
    }

    /// Publishes or replaces the descriptor of the service `id` signs for until `expiry`, and
    /// returns the expiry granted.
    pub async fn advertise(&self, id: &Identity, d: &Descriptor, expiry: u64) -> Result<u64, Error> {
        let s = Signed::new(id, Ctx::Advertise, self.registrar, now(), next_seq(), expiry, vec![], Some(d.clone()))?;
        Ok(self.request(&Request::Signed(s)).await?.expiry)
    }

    /// Removes the service's descriptor.
    pub async fn withdraw(&self, id: &Identity) -> Result<(), Error> {
        let s = Signed::new(id, Ctx::Withdraw, self.registrar, now(), next_seq(), 0, vec![], None)?;
        self.request(&Request::Signed(s)).await.map(|_| ())
    }

    /// Checks a record from this directory: signed by its service for this directory, and not
    /// expired.
    pub fn check(&self, r: &Signed) -> Result<(), Error> {
        r.verify()?;
        if r.ctx != Ctx::Advertise || r.registrar != self.registrar {
            return Err(Error::Other("record was not advertised at this directory".into()));
        }
        if r.expiry <= now() {
            return Err(Error::Other("record expired".into()));
        }
        Ok(())
    }

    /// Returns one service's signed descriptor, checked.
    pub async fn lookup(&self, id: ServiceId) -> Result<Signed, Error> {
        let r = self.request(&Request::Lookup(id)).await?.record.ok_or_else(|| Error::Decode("Lookup reply without a record".into()))?;
        if r.id() != id {
            return Err(Error::Other("directory reply names another service".into()));
        }
        self.check(&r)?;
        Ok(r)
    }

    /// Returns every record the directory holds that checks, read over the connection its
    /// one-time voucher opens.
    pub async fn list(&self) -> Result<Vec<Signed>, Error> {
        let voucher = self.request(&Request::List).await?.voucher;
        let conn = induct(self.ph.clone(), &voucher, "client", self.poll).await?;
        let mut buf = Vec::new();
        let mut want = None;
        while want.is_none_or(|w| buf.len() < 4 + w) {
            buf.extend_from_slice(&conn.recv().await?);
            if want.is_none() && buf.len() >= 4 {
                let w = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
                if w > MAX_SNAPSHOT {
                    return Err(Error::Decode("snapshot too large".into()));
                }
                want = Some(w);
            }
        }
        let snap = Snapshot::decode(&buf[4..4 + want.unwrap()])?;
        Ok(snap.records.into_iter().filter(|r| self.check(r).is_ok()).collect())
    }
}
