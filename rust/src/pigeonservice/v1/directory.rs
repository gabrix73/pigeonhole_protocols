//! A client of a v1 service directory. A service advertises its signed descriptor, and its
//! signed listing if it is public; a client resolves an address to the descriptor, or searches
//! listings by name and type, and checks every record against the service's key and address
//! itself. A directory can withhold a service but not change where it is reached or what it says
//! it is.

use std::sync::Arc;
use std::time::Duration;

use crate::pigeonservice::Error;
use crate::pigeonservice::conn::Conn;
use crate::pigeonservice::handshake::{induct, mint};
use crate::pigeonservice::lease::{next_seq, now};
use crate::pigeonservice::v1::address::{Address, period};
use crate::pigeonservice::v1::link::request;
use crate::pigeonservice::v1::sign::Identity;
use crate::pigeonservice::v1::size;
use crate::pigeonservice::v1::wire::*;
use crate::pigeonservice::version::{self, Kind, V1};
use crate::transport::{Backend, ServiceNode};

const MAX_FRAMED: usize = 10 << 20;

/// Sends `body` on `conn` as one framed layer-1 message.
pub async fn send_framed<B: Backend>(conn: &Conn<B>, body: &[u8]) -> Result<(), Error> {
    let max = conn.max_message().await?;
    for chunk in frame(body).chunks(max) {
        conn.send(chunk).await?;
    }
    Ok(())
}

/// Receives one framed layer-1 message from `conn`.
pub async fn recv_framed<B: Backend>(conn: &Conn<B>) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut want = None;
    while want.is_none_or(|w| buf.len() < 4 + w) {
        buf.extend_from_slice(&conn.recv().await?);
        if want.is_none() && buf.len() >= 4 {
            let w = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
            if w > MAX_FRAMED {
                return Err(Error::Decode("layer-1 message too large".into()));
            }
            want = Some(w);
        }
    }
    buf.truncate(4 + want.unwrap());
    Ok(buf.split_off(4))
}

/// Checks an entry a directory gave for `address`: the service's, signed by it, and current.
pub fn check(entry: &Entry, address: &Address) -> Result<(), Error> {
    address.verify(&entry.descriptor.public_key)?;
    entry.verify()?;
    if entry.descriptor.expiry <= now() {
        return Err(Error::Other("descriptor expired".into()));
    }
    Ok(())
}

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

    /// Registers the service `id` signs for, or updates it, until `expiry`: `entry` holds its
    /// descriptor, and its listing to be public. Returns the expiry granted.
    pub async fn advertise(&self, id: &Identity, entry: &Entry, expiry: u64) -> Result<u64, Error> {
        size::check_geometry(self.ph.max_request().await?)?;
        if entry.descriptor.public_key != id.public_key() {
            return Err(Error::Other("the entry is another service's".into()));
        }
        entry.verify()?;
        let pending = mint(&*self.ph, "service").await?;
        let s = Signed::new(id, Ctx::Advertise, self.registrar, now(), next_seq(), expiry, pending.voucher.clone(), Some(entry.digest()))?;
        let granted = self.request(&Request::Signed(s)).await?.expiry;
        send_framed(&pending.wait(self.ph.clone(), self.poll).await?, &entry.encode()).await?;
        Ok(granted)
    }

    /// Revokes the service's registration: the directory forgets its entry.
    pub async fn withdraw(&self, id: &Identity) -> Result<(), Error> {
        let s = Signed::new(id, Ctx::Withdraw, self.registrar, now(), next_seq(), 0, vec![], None)?;
        self.request(&Request::Signed(s)).await.map(|_| ())
    }

    /// Reads the answer to `req` over the connection its one-time voucher opens.
    async fn fetch(&self, req: &Request) -> Result<Vec<u8>, Error> {
        let voucher = self.request(req).await?.voucher;
        recv_framed(&induct(self.ph.clone(), &voucher, "client", self.poll).await?).await
    }

    /// The service at `address`: its descriptor, and its listing if it is public, checked.
    pub async fn resolve(&self, address: &Address) -> Result<Entry, Error> {
        let entry = Entry::decode(&self.fetch(&Request::Resolve(address.lookup(period(now())))).await?)?;
        check(&entry, address)?;
        Ok(entry)
    }

    /// The public services whose name holds `name` and whose type is `kind`, either empty for
    /// any, checked. Names are labels: several services may share one.
    pub async fn search(&self, name: &str, kind: &str) -> Result<Vec<Listing>, Error> {
        let listings = decode_listings(&self.fetch(&Request::Search { name: name.into(), kind: kind.into() }).await?)?;
        let t = now();
        Ok(listings.into_iter().filter(|l| l.verify().is_ok() && l.expiry > t && l.matches(name, kind)).collect())
    }
}

/// The service at `address`, from the first v1 directory that has it.
pub async fn resolve<B: Backend>(ph: Arc<B>, address: &Address, poll: Duration) -> Result<Entry, Error> {
    let mut last = Error::Status(Status::UnknownService as u8);
    for d in Directory::all(ph, poll).await? {
        match d.resolve(address).await {
            Ok(e) => return Ok(e),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// [`Directory::search`] at every v1 directory, merged: each service once, at its newest
/// listing. Fails only if no directory answers.
pub async fn search<B: Backend>(ph: Arc<B>, name: &str, kind: &str, poll: Duration) -> Result<Vec<Listing>, Error> {
    let mut found: std::collections::BTreeMap<Address, Listing> = Default::default();
    let mut last = None;
    for d in Directory::all(ph, poll).await? {
        match d.search(name, kind).await {
            Ok(ls) => {
                last = Some(Ok(()));
                for l in ls {
                    if found.get(&l.address()).is_none_or(|o| o.revision < l.revision) {
                        found.insert(l.address(), l);
                    }
                }
            }
            Err(e) if last.is_none() => last = Some(Err(e)),
            Err(_) => {}
        }
    }
    last.unwrap_or(Ok(()))?;
    Ok(found.into_values().collect())
}
