//! The framework pigeonhole services are written with; the services themselves are under
//! [`crate::services`].
//!
//! A service holds links with voucher routers and advertises itself in the service directory. A
//! client reaches it by sealing a contact voucher to the service's public key and handing it to
//! one of its routers; the service inducts the voucher and the two share a two-way connection. A
//! service can also hand a voucher out itself, for a client to induct, as a chat client adds a
//! contact.
//!
//! The protocol with the routers and directories, layer 0, is versioned; [`version`] says how a
//! client picks one. [`v0`] is the protocol katzenpost's plugins speak today, and what this
//! module re-exports at its top level; [`v1`] names a service by an address, the hash of its
//! post-quantum hybrid signing key, and registers with that key and a signature. The
//! connections they lead to, layer 1 ([`conn`], [`handshake`]), are the same in every version.

pub mod cbor;
pub mod conn;
pub mod handshake;
pub mod lease;
pub mod nike;
pub mod pigeonhole;
pub mod v0;
pub mod v1;
pub mod version;

pub use v0::{auth, directory, link, service, testkit, wire};

pub use conn::{Conn, ConnState};
pub use directory::Directory;
pub use handshake::{Pending, induct, mint};
pub use lease::{MAX_ENTRY_TTL, MAX_LINK_TTL, lease_expiry};
pub use link::{dial, renew, route, unregister};
pub use nike::Keypair;
pub use pigeonhole::DEFAULT_POLL_INTERVAL;
pub use service::{Config, Incoming, Service, Session};
pub use wire::{ServiceDescriptor, ServiceId};

/// Errors from the framework.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("pigeonservice: invalid key")]
    InvalidKey,
    #[error("pigeonservice: degenerate shared secret")]
    DegenerateSecret,
    #[error("pigeonservice: cryptographic failure")]
    Crypto,
    #[error("pigeonservice: decode: {0}")]
    Decode(String),
    #[error("pigeonservice: WhoReply must name exactly one stream")]
    BadWhoReply,
    #[error("pigeonservice: box not found")]
    BoxNotFound,
    #[error("pigeonservice: box is a tombstone")]
    Tombstone(Vec<u8>),
    #[error("pigeonservice: box already holds something else")]
    BoxAlreadyExists,
    #[error("pigeonservice: message larger than one box")]
    MessageTooLarge,
    #[error("pigeonservice: bad MAC")]
    BadMac,
    #[error("pigeonservice: bad signature")]
    BadSignature,
    #[error("pigeonservice: bad address: {0}")]
    BadAddress(String),
    /// The two sides speak different layer-0 versions. There is no negotiation: each side speaks
    /// exactly the version it was built for.
    #[error("pigeonservice: version mismatch with {service}: the client speaks v{requested}, the service supports {}; upgrade the client or app, or use a service that offers v{requested}", version::list(supported))]
    VersionMismatch { service: String, requested: u8, supported: Vec<u8> },
    #[error("pigeonservice: {0}")]
    Oversize(String),
    #[error("pigeonservice: status {0}")]
    Status(u8),
    #[error("pigeonservice: no voucher router accepted the request")]
    NoRouter,
    #[error("pigeonservice: service closed")]
    Closed,
    #[error("pigeonservice: {0}")]
    Transport(String),
    #[error("pigeonservice: io: {0}")]
    Io(#[from] std::io::Error),
    #[error("pigeonservice: {0}")]
    Other(String),
}

impl From<crate::transport::Error> for Error {
    fn from(e: crate::transport::Error) -> Self {
        match e {
            crate::transport::Error::BoxAlreadyExists => Error::BoxAlreadyExists,
            e => Error::Transport(e.to_string()),
        }
    }
}
