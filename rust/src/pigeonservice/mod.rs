//! The framework pigeonhole services are written with; the services themselves are under
//! [`crate::services`].
//!
//! A service holds links with voucher routers and advertises itself in the service directory. A
//! client reaches it by sealing a contact voucher to the service's public key and handing it to
//! one of its routers; the service inducts the voucher and the two share a two-way connection. A
//! service can also hand a voucher out itself, for a client to induct, as a chat client adds a
//! contact. The framework is wire compatible with the Go one in `pigeonservice/` and with
//! katzenpost's voucher router and service directory, server plugins whose protocol is
//! katzenpost's `pigeonservice/common`, `voucher_router` and `discovery`.

pub mod auth;
pub mod cbor;
pub mod conn;
pub mod directory;
pub mod handshake;
pub mod lease;
pub mod link;
pub mod nike;
pub mod pigeonhole;
pub mod service;
pub mod testkit;
pub mod wire;

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
