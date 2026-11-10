//! Version 1 of the service API. A service is its signing key, hpqc's hybrid
//! `Falcon-padded-512-Ed25519`, and its [`Address`] is the key's hash: what routers route vouchers
//! by, and what a client checks the service's descriptor against.
//!
//! Layer 0, CBOR requests to plugins, one Sphinx packet each ([`size`]):
//!
//! - a **voucher router** links a service that registers with its key and a signature, and
//!   routes a client's sealed voucher to the service by its address;
//! - a **directory** takes a service's signed descriptor and, if it is public, its signed
//!   listing; it resolves an address, asked by a lookup blinded per period, and searches
//!   listings by name and type, answering each with a one-time voucher, never a read cap.
//!
//! Every registration, update and revocation is signed over the request type, the registrar,
//! the time and a revision ([`sign`], [`registrar`]); see [`wire`] for the messages. Layer 1, the
//! descriptor with the 929-byte key and the listings, travels over Pigeonhole connections. Its
//! service types are `voucher_router/v1` and `discovery/v1`; mixnet only.
//!
//! The plugins in katzenpost do not serve v1 yet; `testdata/pigeonservice/v1` holds its wire
//! for them, and [`testkit`] serves it in tests. [`crate::pigeonservice::Service`] runs on v0.

pub mod address;
pub mod directory;
pub mod link;
pub mod registrar;
pub mod sign;
pub mod size;
pub mod testkit;
pub mod wire;

pub use address::Address;
pub use directory::{Directory, resolve, search};
pub use link::{dial, register, renew, route, unregister};
pub use sign::Identity;
pub use wire::{Descriptor, Entry, Listing, Signed};
