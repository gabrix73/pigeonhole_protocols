//! Version 1 of the service API: a service registers with routers and advertises in directories
//! with its signing key and a signature over each request, bound to the plugin it is for, the
//! time and a revision; see [`wire`] for the messages and [`registrar`] for what a plugin checks.
//! Every message fits one Sphinx packet ([`size`]). A directory hands out signed records and
//! one-time vouchers, never read caps. Its service types are `voucher_router/v1` and
//! `discovery/v1`.
//!
//! The plugins in katzenpost do not serve v1 yet; `testdata/pigeonservice/v1` holds its wire
//! for them, and [`testkit`] serves it in tests. [`crate::pigeonservice::Service`] runs on v0.

pub mod directory;
pub mod link;
pub mod registrar;
pub mod sign;
pub mod size;
pub mod testkit;
pub mod wire;

pub use directory::Directory;
pub use link::{dial, register, renew, route, unregister};
pub use sign::Identity;
pub use wire::{Descriptor, Signed};
