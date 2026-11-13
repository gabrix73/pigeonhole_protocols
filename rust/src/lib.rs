//! Protocols over Katzenpost's Pigeonhole storage.
//!
//! - [`protocols`]: designs among peers, such as group chat, where no member is an initiator or
//!   a responder.
//! - [`transport`]: what a protocol asks of Pigeonhole; over the client daemon's thin client, in
//!   memory for tests, and served from one process to others.
//! - [`pigeonservice`]: the framework mixnet services are written with.
//! - [`services`]: responders written with it.
//! - [`clients`]: initiators, which reach services.
//! - [`secret`]: caps and keys in guarded memory, wiped on drop.
//!
//! Without the default `std` feature only the sans-io katzenqt1 core is built, `no_std` with
//! `alloc`: [`protocols::katzenqt1`]'s `wire`, `member`, `engine` and `boxes`, and [`secret`].

#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
pub mod clients;
mod collections;
#[cfg(feature = "std")]
pub mod pigeonservice;
mod prelude;
pub mod protocols;
pub mod secret;
#[cfg(feature = "std")]
pub mod services;
#[cfg(feature = "std")]
pub mod transport;
