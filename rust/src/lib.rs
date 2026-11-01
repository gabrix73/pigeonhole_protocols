//! Protocols over Katzenpost's Pigeonhole storage.
//!
//! - [`protocols`]: designs among peers, such as group chat, where no member is an initiator or
//!   a responder.
//! - [`transport`]: what a protocol asks of Pigeonhole; over the client daemon's thin client, in
//!   memory for tests, and served from one process to others.
//! - [`services`]: responders, and the framework they are written with.
//! - [`clients`]: initiators, which reach services.
//! - [`secret`]: caps and keys in guarded memory, wiped on drop.

pub mod clients;
pub mod protocols;
pub mod secret;
pub mod services;
pub mod transport;
