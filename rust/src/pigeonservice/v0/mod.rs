//! Version 0 of the service API, experimental: the voucher router and service directory
//! protocol katzenpost's `pigeonservice/common`, `voucher_router` and `discovery` plugins speak
//! today. Requests are authenticated by a MAC under a NIKE shared secret with the plugin, and its
//! messages carry no version field. Its service types are `voucher_router/v0` and
//! `discovery/v0`, published in the PKI under their original capabilities, `voucher_router` and
//! `service_directory`.

pub mod auth;
pub mod directory;
pub mod link;
pub mod service;
pub mod testkit;
pub mod wire;

pub use directory::Directory;
pub use link::{dial, renew, route, unregister};
pub use service::{Config, Incoming, Service, Session};
pub use wire::{ServiceDescriptor, ServiceId};
