//! Clients: initiators that reach services. A client finds a service's descriptor in the service
//! directory and dials it, or inducts a voucher the service handed out.

pub use crate::pigeonservice::directory::Directory;
pub use crate::pigeonservice::handshake::induct;
pub use crate::pigeonservice::link::{dial, route};
