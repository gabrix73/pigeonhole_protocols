//! Clients: initiators that reach services. A client finds a service's descriptor in the service
//! directory and dials it, or inducts a voucher the service handed out.

pub use crate::services::directory::Directory;
pub use crate::services::handshake::induct;
pub use crate::services::link::{dial, route};
