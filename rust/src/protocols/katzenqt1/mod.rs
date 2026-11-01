//! katzenqt's group chat as of October 2026.
//!
//! - [`wire`]: message fields, GroupChatMessage CBOR, box framing, the reply to a new member, files.
//! - [`member`]: one member of a group, as a state machine; its trace format, and katzenqt's
//!   scenario simulator.
//! - [`engine`]: the client without IO.
//! - [`client`]: the client, over a transport, with its state on disk.

pub mod client;
pub mod engine;
pub mod member;
pub mod wire;
