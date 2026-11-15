//! katzenqt's group chat as of October 2026.
//!
//! - [`wire`]: message fields, GroupChatMessage CBOR, box framing, the reply to a new member, files.
//! - [`member`]: one member of a group, as a state machine; its trace format, and katzenqt's
//!   scenario simulator.
//! - [`engine`]: the client without IO.
//! - [`boxes`]: what the engine asks a transport for, and BACAP's sealing and opening of boxes
//!   and contact vouchers without IO.
//! - [`client`]: the client, over a transport, with its state on disk.
//! - [`tally`]: polls, katzenqt's tally protocol, without IO.

pub mod boxes;
#[cfg(feature = "std")]
pub mod client;
pub mod engine;
pub mod member;
#[cfg(feature = "std")]
pub mod tally;
pub mod wire;
