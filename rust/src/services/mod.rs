//! Services: responders on the mixnet that speak only Pigeonhole, written with
//! [`crate::pigeonservice`].
//!
//! - [`eliza`]: an ELIZA chatbot katzenqt users can talk to.
//! - [`zulip`]: a bridge between a group and a Zulip stream, with the `zulip` feature.

pub mod eliza;
#[cfg(feature = "zulip")]
pub mod zulip;
