//! Services: responders on the mixnet that speak only Pigeonhole, written with
//! [`crate::pigeonservice`].
//!
//! - [`eliza`]: the ELIZA engine and katzenqt chat framing the status bot answers with.
//! - [`status`]: a status bot for the mixnet, with ELIZA as a joke.
//! - [`zulip`]: a bridge between a group and a Zulip stream, with the `zulip` feature.

pub mod eliza;
pub mod status;
#[cfg(feature = "zulip")]
pub mod zulip;
