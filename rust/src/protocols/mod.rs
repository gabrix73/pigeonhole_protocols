//! Designs among peers, such as group chat, where no member is an initiator or a responder, and
//! [`stream`], a byte stream between two, and [`datagram`], datagrams over one.

#[cfg(feature = "std")]
pub mod datagram;
pub mod katzenqt1;
#[cfg(feature = "std")]
pub mod stream;
