//! What std's prelude gives and `no_std` takes from alloc, for `use crate::prelude::*`.

#![allow(unused_imports)]

pub use alloc::borrow::ToOwned;
pub use alloc::boxed::Box;
pub use alloc::string::{String, ToString};
pub use alloc::vec::Vec;
pub use alloc::{format, vec};
