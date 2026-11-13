//! The core's maps: std's, and without std hashbrown's and indexmap's on hashbrown's hasher.

#[cfg(feature = "std")]
pub use std::collections::{HashMap, HashSet};
#[cfg(feature = "std")]
pub type IndexMap<K, V> = indexmap::IndexMap<K, V>;

#[cfg(not(feature = "std"))]
pub use hashbrown::{HashMap, HashSet};
#[cfg(not(feature = "std"))]
pub type IndexMap<K, V> = indexmap::IndexMap<K, V, hashbrown::DefaultHashBuilder>;
