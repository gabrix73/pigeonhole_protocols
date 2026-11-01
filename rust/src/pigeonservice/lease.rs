//! Leases. A registration with a voucher router and an advertisement in a
//! service directory name an expiry, in Unix seconds, and the plugin
//! forgets the record once it passes. A request's expiry must lie after the
//! plugin's clock and at most the plugin's longest lease plus
//! [`MAX_CLOCK_SKEW`] ahead of it, so a request is only ever valid within
//! its own window.

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The longest lease a router grants a link.
pub const MAX_LINK_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
/// The longest lease a directory grants a descriptor.
pub const MAX_ENTRY_TTL: Duration = Duration::from_secs(24 * 3600);
/// How far ahead of the plugin's clock a lease may reach beyond the longest
/// lease, allowing for the clocks of the two to differ.
pub const MAX_CLOCK_SKEW: Duration = Duration::from_secs(10 * 60);

static LAST_SEQ: Mutex<u64> = Mutex::new(0);

/// Unix seconds now.
pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// A sequence number for a request that replaces an earlier one: the time
/// in nanoseconds, and always more than the last returned.
pub fn next_seq() -> u64 {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos() as u64;
    let mut seq = LAST_SEQ.lock().unwrap();
    *seq = (*seq + 1).max(nanos);
    *seq
}

/// The expiry a client asks for to hold a lease as long as a plugin grants:
/// `longest` from now.
pub fn lease_expiry(longest: Duration) -> u64 {
    now() + longest.as_secs()
}

/// Validates a requested expiry against a plugin's clock and its longest
/// lease, returning when the plugin may forget every record the request
/// could have replaced.
pub fn check_lease(now: u64, expiry: u64, longest: Duration) -> Option<u64> {
    let keep = now + (longest + MAX_CLOCK_SKEW).as_secs();
    (expiry > now && expiry <= keep).then_some(keep)
}
