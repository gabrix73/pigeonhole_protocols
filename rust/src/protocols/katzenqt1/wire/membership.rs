use sha2::{Digest, Sha256};

use crate::protocols::katzenqt1::wire::key_of;

/// What a message's membership_hash says of its sender's view of the group, as katzenqt's
/// canonical_membership_hash computes it: SHA-256, under a domain, of the members' keys, each
/// once, in byte order. A member counts itself as write_cap[32:].
pub fn membership_hash<T: AsRef<[u8]>>(read_caps: &[T]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = read_caps.iter().map(|c| key_of(c.as_ref())).collect();
    keys.sort();
    keys.dedup();
    let mut h = Sha256::new();
    h.update(b"KP:membership:v1");
    for k in keys {
        h.update(k);
    }
    h.finalize().into()
}
