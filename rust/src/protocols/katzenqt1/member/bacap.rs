//! The one BACAP step a member's driver needs: the index of the box after a box, by
//! HKDF-BLAKE2b-512 over the index's HKDF state, as hpqc's MessageBoxIndex.NextIndex.

use blake2::{Blake2b512, Digest};

use crate::protocols::katzenqt1::member::Index;

const BLOCK: usize = 128;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..64].copy_from_slice(&Blake2b512::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Blake2b512::new();
    inner.update(k.map(|b| b ^ 0x36));
    for p in parts {
        inner.update(p);
    }
    let mut outer = Blake2b512::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// HKDF (RFC 5869) over HMAC-BLAKE2b-512, with no salt.
pub fn hkdf(secret: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let prk = hmac(&[0u8; 64], &[secret]);
    let mut out = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut i = 1u8;
    while out.len() < len {
        t = hmac(&prk, &[&t, info, &[i]]).to_vec();
        out.extend_from_slice(&t);
        i += 1;
    }
    out.truncate(len);
    out
}

/// The index of the box after `i`: Idx64, blinding factor, encryption key and HKDF state, as
/// BACAP lays a MessageBoxIndex out.
pub fn next_index(i: &[u8]) -> Option<Index> {
    if i.len() != 104 {
        return None;
    }
    let idx64 = u64::from_le_bytes(i[..8].try_into().unwrap());
    let okm = hkdf(&i[72..104], &idx64.to_le_bytes(), 96);
    let mut n = Vec::with_capacity(104);
    n.extend((idx64.checked_add(1)?).to_le_bytes());
    n.extend_from_slice(&okm[64..96]);
    n.extend_from_slice(&okm[32..64]);
    n.extend_from_slice(&okm[0..32]);
    Some(n)
}
