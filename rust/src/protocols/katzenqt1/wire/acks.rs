//! The Acks field, following katzenqt's ack_codec.py: the count less one, the members named as a
//! list or a bitmap, whichever is shorter, then each one's Idx64, little-endian. Reading is not
//! strict: like katzenqt, it accepts a list where the bitmap would have been shorter.

use crate::protocols::katzenqt1::wire::Ack;

/// The longest naming: a bitmap reaching roster index 255.
const MAX_NAMING: usize = 32;
const IDX_SIZE: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcksError {
    /// The field is shorter than its count.
    Short,
    /// The members are not named as a list or a bitmap may name them.
    Naming,
}

impl std::fmt::Display for AcksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcksError::Short => write!(f, "acks: field shorter than its count"),
            AcksError::Naming => write!(f, "acks: malformed naming"),
        }
    }
}

impl std::error::Error for AcksError {}

/// The bytes a bitmap needs to reach roster index `i`.
fn width(i: usize) -> usize {
    i / 8 + 1
}

/// The field for `acks`, in ascending order of roster index; empty when there is nothing to
/// acknowledge.
pub fn acks_to_bytes(acks: &[Ack]) -> Vec<u8> {
    let Some(last) = acks.last() else {
        return Vec::new();
    };
    let mut out = vec![(acks.len() - 1) as u8];
    if acks.len() <= width(last.member) {
        out.extend(acks.iter().map(|a| a.member as u8));
    } else {
        let mut bitmap = vec![0u8; width(last.member)];
        for a in acks {
            bitmap[a.member / 8] |= 1 << (7 - a.member % 8);
        }
        out.extend(bitmap);
    }
    for a in acks {
        out.extend(a.idx64.to_le_bytes());
    }
    out
}

fn read_members(naming: &[u8], count: usize) -> Result<Vec<usize>, AcksError> {
    if naming.len() == count {
        if naming.windows(2).any(|w| w[0] >= w[1]) {
            return Err(AcksError::Naming);
        }
        return Ok(naming.iter().map(|&b| b as usize).collect());
    }
    if count < naming.len() || naming.len() > MAX_NAMING || naming.last().is_none_or(|&b| b == 0) {
        return Err(AcksError::Naming);
    }
    let idx: Vec<usize> = (0..naming.len() * 8)
        .filter(|i| naming[i / 8] & (1 << (7 - i % 8)) != 0)
        .collect();
    if idx.len() != count {
        return Err(AcksError::Naming);
    }
    Ok(idx)
}

/// The acknowledgements a field carries.
pub fn acks_from_bytes(field: &[u8]) -> Result<Vec<Ack>, AcksError> {
    let Some((&c, rest)) = field.split_first() else {
        return Ok(Vec::new());
    };
    let count = c as usize + 1;
    if rest.len() < count * IDX_SIZE {
        return Err(AcksError::Short);
    }
    let w = rest.len() - count * IDX_SIZE;
    let members = read_members(&rest[..w], count)?;
    Ok(members
        .into_iter()
        .zip(rest[w..].chunks(IDX_SIZE))
        .map(|(member, v)| Ack {
            member,
            idx64: u64::from_le_bytes(v.try_into().unwrap()),
        })
        .collect())
}
