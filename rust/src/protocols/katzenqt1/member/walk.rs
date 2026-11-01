use crate::protocols::katzenqt1::member::{Index, counter};

/// How far ahead a walk reaches.
pub const WALK_LIMIT: u64 = 256;

/// The answer to a Walk effect, given how to step from one box's index to the next: the box at
/// the furthest of `targets` fewer than [`WALK_LIMIT`] boxes ahead of `start`, the last `keep`
/// indexes before it (all for `keep` 0), and the step count.
pub fn walk_with<E>(
    mut next: impl FnMut(&[u8]) -> Result<Index, E>,
    start: &[u8],
    targets: &[u64],
    keep: usize,
) -> Result<(Option<Index>, Vec<Index>, usize), E> {
    let here = counter(start);
    let Some(target) = targets
        .iter()
        .copied()
        .filter(|&t| t >= here && t - here < WALK_LIMIT)
        .max()
    else {
        return Ok((None, Vec::new(), 0));
    };
    let first = if keep != 0 && target - here > keep as u64 {
        target - keep as u64
    } else {
        here
    };
    let mut index = start.to_vec();
    for _ in here..first {
        index = next(&index)?;
    }
    let mut skipped = Vec::new();
    for _ in first..target {
        skipped.push(index.clone());
        index = next(&index)?;
    }
    Ok((Some(index), skipped, (target - here) as usize))
}

/// The answer to a DeriveIndexes effect: `count` indexes after `start`.
pub fn derive_with<E>(
    mut next: impl FnMut(&[u8]) -> Result<Index, E>,
    start: &[u8],
    count: usize,
) -> Result<Vec<Index>, E> {
    let mut out = Vec::with_capacity(count);
    let mut at = start.to_vec();
    for _ in 0..count {
        at = next(&at)?;
        out.push(at.clone());
    }
    Ok(out)
}
