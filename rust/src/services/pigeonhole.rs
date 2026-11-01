//! Boxes on streams over a [`Backend`], stepping from one index to the next, and the retry loops
//! services need.

use std::time::Duration;

use rand::Rng;

use crate::protocols::katzenqt1::member::next_index;
use crate::services::Error;
use crate::transport::{Backend, Read};

/// How long a reader waits before asking again for a box nobody has written yet.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How long a failed write or read waits before retrying.
const RETRY_INTERVAL: Duration = Duration::from_secs(2);

/// Size of a BACAP message box index. Write caps and read caps end with the index of their
/// stream's first box.
pub const INDEX_SIZE: usize = 104;

/// The index a write cap or read cap starts at.
pub fn cap_index(cap: &[u8]) -> Result<Vec<u8>, Error> {
    if cap.len() < INDEX_SIZE {
        return Err(Error::Decode("cap too short".into()));
    }
    Ok(cap[cap.len() - INDEX_SIZE..].to_vec())
}

/// The index after `idx`.
pub fn next(idx: &[u8]) -> Result<Vec<u8>, Error> {
    next_index(idx).ok_or_else(|| Error::Decode("not a box index".into()))
}

/// Writes one box and returns the index after it. An empty plaintext writes a tombstone.
pub async fn write<B: Backend>(b: &B, write_cap: &[u8], idx: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    b.write_box(write_cap, idx, plaintext).await?;
    next(idx)
}

/// Reads one box once and returns its plaintext and the index after it, or
/// [`Error::BoxNotFound`] or [`Error::Tombstone`].
pub async fn read<B: Backend>(b: &B, read_cap: &[u8], idx: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    match b.read_box(read_cap, idx).await? {
        Read::Data(d) => Ok((d, next(idx)?)),
        Read::NotFound => Err(Error::BoxNotFound),
        Read::Tombstone => Err(Error::Tombstone(next(idx)?)),
    }
}

/// Sleeps for about `d`, with jitter so many readers don't ask in lockstep.
pub(crate) async fn sleep(d: Duration) {
    let jitter = Duration::from_millis(rand::thread_rng().gen_range(0..=d.as_millis() as u64 / 4));
    tokio::time::sleep(d + jitter).await;
}

/// Reads a box, waiting until it is written. A tombstone is returned as [`Error::Tombstone`] with
/// the index after it. Other failures are retried.
pub async fn read_wait<B: Backend>(b: &B, read_cap: &[u8], idx: &[u8], interval: Duration) -> Result<(Vec<u8>, Vec<u8>), Error> {
    loop {
        match read(b, read_cap, idx).await {
            Ok(r) => return Ok(r),
            Err(e @ (Error::Tombstone(_) | Error::Decode(_))) => return Err(e),
            Err(Error::BoxNotFound) => sleep(interval).await,
            Err(e) => {
                log::debug!("read failed, retrying: {e}");
                sleep(RETRY_INTERVAL).await
            }
        }
    }
}

/// Writes a box, retrying failures. A repeated write of the same box is an idempotent success,
/// so retrying is safe; a box that holds something else is an error.
pub async fn write_retry<B: Backend>(b: &B, write_cap: &[u8], idx: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    loop {
        match write(b, write_cap, idx, plaintext).await {
            Ok(n) => return Ok(n),
            Err(e @ (Error::BoxAlreadyExists | Error::Decode(_))) => return Err(e),
            Err(e) => {
                log::debug!("write failed, retrying: {e}");
                sleep(RETRY_INTERVAL).await
            }
        }
    }
}
