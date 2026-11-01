//! A file kept sealed whole: [`MAGIC`], then the file's bytes sealed by [`seal`] under a key of
//! 32 bytes, with the magic as associated data. The state's redb database lives in memory in a
//! [`SealedFile`], and the whole of it is sealed and written out after every commit.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use zeroize::{Zeroize, Zeroizing};

use crate::protocols::katzenqt1::client::seal;
use crate::secret::Secret;

/// How every sealed file starts.
pub const MAGIC: &[u8; 8] = b"PHSTATE1";

/// `plain`, sealed whole as a file.
pub fn seal_file(key: &[u8], plain: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    out.extend(seal::seal(key, MAGIC, plain));
    out
}

/// What a sealed file holds; `None` if it is not one, was sealed with another key, or was changed.
pub fn open_file(key: &[u8], kept: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let sealed = kept.strip_prefix(MAGIC.as_slice())?;
    seal::open(key, MAGIC, sealed).ok()
}

pub fn is_sealed(kept: &[u8]) -> bool {
    kept.starts_with(MAGIC)
}

/// Write `bytes` to `path` in its place: to a file beside it first, synced unless `no_sync`, then
/// renamed over it, so that a crash leaves either the old file or the new one.
pub fn write_in_place(path: &Path, bytes: &[u8], no_sync: bool) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(bytes)?;
            if !no_sync {
                f.sync_all()?;
            }
            Ok(())
        })
        .and_then(|()| std::fs::rename(&tmp, path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if !no_sync && let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// A redb database's bytes, in memory, kept on disk sealed whole at `path`.
pub struct SealedFile {
    path: PathBuf,
    key: Secret,
    no_sync: bool,
    bytes: RwLock<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for SealedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SealedFile({})", self.path.display())
    }
}

/// The file could not be opened with the key given.
#[derive(Debug)]
pub enum Unopened {
    Locked,
    Io(std::io::Error),
}

impl SealedFile {
    /// The database sealed at `path`, or an empty one if there is no file there.
    pub fn open(path: PathBuf, key: Secret, no_sync: bool) -> Result<SealedFile, Unopened> {
        let bytes = match std::fs::read(&path) {
            Ok(kept) => open_file(&key, &kept).ok_or(Unopened::Locked)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Zeroizing::new(Vec::new()),
            Err(e) => return Err(Unopened::Io(e)),
        };
        Ok(SealedFile::new(path, key, no_sync, bytes))
    }

    /// A database of `bytes`, to be kept sealed at `path`.
    pub fn new(path: PathBuf, key: Secret, no_sync: bool, bytes: Zeroizing<Vec<u8>>) -> SealedFile {
        SealedFile {
            path,
            key,
            no_sync,
            bytes: RwLock::new(bytes),
        }
    }

    /// Seal the whole database and write it in place of the last.
    pub fn save(&self) -> std::io::Result<()> {
        let sealed = seal_file(&self.key, &self.bytes.read().unwrap());
        write_in_place(&self.path, &sealed, self.no_sync)
    }
}

/// A [`SealedFile`] as redb's storage.
#[derive(Debug)]
pub struct Backend(pub Arc<SealedFile>);

fn out_of_range() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, "out of range")
}

impl redb::StorageBackend for Backend {
    fn len(&self) -> std::io::Result<u64> {
        Ok(self.0.bytes.read().unwrap().len() as u64)
    }

    fn read(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        let b = self.0.bytes.read().unwrap();
        let start = usize::try_from(offset).map_err(|_| out_of_range())?;
        let end = start.checked_add(len).ok_or_else(out_of_range)?;
        b.get(start..end).map(<[u8]>::to_vec).ok_or_else(out_of_range)
    }

    fn set_len(&self, len: u64) -> std::io::Result<()> {
        let len = usize::try_from(len).map_err(|_| out_of_range())?;
        let mut b = self.0.bytes.write().unwrap();
        if len <= b.len() {
            b[len..].zeroize();
            b.truncate(len);
        } else if len <= b.capacity() {
            b.resize(len, 0);
        } else {
            // Grow into a new allocation and wipe the old one, rather than leave a copy behind.
            let mut grown = Zeroizing::new(Vec::with_capacity(len.max(b.capacity() * 2)));
            grown.extend_from_slice(&b);
            grown.resize(len, 0);
            *b = grown;
        }
        Ok(())
    }

    fn sync_data(&self, _: bool) -> std::io::Result<()> {
        // Written out whole by the store after each commit instead.
        Ok(())
    }

    fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        let mut b = self.0.bytes.write().unwrap();
        let start = usize::try_from(offset).map_err(|_| out_of_range())?;
        let end = start.checked_add(data.len()).ok_or_else(out_of_range)?;
        b.get_mut(start..end).ok_or_else(out_of_range)?.copy_from_slice(data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_file_opens_only_with_its_key() {
        let s = seal_file(&[1; 32], b"hello");
        assert!(is_sealed(&s));
        assert_eq!(&*open_file(&[1; 32], &s).unwrap(), b"hello");
        assert!(open_file(&[2; 32], &s).is_none());
        assert!(open_file(&[1; 32], b"hello").is_none());
        let mut t = s.clone();
        *t.last_mut().unwrap() ^= 1;
        assert!(open_file(&[1; 32], &t).is_none());
    }
}
