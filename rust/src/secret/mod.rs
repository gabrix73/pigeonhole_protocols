//! Bytes that must not leak, such as the caps that let one read or write a stream and the keys
//! of a contact voucher.
//!
//! A [`Secret`] lives in memory of its own: between two inaccessible guard pages, so that
//! running off the end of a neighbouring buffer faults rather than reads it; locked out of swap
//! and left out of core dumps where the system allows; after a random canary that is checked when
//! it goes; and wiped when it is dropped. Copies made from it are secrets too. Should guarded
//! memory be refused, a secret falls back to the heap, and is still wiped when dropped.

use std::fmt;
use std::ops::Deref;
use std::ptr::NonNull;

use zeroize::Zeroize;

pub struct Secret(Store);

enum Store {
    Guarded(NonNull<[u8]>),
    Heap(Box<[u8]>),
}

// SAFETY: the guarded memory is owned by the Secret alone and never written after it is made.
unsafe impl Send for Secret {}
unsafe impl Sync for Secret {}

impl Secret {
    /// A secret holding a copy of `bytes`.
    pub fn new(bytes: &[u8]) -> Secret {
        // SAFETY: malloc_sized hands back `bytes.len()` writable bytes of its own, or nothing.
        match unsafe { memsec::malloc_sized(bytes.len()) } {
            Some(mut p) => {
                unsafe { p.as_mut() }.copy_from_slice(bytes);
                Secret(Store::Guarded(p))
            }
            None => Secret(Store::Heap(bytes.into())),
        }
    }

    /// Whether the bytes are in guarded memory.
    pub fn is_guarded(&self) -> bool {
        matches!(self.0, Store::Guarded(_))
    }
}

impl Deref for Secret {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match &self.0 {
            // SAFETY: the memory is ours until drop, and readable.
            Store::Guarded(p) => unsafe { p.as_ref() },
            Store::Heap(b) => b,
        }
    }
}

impl AsRef<[u8]> for Secret {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        match &mut self.0 {
            // SAFETY: allocated by memsec::malloc_sized; free wipes it, and aborts if its canary
            // was overwritten.
            Store::Guarded(p) => unsafe { memsec::free(*p) },
            Store::Heap(b) => b.zeroize(),
        }
    }
}

impl Clone for Secret {
    fn clone(&self) -> Secret {
        Secret::new(self)
    }
}

impl Default for Secret {
    fn default() -> Secret {
        Secret::new(&[])
    }
}

/// In constant time, for secrets of equal length.
impl PartialEq for Secret {
    fn eq(&self, other: &Secret) -> bool {
        self.len() == other.len()
            && unsafe { memsec::memeq(self.as_ptr(), other.as_ptr(), self.len()) }
    }
}

impl Eq for Secret {}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({} bytes)", self.len())
    }
}

impl From<&[u8]> for Secret {
    fn from(b: &[u8]) -> Secret {
        Secret::new(b)
    }
}

/// Takes the bytes into a secret, and wipes the vector they came in.
impl From<Vec<u8>> for Secret {
    fn from(mut v: Vec<u8>) -> Secret {
        let s = Secret::new(&v);
        v.zeroize();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holds_and_compares_its_bytes() {
        let a = Secret::from(vec![1u8, 2, 3]);
        assert!(a.is_guarded());
        assert_eq!(&*a, &[1, 2, 3]);
        assert_eq!(a.clone(), a);
        assert_ne!(Secret::new(&[1, 2, 4]), a);
        assert_ne!(Secret::new(&[1, 2]), a);
        assert_eq!(Secret::default().len(), 0);
    }

    #[test]
    fn never_shows_its_bytes() {
        assert_eq!(format!("{:?}", Secret::new(b"read cap")), "Secret(8 bytes)");
    }
}
