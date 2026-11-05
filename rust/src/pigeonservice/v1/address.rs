//! A service's address: who it is, as text a person can pass on.
//!
//! ```text
//! address  = base32(version || id || checksum)       56 characters, RFC 4648, lower case, no padding
//! version  = 1
//! id       = BLAKE2b-256(public key)                 the Falcon-padded-512-Ed25519 key, 929 B
//! checksum = BLAKE2b-256("pigeonservice address checksum" || version || id)[..2]
//! lookup   = BLAKE2b-256("pigeonservice-v1-lookup" || 0x00 || id || u64be(period))
//! period   = unix time / 86400
//! ```
//!
//! The id is what routers route vouchers by and directories file descriptors under. The key
//! itself is in the service's descriptor, which a client checks against the address. A client
//! resolves an address at a directory by its lookup for the current period, so the request does
//! not carry the address and lookups in different periods do not match.

use std::fmt;
use std::str::FromStr;

use blake2::{Blake2b, Digest, digest::consts::U32};

use crate::pigeonservice::Error;
use crate::pigeonservice::v0::wire::ServiceId;

pub const VERSION: u8 = 1;
/// The length of an address as text.
pub const LEN: usize = 56;
/// How long a lookup holds.
pub const PERIOD: u64 = 24 * 3600;

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const RAW: usize = 1 + 32 + 2;

/// A service's address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(pub ServiceId);

impl Address {
    /// The address of the service with `public_key`.
    pub fn of(public_key: &[u8]) -> Self {
        Address(ServiceId::from_public_key(public_key))
    }

    /// Checks that `public_key` is this address's.
    pub fn verify(&self, public_key: &[u8]) -> Result<(), Error> {
        if Address::of(public_key) != *self {
            return Err(Error::BadAddress("the key is another service's".into()));
        }
        Ok(())
    }

    /// The lookup a directory files the service under in `period`.
    pub fn lookup(&self, period: u64) -> [u8; 32] {
        Blake2b::<U32>::new()
            .chain_update(b"pigeonservice-v1-lookup\0")
            .chain_update(self.0.0)
            .chain_update(period.to_be_bytes())
            .finalize()
            .into()
    }

    fn checksum(version: u8, id: &[u8]) -> [u8; 2] {
        let h = Blake2b::<U32>::new().chain_update(b"pigeonservice address checksum").chain_update([version]).chain_update(id).finalize();
        [h[0], h[1]]
    }
}

/// The lookup period of Unix time `t`.
pub fn period(t: u64) -> u64 {
    t / PERIOD
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = [&[VERSION][..], &self.0.0, &Address::checksum(VERSION, &self.0.0)].concat();
        let (mut acc, mut bits) = (0u32, 0);
        for b in raw {
            acc = (acc << 8 | b as u32) & 0xfff;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                write!(f, "{}", ALPHABET[(acc >> bits) as usize & 31] as char)?;
            }
        }
        Ok(())
    }
}

impl FromStr for Address {
    type Err = Error;

    /// Parses an address, in either case.
    fn from_str(s: &str) -> Result<Self, Error> {
        if s.len() != LEN {
            return Err(Error::BadAddress(format!("{} characters, not {LEN}", s.len())));
        }
        let mut raw = [0u8; RAW];
        let (mut acc, mut bits, mut n) = (0u32, 0, 0);
        for c in s.bytes() {
            let v = ALPHABET.iter().position(|&a| a == c.to_ascii_lowercase()).ok_or_else(|| Error::BadAddress(format!("{:?} is not base32", c as char)))?;
            acc = (acc << 5 | v as u32) & 0xfff;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                raw[n] = (acc >> bits) as u8;
                n += 1;
            }
        }
        if raw[0] != VERSION {
            return Err(Error::BadAddress(format!("version {}; this client reads version {VERSION}", raw[0])));
        }
        if raw[33..] != Address::checksum(raw[0], &raw[1..33]) {
            return Err(Error::BadAddress("the checksum does not match: is it mistyped?".into()));
        }
        Ok(Address(ServiceId(raw[1..33].try_into().unwrap())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text() {
        let a = Address::of(b"some key");
        let s = a.to_string();
        assert_eq!(s.len(), LEN);
        assert!(s.starts_with('a') && (b'e'..=b'h').contains(&s.as_bytes()[1]), "{s}: version 1 leads");
        assert_eq!(s.parse::<Address>().unwrap(), a);
        assert_eq!(s.to_uppercase().parse::<Address>().unwrap(), a);
        a.verify(b"some key").unwrap();
        assert!(matches!(a.verify(b"other key"), Err(Error::BadAddress(_))));

        // Every single-character change is caught.
        for i in 0..LEN {
            let mut t = s.clone().into_bytes();
            t[i] = if t[i] == b'a' { b'b' } else { b'a' };
            assert!(String::from_utf8(t).unwrap().parse::<Address>().is_err(), "position {i}");
        }
        assert!(s[1..].parse::<Address>().is_err());
        assert!(format!("{}1", &s[1..]).parse::<Address>().is_err(), "1 is not base32");
        let Err(Error::BadAddress(e)) = format!("aa{}", &s[2..]).parse::<Address>() else { panic!() };
        assert!(e.starts_with("version 0"), "{e}");
    }

    #[test]
    fn lookups() {
        let a = Address::of(b"some key");
        assert_ne!(a.lookup(1), a.lookup(2));
        assert_ne!(a.lookup(1), Address::of(b"other key").lookup(1));
        assert_ne!(a.lookup(1), a.0.0);
        assert_eq!(period(PERIOD * 5 + 7), 5);
    }
}
