//! Pigeonhole boxes without IO: what the engine asks a transport for and gets back, the box
//! sizes, Katzenpost's padding, and, with the `bacap` feature, BACAP's sealing and opening of
//! boxes and hpqc's contact vouchers. A transport, such as `transport::reticulum_rs`, or firmware
//! carries the sealed boxes to a replica; `transport` re-exports the types.

use crate::prelude::*;
use crate::secret::Secret;

/// Box plaintext sizes by name: `mesh`, a writer's default on Reticulum, is
/// `reticulum_rs::mesh_box_size`, a write in one Link packet; `mixnet` is Katzenpost's. A group
/// can span meshes and mixnets joined by bridges, so a reader takes a box of any allowed size:
/// these, the writer's own and any configured extra, each within [`MIN_BOX_SIZE`] (a substream's I
/// box) and [`MAX_BOX_SIZE`]. Only the payload differs: box IDs and signatures are the same size.
pub const BOX_SIZES: [(&str, usize); 2] = [("mesh", 256), ("mixnet", 1549)];
pub const MIN_BOX_SIZE: usize = 141;
pub const MAX_BOX_SIZE: usize = 16384;

/// A named size, or a number of bytes, within the bounds.
pub fn box_size(size: &str) -> Option<usize> {
    BOX_SIZES
        .iter()
        .find(|(n, _)| *n == size)
        .map(|(_, s)| *s)
        .or_else(|| size.parse().ok())
        .filter(|n| (MIN_BOX_SIZE..=MAX_BOX_SIZE).contains(n))
}

/// The named sizes and `sizes`, smallest first; `None` when one is out of bounds.
pub fn allowed_sizes(sizes: &[usize]) -> Option<Vec<usize>> {
    let mut out: Vec<usize> = BOX_SIZES.iter().map(|(_, s)| *s).chain(sizes.iter().copied()).collect();
    if out.iter().any(|n| !(MIN_BOX_SIZE..=MAX_BOX_SIZE).contains(n)) {
        return None;
    }
    out.sort_unstable();
    out.dedup();
    Some(out)
}

/// The size a box of `n` bytes is written at: the writer's, or when `n` outgrows it, as a
/// voucher's box, which is never split, does, the smallest allowed size that holds it.
pub fn fit_size(allowed: &[usize], writer: usize, n: usize) -> Option<usize> {
    core::iter::once(writer).chain(allowed.iter().copied()).find(|s| n <= *s)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A write to a box that holds something else.
    BoxAlreadyExists,
    Closed,
    Other(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::BoxAlreadyExists => {
                write!(f, "transport: box already exists with other contents")
            }
            Error::Closed => write!(f, "transport: closed"),
            Error::Other(e) => write!(f, "transport: {e}"),
        }
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read {
    Data(Vec<u8>),
    NotFound,
    Tombstone,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keypair {
    pub write_cap: Secret,
    pub read_cap: Secret,
    /// The index the stream starts at.
    pub first: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Minted {
    pub voucher: Secret,
    /// Our name and read cap, for the member who adds us.
    pub payload: Secret,
    pub write_cap: Secret,
    pub read_cap: Secret,
    pub secret_key: Secret,
    /// The payload's form: 2 the compact array, answered by a sealed box framed over boxes 1 on;
    /// 1 the signed map, answered by an unframed reply in box 1 alone.
    pub version: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inducted {
    pub name: String,
    pub mutated_read_cap: Secret,
    pub sealed_reply: Vec<u8>,
    /// The form the payload was in and the reply is in; see [`Minted`].
    pub version: u8,
}

/// The form of a voucher payload: 1 for the map form, else 2.
pub fn voucher_version(payload: &[u8]) -> u8 {
    match payload.first() {
        Some(b) if b >> 5 == 5 => 1,
        _ => 2,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The read caps of the members we are to read.
    pub who_reply: Secret,
    pub mutated_write_cap: Secret,
}

/// Katzenpost's padding of a box's plaintext: its length as a big endian u32, the plaintext,
/// then zeros to `box_size + 4` bytes.
pub fn pad(plaintext: &[u8], box_size: usize) -> Result<Vec<u8>> {
    if plaintext.len() > box_size {
        return Err(Error::Other(format!(
            "message of {} bytes exceeds the box size {box_size}",
            plaintext.len()
        )));
    }
    let mut out = Vec::with_capacity(box_size + 4);
    out.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
    out.extend_from_slice(plaintext);
    out.resize(box_size + 4, 0);
    Ok(out)
}

/// The plaintext [`pad`] padded.
pub fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    let n = padded
        .get(..4)
        .map(|b| u32::from_be_bytes(b.try_into().unwrap()) as usize)
        .ok_or_else(|| Error::Other("padded box too short".into()))?;
    padded
        .get(4..4 + n)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| Error::Other("padded length exceeds the box".into()))
}

/// The plaintext [`pad`] padded, when the box is of one of `allowed` sizes.
pub fn unpad_allowed(padded: &[u8], allowed: &[usize]) -> Result<Vec<u8>> {
    if !allowed.contains(&padded.len().saturating_sub(4)) {
        return Err(Error::Other(format!("a box of {} bytes, not an allowed size", padded.len().saturating_sub(4))));
    }
    unpad(padded)
}

#[cfg(feature = "bacap")]
pub use bacap::*;

#[cfg(feature = "bacap")]
mod bacap {
    use hpqc::bacap::{BOX_ID_SIZE, MessageBoxIndex, ReadCap, SIGNATURE_SIZE, WriteCap};
    use hpqc::rand_core::CryptoRng;
    use hpqc::voucher::{self, VOUCHER_SIZE, VoucherStream};

    use super::*;

    /// The BACAP context of Pigeonhole boxes, shared with Katzenpost clients.
    pub const CONTEXT: &[u8] = b"pigeonhole context";

    /// A box ready to write: its ID, its signature, and its ciphertext, empty for a tombstone.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SealedBox {
        pub box_id: [u8; BOX_ID_SIZE],
        pub signature: [u8; SIGNATURE_SIZE],
        pub ciphertext: Vec<u8>,
    }

    fn other(e: impl core::fmt::Display) -> Error {
        Error::Other(format!("bacap: {e}"))
    }

    /// A new stream: its caps, and the index it starts at.
    pub fn new_keypair(rng: &mut dyn CryptoRng) -> Keypair {
        let wc = WriteCap::generate(rng);
        let rc = wc.read_cap().to_bytes();
        Keypair { write_cap: Secret::new(&wc.to_bytes()), read_cap: Secret::new(&rc), first: rc[32..].to_vec() }
    }

    /// Seals `plaintext` into the box at `index`, padded to the writer's size `writer` or, when it
    /// outgrows that, the smallest of `allowed` that holds it ([`fit_size`]); an empty plaintext
    /// is a tombstone.
    pub fn seal(write_cap: &[u8], index: &[u8], plaintext: &[u8], allowed: &[usize], writer: usize) -> Result<SealedBox> {
        let wc = WriteCap::from_bytes(write_cap).map_err(other)?;
        let idx = MessageBoxIndex::from_bytes(index).map_err(other)?;
        let pos = wc.position_at(&idx).map_err(other)?;
        let (box_id, ciphertext, signature) = if plaintext.is_empty() {
            let (b, s) = pos.tombstone(CONTEXT).map_err(other)?;
            (b, Vec::new(), s)
        } else {
            let size = fit_size(allowed, writer, plaintext.len())
                .ok_or_else(|| Error::Other(format!("a box of {} bytes exceeds every allowed size", plaintext.len())))?;
            pos.encrypt(CONTEXT, &pad(plaintext, size)?).map_err(other)?
        };
        Ok(SealedBox { box_id, signature, ciphertext })
    }

    /// The ID of the box at `index` on the stream `read_cap` reads, which a replica stores it by.
    pub fn box_id(read_cap: &[u8], index: &[u8]) -> Result<[u8; BOX_ID_SIZE]> {
        let rc = ReadCap::from_bytes(read_cap).map_err(other)?;
        let idx = MessageBoxIndex::from_bytes(index).map_err(other)?;
        rc.position_at(&idx).map_err(other)?.box_id(CONTEXT).map_err(other)
    }

    /// Verifies and decrypts the box at `index` a replica returned, and unpads it when it is of
    /// one of `allowed` sizes: [`Read::Data`], or [`Read::Tombstone`] for an empty box.
    pub fn open(read_cap: &[u8], index: &[u8], ciphertext: &[u8], signature: &[u8], allowed: &[usize]) -> Result<Read> {
        let rc = ReadCap::from_bytes(read_cap).map_err(other)?;
        let idx = MessageBoxIndex::from_bytes(index).map_err(other)?;
        let pos = rc.position_at(&idx).map_err(other)?;
        let box_id = pos.box_id(CONTEXT).map_err(other)?;
        let opened = pos.open(CONTEXT, &box_id, ciphertext, signature).map_err(other)?;
        if opened.is_empty() {
            return Ok(Read::Tombstone);
        }
        Ok(Read::Data(unpad_allowed(&opened, allowed)?))
    }

    /// Mints a voucher for the stream `write_cap` writes, its payload in `form`: 2 the compact
    /// array, 1 the signed map.
    pub fn voucher_mint(write_cap: &[u8], name: &str, form: u8, rng: &mut dyn CryptoRng) -> Result<Minted> {
        let wc = WriteCap::from_bytes(write_cap).map_err(other)?;
        let m = if form == 1 { voucher::mint_long(&wc, name, rng) } else { voucher::mint_compact(&wc, name, rng) };
        Ok(Minted {
            voucher: Secret::new(&m.voucher),
            payload: Secret::new(&m.payload),
            write_cap: Secret::new(&m.stream.write_cap.to_bytes()),
            read_cap: Secret::new(&m.stream.read_cap.to_bytes()),
            secret_key: Secret::new(&m.secret_key),
            version: m.form.version(),
        })
    }

    /// The voucher stream's write cap and read cap.
    pub fn voucher_derive_stream(v: &[u8]) -> Result<(Secret, Secret)> {
        let s = VoucherStream::derive(&voucher_bytes(v)?);
        Ok((Secret::new(&s.write_cap.to_bytes()), Secret::new(&s.read_cap.to_bytes())))
    }

    /// Inducts the joiner whose voucher is `v` and whose payload is `payload`, sealing `who_reply`
    /// to it.
    pub fn voucher_induct(v: &[u8], payload: &[u8], who_reply: &[u8], rng: &mut dyn CryptoRng) -> Result<Inducted> {
        let r = voucher::induct(&voucher_bytes(v)?, payload, who_reply, rng).map_err(other)?;
        Ok(Inducted {
            name: r.display_name,
            mutated_read_cap: Secret::new(&r.mutated_read_cap.to_bytes()),
            sealed_reply: r.sealed_reply,
            version: r.form.version(),
        })
    }

    /// Opens the reply sealed to the voucher's `secret_key`, for the stream `write_cap` writes.
    pub fn voucher_open(secret_key: &[u8], sealed_reply: &[u8], write_cap: &[u8]) -> Result<Opened> {
        let wc = WriteCap::from_bytes(write_cap).map_err(other)?;
        let r = voucher::open_reply(secret_key, sealed_reply, &wc).map_err(other)?;
        Ok(Opened {
            who_reply: Secret::new(&r.who_reply),
            mutated_write_cap: Secret::new(&r.mutated_write_cap.to_bytes()),
        })
    }

    fn voucher_bytes(v: &[u8]) -> Result<[u8; VOUCHER_SIZE]> {
        v.try_into().map_err(|_| Error::Other("voucher is not 32 bytes".into()))
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn seal_open_and_vouchers() {
            let rng = &mut hpqc::voucher::ShakeRng::new(b"boxes");
            let k = new_keypair(rng);
            let allowed = allowed_sizes(&[]).unwrap();
            for p in [&b"hi"[..], &[7; 300]] {
                let b = seal(&k.write_cap, &k.first, p, &allowed, 256).unwrap();
                assert_eq!(b.box_id, box_id(&k.read_cap, &k.first).unwrap());
                assert_eq!(open(&k.read_cap, &k.first, &b.ciphertext, &b.signature, &allowed), Ok(Read::Data(p.to_vec())));
                assert!(open(&k.read_cap, &k.first, &b.ciphertext, &b.signature, &[256]).is_err() == (p.len() > 256));
            }
            assert!(seal(&k.write_cap, &k.first, &[], &allowed, 256).unwrap().ciphertext.is_empty());
            assert!(seal(&k.write_cap, &k.first, &[0; 1550], &allowed, 256).is_err());

            let m = voucher_mint(&k.write_cap, "alice", 2, rng).unwrap();
            assert_eq!(voucher_derive_stream(&m.voucher).unwrap(), (m.write_cap.clone(), m.read_cap.clone()));
            let i = voucher_induct(&m.voucher, &m.payload, b"who", rng).unwrap();
            assert_eq!((i.name.as_str(), i.version), ("alice", 2));
            let o = voucher_open(&m.secret_key, &i.sealed_reply, &k.write_cap).unwrap();
            assert_eq!(&*o.who_reply, b"who");
        }
    }
}
