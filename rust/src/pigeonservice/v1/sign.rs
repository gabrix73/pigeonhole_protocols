//! The signatures v1 requests carry: proof that the sender holds the private key of the public
//! key it registers.
//!
//! ```text
//! sig = Sign(sk, "pigeonservice-v1-sig" || 0x00 || ctx || 0x00 || canonical CBOR of the request without Signature)
//! ```
//!
//! `ctx` names the request type, so a signature for one cannot pass as another. The request
//! names the registrar it is for, the time it was made and a revision above the last, so it
//! cannot be replayed at another plugin, later, or after a newer one.
//!
//! The scheme is meant to be hpqc's hybrid `Falcon-padded-512-Ed25519`, both halves required.
//! hpqc's Rust crate has no Falcon yet (its `sign::schemes` has Ed25519, ML-DSA and their
//! hybrids, and ML-DSA's signatures do not fit a Sphinx packet), so [`Scheme`] is Ed25519 for
//! now. TODO: when hpqc's Rust crate gains Falcon-padded-512 and its `Falcon-padded-512-Ed25519`
//! hybrid, implement [`SignScheme`] for [`FalconPadded512Ed25519`] over it and make it
//! [`Scheme`]; the size checks in [`super::size`] already hold for it where it fits.

use crate::pigeonservice::Error;
use crate::pigeonservice::cbor::{self, Value};

const LABEL: &[u8] = b"pigeonservice-v1-sig";

/// The sizes of a signature scheme, all the size checks need.
pub trait Sizes {
    /// The scheme's name, as hpqc spells it.
    const NAME: &'static str;
    const PUBLIC_KEY: usize;
    const SIGNATURE: usize;
}

/// A signature scheme v1 can sign with.
pub trait SignScheme: Sizes {
    type SigningKey: Clone + Send + Sync;
    /// The length of a seed [`SignScheme::from_seed`] takes.
    const SEED: usize;
    fn from_seed(seed: &[u8]) -> Result<Self::SigningKey, Error>;
    fn public_key(sk: &Self::SigningKey) -> Vec<u8>;
    fn sign(sk: &Self::SigningKey, msg: &[u8]) -> Vec<u8>;
    fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error>;
}

/// Ed25519, as RFC 8032, verified strictly.
pub struct Ed25519;

impl Sizes for Ed25519 {
    const NAME: &'static str = "Ed25519";
    const PUBLIC_KEY: usize = 32;
    const SIGNATURE: usize = 64;
}

impl SignScheme for Ed25519 {
    type SigningKey = ed25519_dalek::SigningKey;
    const SEED: usize = 32;

    fn from_seed(seed: &[u8]) -> Result<Self::SigningKey, Error> {
        Ok(ed25519_dalek::SigningKey::from_bytes(seed.try_into().map_err(|_| Error::InvalidKey)?))
    }

    fn public_key(sk: &Self::SigningKey) -> Vec<u8> {
        sk.verifying_key().to_bytes().to_vec()
    }

    fn sign(sk: &Self::SigningKey, msg: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        sk.sign(msg).to_bytes().to_vec()
    }

    fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let pk = ed25519_dalek::VerifyingKey::from_bytes(public_key.try_into().map_err(|_| Error::BadSignature)?)
            .map_err(|_| Error::BadSignature)?;
        let sig = ed25519_dalek::Signature::from_slice(sig).map_err(|_| Error::BadSignature)?;
        pk.verify_strict(msg, &sig).map_err(|_| Error::BadSignature)
    }
}

/// hpqc's `hybrid.FalconPadded512Ed25519`: keys and signatures are Falcon's then Ed25519's, and a
/// signature verifies only if both halves do. Sizes only, until hpqc's Rust crate has Falcon.
pub struct FalconPadded512Ed25519;

impl Sizes for FalconPadded512Ed25519 {
    const NAME: &'static str = "Falcon-padded-512-Ed25519";
    const PUBLIC_KEY: usize = 897 + 32;
    const SIGNATURE: usize = 666 + 64;
}

/// The scheme v1 signs with.
pub type Scheme = Ed25519;

/// A service's signing key.
#[derive(Clone)]
pub struct Identity(<Scheme as SignScheme>::SigningKey);

impl Identity {
    /// A fresh key.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = zeroize::Zeroizing::new(vec![0u8; Scheme::SEED]);
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Identity::from_seed(&seed).expect("seed of the scheme's length")
    }

    /// The key a seed derives, deterministically.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        Ok(Identity(Scheme::from_seed(seed)?))
    }

    pub fn public_key(&self) -> Vec<u8> {
        Scheme::public_key(&self.0)
    }

    /// Signs `body`, a request without its signature, as a `ctx` request.
    pub fn sign(&self, ctx: &str, body: &Value) -> Vec<u8> {
        Scheme::sign(&self.0, &message(ctx, body))
    }
}

/// Checks `sig` over `body` as a `ctx` request by the holder of `public_key`.
pub fn verify(public_key: &[u8], ctx: &str, body: &Value, sig: &[u8]) -> Result<(), Error> {
    Scheme::verify(public_key, &message(ctx, body), sig)
}

/// What is signed.
pub fn message(ctx: &str, body: &Value) -> Vec<u8> {
    [LABEL, &[0], ctx.as_bytes(), &[0], &cbor::encode(body)].concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let id = Identity::from_seed(&[7; 32]).unwrap();
        let body = cbor::map(vec![("Revision", cbor::uint(1))]);
        let sig = id.sign("register", &body);
        assert_eq!(sig.len(), Scheme::SIGNATURE);
        assert_eq!(id.public_key().len(), Scheme::PUBLIC_KEY);
        verify(&id.public_key(), "register", &body, &sig).unwrap();
        assert!(verify(&id.public_key(), "renew", &body, &sig).is_err(), "ctx separates request types");
        let other = cbor::map(vec![("Revision", cbor::uint(2))]);
        assert!(verify(&id.public_key(), "register", &other, &sig).is_err());
        let mut bad = sig.clone();
        bad[0] ^= 1;
        assert!(verify(&id.public_key(), "register", &body, &bad).is_err());
        assert!(verify(&Identity::generate().public_key(), "register", &body, &sig).is_err());
        assert!(verify(&id.public_key(), "register", &body, &sig[1..]).is_err());
    }
}
