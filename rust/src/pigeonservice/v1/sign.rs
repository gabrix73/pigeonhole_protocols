//! The signatures v1 carries: proof that the sender holds the private key of the public key it
//! names.
//!
//! ```text
//! sig = Sign(sk, "pigeonservice-v1-sig" || 0x00 || ctx || 0x00 || canonical CBOR of the body without Signature)
//! ```
//!
//! `ctx` names the message type, so a signature for one cannot pass as another. A request names
//! the registrar it is for, the time it was made and a revision above the last, so it cannot be
//! replayed at another plugin, later, or after a newer one.
//!
//! The scheme is hpqc's hybrid `Falcon-padded-512-Ed25519`: the key and the signature are
//! Falcon-padded-512's then Ed25519's, both halves sign the same message, and a signature verifies
//! only if both do. Falcon here is falcon-rs's port of the Falcon reference code, which reads and
//! writes the keys and signatures of katzenpost/falcon (PQClean), the Go side's, byte for byte.
//!
//! Falcon signing is deterministic, as Ed25519's is: its random generator is seeded with SHAKE256
//! of a label, the private key and the message, and falcon-rs emulates floating point, so a key
//! and a message give one signature on every platform. Two different signatures of one message
//! under one nonce would leak the key; one signature cannot.

use falcon::falcon as fr;
use falcon::shake::InnerShake256Context;
use zeroize::Zeroizing;

use crate::pigeonservice::Error;
use crate::pigeonservice::cbor::{self, Value};
use crate::pigeonservice::v1::address::Address;

const LABEL: &[u8] = b"pigeonservice-v1-sig";
const FALCON_SIGN_LABEL: &[u8] = b"pigeonservice-v1 falcon sign";

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

const LOGN: u32 = 9;
const FALCON_PUBLIC_KEY: usize = fr::falcon_pubkey_size(LOGN);
const FALCON_PRIVATE_KEY: usize = fr::falcon_privkey_size(LOGN);
const FALCON_SIGNATURE: usize = fr::falcon_sig_padded_size(LOGN);
const _: () = assert!(FALCON_PUBLIC_KEY == 897 && FALCON_PRIVATE_KEY == 1281 && FALCON_SIGNATURE == 666);

/// hpqc's `hybrid.FalconPadded512Ed25519`: keys and signatures are Falcon-padded-512's then
/// Ed25519's, and a signature verifies only if both halves do.
pub struct FalconPadded512Ed25519;

/// A [`FalconPadded512Ed25519`] private key.
#[derive(Clone)]
pub struct HybridKey {
    falcon: Zeroizing<Vec<u8>>,
    falcon_public: Vec<u8>,
    ed25519: ed25519_dalek::SigningKey,
}

impl Sizes for FalconPadded512Ed25519 {
    const NAME: &'static str = "Falcon-padded-512-Ed25519";
    const PUBLIC_KEY: usize = FALCON_PUBLIC_KEY + Ed25519::PUBLIC_KEY;
    const SIGNATURE: usize = FALCON_SIGNATURE + Ed25519::SIGNATURE;
}

fn falcon_verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let mut tmp = vec![0u8; fr::falcon_tmpsize_verify(LOGN)];
    sig.len() == FALCON_SIGNATURE && fr::falcon_verify(sig, fr::FALCON_SIG_PADDED, public_key, msg, &mut tmp) == 0
}

impl FalconPadded512Ed25519 {
    /// The key hpqc encodes as Falcon's private key (1281 B), then Ed25519's seed and public key.
    pub fn key_from_bytes(b: &[u8]) -> Result<HybridKey, Error> {
        if b.len() != FALCON_PRIVATE_KEY + 64 {
            return Err(Error::InvalidKey);
        }
        let mut falcon_public = vec![0u8; FALCON_PUBLIC_KEY];
        let mut tmp = Zeroizing::new(vec![0u8; fr::falcon_tmpsize_makepub(LOGN)]);
        if fr::falcon_make_public(&mut falcon_public, &b[..FALCON_PRIVATE_KEY], &mut tmp) != 0 {
            return Err(Error::InvalidKey);
        }
        let ed25519 = Ed25519::from_seed(&b[FALCON_PRIVATE_KEY..FALCON_PRIVATE_KEY + 32])?;
        if ed25519.verifying_key().as_bytes()[..] != b[FALCON_PRIVATE_KEY + 32..] {
            return Err(Error::InvalidKey);
        }
        Ok(HybridKey { falcon: Zeroizing::new(b[..FALCON_PRIVATE_KEY].to_vec()), falcon_public, ed25519 })
    }
}

impl SignScheme for FalconPadded512Ed25519 {
    type SigningKey = HybridKey;
    /// Falcon's key generator seed, then Ed25519's, split as hpqc splits a hybrid seed.
    const SEED: usize = 32 + Ed25519::SEED;

    fn from_seed(seed: &[u8]) -> Result<HybridKey, Error> {
        if seed.len() != Self::SEED {
            return Err(Error::InvalidKey);
        }
        let mut rng = InnerShake256Context::new();
        fr::shake256_init_prng_from_seed(&mut rng, &seed[..32]);
        let mut falcon = Zeroizing::new(vec![0u8; FALCON_PRIVATE_KEY]);
        let mut falcon_public = vec![0u8; FALCON_PUBLIC_KEY];
        let mut tmp = Zeroizing::new(vec![0u8; fr::falcon_tmpsize_keygen(LOGN)]);
        if fr::falcon_keygen_make(&mut rng, LOGN, &mut falcon, Some(&mut falcon_public), &mut tmp) != 0 {
            return Err(Error::Crypto);
        }
        Ok(HybridKey { falcon, falcon_public, ed25519: Ed25519::from_seed(&seed[32..])? })
    }

    fn public_key(sk: &HybridKey) -> Vec<u8> {
        [&sk.falcon_public[..], sk.ed25519.verifying_key().as_bytes()].concat()
    }

    fn sign(sk: &HybridKey, msg: &[u8]) -> Vec<u8> {
        let mut rng = InnerShake256Context::new();
        fr::shake256_init(&mut rng);
        fr::shake256_inject(&mut rng, FALCON_SIGN_LABEL);
        fr::shake256_inject(&mut rng, &sk.falcon);
        fr::shake256_inject(&mut rng, msg);
        fr::shake256_flip(&mut rng);
        let mut sig = vec![0u8; FALCON_SIGNATURE];
        let mut len = sig.len();
        let mut tmp = Zeroizing::new(vec![0u8; fr::falcon_tmpsize_signdyn(LOGN)]);
        let rc = fr::falcon_sign_dyn(&mut rng, &mut sig, &mut len, fr::FALCON_SIG_PADDED, &sk.falcon, msg, &mut tmp);
        // A signature from a faulty computation can leak the key: never hand one out.
        assert!(rc == 0 && len == FALCON_SIGNATURE && falcon_verify(&sk.falcon_public, msg, &sig), "Falcon signing failed");
        sig.extend(Ed25519::sign(&sk.ed25519, msg));
        sig
    }

    fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        if public_key.len() != Self::PUBLIC_KEY || sig.len() != Self::SIGNATURE {
            return Err(Error::BadSignature);
        }
        if !falcon_verify(&public_key[..FALCON_PUBLIC_KEY], msg, &sig[..FALCON_SIGNATURE]) {
            return Err(Error::BadSignature);
        }
        Ed25519::verify(&public_key[FALCON_PUBLIC_KEY..], msg, &sig[FALCON_SIGNATURE..])
    }
}

/// The scheme v1 signs with.
pub type Scheme = FalconPadded512Ed25519;

/// A service's signing key.
#[derive(Clone)]
pub struct Identity(<Scheme as SignScheme>::SigningKey);

impl Identity {
    /// A fresh key.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = Zeroizing::new(vec![0u8; Scheme::SEED]);
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Identity::from_seed(&seed).expect("seed of the scheme's length")
    }

    /// The key a seed of [`SignScheme::SEED`] bytes derives, deterministically: what a service
    /// keeps to keep its address.
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        Ok(Identity(Scheme::from_seed(seed)?))
    }

    /// A key in hpqc's encoding, as Go writes it.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(Identity(Scheme::key_from_bytes(b)?))
    }

    pub fn public_key(&self) -> Vec<u8> {
        Scheme::public_key(&self.0)
    }

    pub fn address(&self) -> Address {
        Address::of(&self.public_key())
    }

    /// Signs `body`, a message without its signature, as a `ctx` message.
    pub fn sign(&self, ctx: &str, body: &Value) -> Vec<u8> {
        Scheme::sign(&self.0, &message(ctx, body))
    }
}

/// Checks `sig` over `body` as a `ctx` message by the holder of `public_key`.
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

    fn seed(b: u8) -> Vec<u8> {
        vec![b; Scheme::SEED]
    }

    #[test]
    fn sign_and_verify() {
        let id = Identity::from_seed(&seed(7)).unwrap();
        let body = cbor::map(vec![("Revision", cbor::uint(1))]);
        let sig = id.sign("register", &body);
        assert_eq!(sig.len(), Scheme::SIGNATURE);
        assert_eq!(id.public_key().len(), Scheme::PUBLIC_KEY);
        verify(&id.public_key(), "register", &body, &sig).unwrap();
        assert_eq!(sig, id.sign("register", &body), "deterministic");
        assert_eq!(Identity::from_seed(&seed(7)).unwrap().public_key(), id.public_key(), "a seed gives one key");
        assert!(verify(&id.public_key(), "renew", &body, &sig).is_err(), "ctx separates message types");
        let other = cbor::map(vec![("Revision", cbor::uint(2))]);
        assert!(verify(&id.public_key(), "register", &other, &sig).is_err());
        assert_ne!(id.sign("register", &other)[1..41], sig[1..41], "another message, another Falcon nonce");
        assert!(verify(&Identity::from_seed(&seed(8)).unwrap().public_key(), "register", &body, &sig).is_err());
        assert!(verify(&id.public_key(), "register", &body, &sig[1..]).is_err());
        assert!(Identity::from_seed(&[7; 32]).is_err(), "a seed of the wrong length");
    }

    /// Both halves must verify: neither a classical nor a post-quantum forgery alone passes.
    #[test]
    fn both_halves_are_required() {
        let (a, b) = (Identity::from_seed(&seed(1)).unwrap(), Identity::from_seed(&seed(2)).unwrap());
        let body = cbor::map(vec![("Revision", cbor::uint(1))]);
        let (sa, sb) = (a.sign("x", &body), b.sign("x", &body));
        let mut bad_falcon = sa.clone();
        bad_falcon[100] ^= 1;
        assert!(verify(&a.public_key(), "x", &body, &bad_falcon).is_err());
        let mut bad_ed = sa.clone();
        bad_ed[FALCON_SIGNATURE + 3] ^= 1;
        assert!(verify(&a.public_key(), "x", &body, &bad_ed).is_err());
        // a's Falcon half with b's Ed25519 half, under a key of the same mix.
        let mixed_key = [&a.public_key()[..FALCON_PUBLIC_KEY], &b.public_key()[FALCON_PUBLIC_KEY..]].concat();
        let mixed_sig = [&sa[..FALCON_SIGNATURE], &sb[FALCON_SIGNATURE..]].concat();
        verify(&mixed_key, "x", &body, &mixed_sig).unwrap();
        assert!(verify(&a.public_key(), "x", &body, &mixed_sig).is_err(), "a's key needs a's Ed25519 half");
        assert!(verify(&b.public_key(), "x", &body, &mixed_sig).is_err(), "b's key needs b's Falcon half");
    }

    /// katzenpost/falcon and hpqc, in Go, read what this writes and write what this reads.
    #[test]
    fn go_interop() {
        let v: serde_json::Value = serde_json::from_str(include_str!("../../../../testdata/pigeonservice/v1/falcon_go.json")).unwrap();
        for v in v["vectors"].as_array().unwrap() {
            let h = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
            let (pk, sk, msg, sig) = (h("public_key_hex"), h("private_key_hex"), h("message_hex"), h("signature_hex"));
            Scheme::verify(&pk, &msg, &sig).unwrap();
            let id = Identity::from_bytes(&sk).unwrap();
            assert_eq!(id.public_key(), pk, "the public key from Go's private key");
            let ours = Scheme::sign(&id.0, &msg);
            assert_ne!(ours, sig, "Go's Falcon signing is randomized");
            Scheme::verify(&pk, &msg, &ours).unwrap();
            let mut short = sk.clone();
            short.pop();
            assert!(Identity::from_bytes(&short).is_err());
        }
    }
}
