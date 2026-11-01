//! The X25519 and CTIDH-1024 hybrid NIKE that services, routers and
//! directories key themselves with, hpqc's `hybrid.X25519CTIDH1024`. Keys
//! are opaque bytes: the client daemon generates them and does every
//! operation with them, through [`Backend`].

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use crate::services::Error;
use crate::transport::{Backend, Secret};

/// The scheme's name, as hpqc spells it.
pub const SCHEME: &str = "X25519-CTIDH1024";

/// Size of a serialized public key: X25519's, then CTIDH-1024's.
pub const PUBLIC_KEY_SIZE: usize = 32 + 128;
/// Size of a serialized private key.
pub const PRIVATE_KEY_SIZE: usize = 32 + 130;

/// A hybrid public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    /// Decodes a public key. The daemon validates it when it is used.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() != PUBLIC_KEY_SIZE {
            return Err(Error::InvalidKey);
        }
        Ok(PublicKey(b.to_vec()))
    }

    /// Encodes the public key.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({:02x?}…)", &self.0[..4])
    }
}

/// A hybrid private key, in guarded memory.
#[derive(Clone)]
pub struct PrivateKey(Secret);

impl PrivateKey {
    /// Decodes a private key.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() != PRIVATE_KEY_SIZE {
            return Err(Error::InvalidKey);
        }
        Ok(PrivateKey(Secret::new(b)))
    }

    /// The private key's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Computes the shared secret with `peer`. A degenerate secret is an
    /// error.
    pub async fn derive_secret<B: Backend>(&self, ph: &B, peer: &PublicKey) -> Result<Secret, Error> {
        Ok(ph.nike_derive_secret(SCHEME, &self.0, &peer.0).await?)
    }
}

/// A keypair.
#[derive(Clone)]
pub struct Keypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl Keypair {
    /// Generates a keypair.
    pub async fn generate<B: Backend>(ph: &B) -> Result<Self, Error> {
        let (public, private) = ph.nike_generate_key_pair(SCHEME).await?;
        Ok(Keypair { public: PublicKey::from_bytes(&public)?, private: PrivateKey::from_bytes(&private)? })
    }

    /// Loads the keypair stored as `name.private.pem` and `name.public.pem`
    /// in `dir`, in hpqc's PEM format, or generates and stores one if
    /// neither file exists.
    pub async fn load_or_generate<B: Backend>(ph: &B, dir: &Path, name: &str) -> Result<Self, Error> {
        let priv_file = dir.join(format!("{name}.private.pem"));
        let pub_file = dir.join(format!("{name}.public.pem"));
        match (priv_file.exists(), pub_file.exists()) {
            (true, true) => {
                let private = PrivateKey::from_bytes(&read_pem(&priv_file, "PRIVATE KEY")?)?;
                let public = PublicKey::from_bytes(&read_pem(&pub_file, "PUBLIC KEY")?)?;
                // The daemon does the NIKE, so check the pair by deriving a
                // secret with a fresh key both ways.
                let probe = Keypair::generate(ph).await?;
                if private.derive_secret(ph, &probe.public).await?[..] != probe.private.derive_secret(ph, &public).await?[..] {
                    return Err(Error::Other(format!("{name} public key does not match its private key")));
                }
                Ok(Keypair { public, private })
            }
            (false, false) => {
                let kp = Keypair::generate(ph).await?;
                write_pem(&priv_file, "PRIVATE KEY", kp.private.as_bytes(), 0o600)?;
                write_pem(&pub_file, "PUBLIC KEY", &kp.public.to_bytes(), 0o644)?;
                Ok(kp)
            }
            _ => Err(Error::Other(format!("{name} key files must both exist or both be absent"))),
        }
    }
}

fn pem_label(kind: &str) -> String {
    format!("{} {kind}", SCHEME.to_uppercase())
}

fn read_pem(path: &Path, kind: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let text = Zeroizing::new(std::fs::read_to_string(path)?);
    let label = pem_label(kind);
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let body = text
        .split_once(&begin)
        .and_then(|(_, rest)| rest.split_once(&end))
        .map(|(body, _)| body)
        .ok_or_else(|| Error::Other(format!("{}: not a {label}", path.display())))?;
    let b64: Zeroizing<String> = Zeroizing::new(body.chars().filter(|c| !c.is_whitespace()).collect());
    Ok(Zeroizing::new(STANDARD.decode(b64.as_bytes()).map_err(|_| Error::InvalidKey)?))
}

fn write_pem(path: &Path, kind: &str, der: &[u8], mode: u32) -> Result<(), Error> {
    let label = pem_label(kind);
    let b64 = Zeroizing::new(STANDARD.encode(der));
    let mut out = Zeroizing::new(format!("-----BEGIN {label}-----\n"));
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    write_file(path, out.as_bytes(), mode)
}

#[cfg(unix)]
fn write_file(path: &Path, data: &[u8], mode: u32) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).open(path)?;
    f.write_all(data)?;
    Ok(f.sync_all()?)
}

#[cfg(not(unix))]
fn write_file(path: &Path, data: &[u8], _mode: u32) -> Result<(), Error> {
    Ok(std::fs::write(path, data)?)
}
