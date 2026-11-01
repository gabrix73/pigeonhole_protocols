//! What a protocol asks of Pigeonhole: boxes on streams, the contact vouchers a peer joins
//! through, and requests to the mixnet services that run on service nodes. Caps and indexes are
//! BACAP's binary forms; a client steps from one index to the next itself, by BACAP.

pub use crate::secret::Secret;
use std::collections::BTreeMap;
use std::future::Future;

pub mod remote;
pub mod sim;
pub mod thinclient;

use std::sync::Arc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A write to a box that holds something else.
    BoxAlreadyExists,
    Closed,
    Other(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BoxAlreadyExists => {
                write!(f, "transport: box already exists with other contents")
            }
            Error::Closed => write!(f, "transport: closed"),
            Error::Other(e) => write!(f, "transport: {e}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inducted {
    pub name: String,
    pub mutated_read_cap: Secret,
    pub sealed_reply: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The read caps of the members we are to read.
    pub who_reply: Secret,
    pub mutated_write_cap: Secret,
}

/// One instance of a mixnet service in the PKI.
#[derive(Clone, Debug, PartialEq)]
pub struct ServiceNode {
    /// The hash of the service node's identity key.
    pub node_id_hash: [u8; 32],
    /// The service's endpoint on that node.
    pub endpoint: Vec<u8>,
    /// What the service publishes in the PKI.
    pub params: BTreeMap<String, serde_cbor::Value>,
}

/// Pigeonhole's storage, and contact vouchers: a joiner mints one for its stream, an existing
/// member inducts it with a sealed reply, and the joiner opens the reply. Every call may fail; a
/// caller that must succeed retries.
pub trait Backend: Send + Sync + 'static {
    fn new_keypair(&self) -> impl Future<Output = Result<Keypair>> + Send;
    /// Write `plaintext` to the box at `index`; an empty plaintext is a tombstone. Writing again
    /// what a box holds succeeds; writing anything else is [`Error::BoxAlreadyExists`].
    fn write_box(
        &self,
        write_cap: &[u8],
        index: &[u8],
        plaintext: &[u8],
    ) -> impl Future<Output = Result<()>> + Send;
    /// Read the box at `index`, reporting at once a box not written.
    fn read_box(&self, read_cap: &[u8], index: &[u8]) -> impl Future<Output = Result<Read>> + Send;
    /// The storage replicas' current epoch.
    fn replica_epoch(&self) -> impl Future<Output = Result<u64>> + Send;
    /// The most a box holds.
    fn max_plaintext(&self) -> impl Future<Output = Result<usize>> + Send;
    fn voucher_mint(
        &self,
        write_cap: &[u8],
        name: &str,
    ) -> impl Future<Output = Result<Minted>> + Send;
    /// The voucher stream's write cap and read cap.
    fn voucher_derive_stream(
        &self,
        voucher: &[u8],
    ) -> impl Future<Output = Result<(Secret, Secret)>> + Send;
    fn voucher_induct(
        &self,
        voucher: &[u8],
        payload: &[u8],
        who_reply: &[u8],
    ) -> impl Future<Output = Result<Inducted>> + Send;
    fn voucher_open(
        &self,
        secret_key: &[u8],
        sealed_reply: &[u8],
        write_cap: &[u8],
    ) -> impl Future<Output = Result<Opened>> + Send;
    /// Send `payload` to the mixnet service at `endpoint` on the node `node`, and return its
    /// reply, retransmitting until one comes. A service must therefore treat a repeated request
    /// as one. A transport without mixnet services fails.
    fn request(
        &self,
        _node: &[u8; 32],
        _endpoint: &[u8],
        _payload: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>>> + Send {
        async { Err(Error::Other("no mixnet services over this transport".into())) }
    }
    /// The instances of the mixnet service `capability` in the PKI.
    fn services(&self, _capability: &str) -> impl Future<Output = Result<Vec<ServiceNode>>> + Send {
        async { Ok(Vec::new()) }
    }
    /// A keypair for the NIKE `scheme` names, as its public and private keys. The client daemon
    /// does this and the other NIKE and sealed box operations, so this crate needs none of the
    /// NIKEs; a transport without them fails.
    fn nike_generate_key_pair(&self, _scheme: &str) -> impl Future<Output = Result<(Vec<u8>, Secret)>> + Send {
        async { Err(Error::Other("no NIKE over this transport".into())) }
    }
    /// The shared secret of `private` and the peer's `public`; a degenerate one fails.
    fn nike_derive_secret(
        &self,
        _scheme: &str,
        _private: &[u8],
        _public: &[u8],
    ) -> impl Future<Output = Result<Secret>> + Send {
        async { Err(Error::Other("no NIKE over this transport".into())) }
    }
    /// Seals `plaintext` to `public`, anonymously, as hpqc's sealedbox.
    fn box_seal(&self, _scheme: &str, _public: &[u8], _plaintext: &[u8]) -> impl Future<Output = Result<Vec<u8>>> + Send {
        async { Err(Error::Other("no sealed boxes over this transport".into())) }
    }
    /// Opens a box sealed to the public key of `private`.
    fn box_open(&self, _scheme: &str, _private: &[u8], _ciphertext: &[u8]) -> impl Future<Output = Result<Vec<u8>>> + Send {
        async { Err(Error::Other("no sealed boxes over this transport".into())) }
    }
}

impl<B: Backend> Backend for Arc<B> {
    fn new_keypair(&self) -> impl Future<Output = Result<Keypair>> + Send {
        (**self).new_keypair()
    }
    fn write_box(
        &self,
        write_cap: &[u8],
        index: &[u8],
        plaintext: &[u8],
    ) -> impl Future<Output = Result<()>> + Send {
        (**self).write_box(write_cap, index, plaintext)
    }
    fn read_box(&self, read_cap: &[u8], index: &[u8]) -> impl Future<Output = Result<Read>> + Send {
        (**self).read_box(read_cap, index)
    }
    fn replica_epoch(&self) -> impl Future<Output = Result<u64>> + Send {
        (**self).replica_epoch()
    }
    fn max_plaintext(&self) -> impl Future<Output = Result<usize>> + Send {
        (**self).max_plaintext()
    }
    fn voucher_mint(
        &self,
        write_cap: &[u8],
        name: &str,
    ) -> impl Future<Output = Result<Minted>> + Send {
        (**self).voucher_mint(write_cap, name)
    }
    fn voucher_derive_stream(
        &self,
        voucher: &[u8],
    ) -> impl Future<Output = Result<(Secret, Secret)>> + Send {
        (**self).voucher_derive_stream(voucher)
    }
    fn voucher_induct(
        &self,
        voucher: &[u8],
        payload: &[u8],
        who_reply: &[u8],
    ) -> impl Future<Output = Result<Inducted>> + Send {
        (**self).voucher_induct(voucher, payload, who_reply)
    }
    fn voucher_open(
        &self,
        secret_key: &[u8],
        sealed_reply: &[u8],
        write_cap: &[u8],
    ) -> impl Future<Output = Result<Opened>> + Send {
        (**self).voucher_open(secret_key, sealed_reply, write_cap)
    }
    fn request(
        &self,
        node: &[u8; 32],
        endpoint: &[u8],
        payload: &[u8],
    ) -> impl Future<Output = Result<Vec<u8>>> + Send {
        (**self).request(node, endpoint, payload)
    }
    fn services(&self, capability: &str) -> impl Future<Output = Result<Vec<ServiceNode>>> + Send {
        (**self).services(capability)
    }
    fn nike_generate_key_pair(&self, scheme: &str) -> impl Future<Output = Result<(Vec<u8>, Secret)>> + Send {
        (**self).nike_generate_key_pair(scheme)
    }
    fn nike_derive_secret(&self, scheme: &str, private: &[u8], public: &[u8]) -> impl Future<Output = Result<Secret>> + Send {
        (**self).nike_derive_secret(scheme, private, public)
    }
    fn box_seal(&self, scheme: &str, public: &[u8], plaintext: &[u8]) -> impl Future<Output = Result<Vec<u8>>> + Send {
        (**self).box_seal(scheme, public, plaintext)
    }
    fn box_open(&self, scheme: &str, private: &[u8], ciphertext: &[u8]) -> impl Future<Output = Result<Vec<u8>>> + Send {
        (**self).box_open(scheme, private, ciphertext)
    }
}
