//! An in-memory Pigeonhole with the katzenpost replica's rules, for tests: a box is kept for the
//! epoch it was stored in and the next, a matching rewrite succeeds without storing it again, a
//! different one is refused, and a tombstone is always stored. A write cap here is a signing seed,
//! then the read cap: its public key and the stream's first index.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use crate::protocols::katzenqt1::member::{hkdf, next_index};
use rand::RngCore;

use crate::transport::{
    Backend, Error, Inducted, Keypair, Minted, Opened, Read, Result, Secret, ServiceNode,
};

/// A mixnet service: it takes a request's payload and returns the reply.
pub type Handler = Arc<dyn Fn(Vec<u8>) -> Pin<Box<dyn Future<Output = Vec<u8>> + Send>> + Send + Sync>;

/// A box: its stream's key and its Idx64.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BoxName {
    pub stream: Vec<u8>,
    pub idx64: u64,
}

/// A box, by its stream's key and its index, with the epoch it was stored in and what it holds.
type Boxes = HashMap<(Vec<u8>, Vec<u8>), (u64, Vec<u8>)>;

#[derive(Default)]
pub struct State {
    boxes: Boxes,
    pub epoch: u64,
    pub max_plaintext: usize,
    pub fail_writes: usize,
    /// Each write refused for its box holding other contents.
    pub refused: Vec<BoxName>,
    pub writes: usize,
    pub reads: usize,
    handlers: HashMap<([u8; 32], Vec<u8>), Handler>,
    services: HashMap<String, Vec<ServiceNode>>,
}

/// The replica every handle on it shares.
#[derive(Clone)]
pub struct World(pub Arc<Mutex<State>>);

impl Default for World {
    fn default() -> Self {
        World(Arc::new(Mutex::new(State {
            epoch: 1,
            max_plaintext: 1530,
            ..State::default()
        })))
    }
}

/// A keypair from a seed: the stream's root key and its first index, as BACAP derives them.
pub fn keypair_from_seed(seed: &[u8; 32], index_seed: &[u8; 48]) -> Keypair {
    let pk = ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes();
    let mut r = index_seed[32..].to_vec();
    r[7] &= 0x3f;
    r[15] &= 0x3f;
    let idx = u64::from_le_bytes(r[..8].try_into().unwrap())
        + u64::from_le_bytes(r[8..].try_into().unwrap());
    let mut index = idx.to_le_bytes().to_vec();
    index.extend([0u8; 64]);
    index.extend_from_slice(&index_seed[..32]);
    let first = next_index(&index).unwrap();
    let read_cap = [pk.as_slice(), &first].concat();
    Keypair {
        write_cap: [seed.as_slice(), &read_cap].concat().into(),
        read_cap: read_cap.into(),
        first,
    }
}

fn read_cap_of(write_cap: &[u8]) -> Result<&[u8]> {
    write_cap
        .get(32..)
        .filter(|r| r.len() == 136)
        .ok_or_else(|| Error::Other("not a write cap".into()))
}

impl World {
    /// Adds a mixnet service, `capability`, at `endpoint` on the node `node`.
    pub fn add_service(
        &self,
        capability: &str,
        node: [u8; 32],
        endpoint: &str,
        params: BTreeMap<String, serde_cbor::Value>,
        handler: Handler,
    ) {
        let mut s = self.0.lock().unwrap();
        s.handlers.insert((node, endpoint.as_bytes().to_vec()), handler);
        s.services.entry(capability.into()).or_default().push(ServiceNode {
            node_id_hash: node,
            endpoint: endpoint.as_bytes().to_vec(),
            params,
        });
    }

    pub fn set_epoch(&self, e: u64) {
        self.0.lock().unwrap().epoch = e;
    }

    pub fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap()
    }

    fn write(&self, read_cap: &[u8], index: &[u8], plaintext: &[u8]) -> Result<()> {
        let mut s = self.0.lock().unwrap();
        if s.fail_writes > 0 {
            s.fail_writes -= 1;
            return Err(Error::Other("sim: write failed".into()));
        }
        if plaintext.len() > s.max_plaintext {
            return Err(Error::Other("sim: box too large".into()));
        }
        s.writes += 1;
        let k = (read_cap[..32].to_vec(), index.to_vec());
        let epoch = s.epoch;
        if let Some((e, old)) = s.boxes.get(&k)
            && e + 1 >= epoch
            && !plaintext.is_empty()
        {
            if old == plaintext {
                return Ok(());
            }
            let idx64 = u64::from_le_bytes(index[..8].try_into().unwrap());
            s.refused.push(BoxName {
                stream: read_cap[..32].to_vec(),
                idx64,
            });
            return Err(Error::BoxAlreadyExists);
        }
        s.boxes.insert(k, (epoch, plaintext.to_vec()));
        Ok(())
    }

    fn read(&self, read_cap: &[u8], index: &[u8]) -> Read {
        let mut s = self.0.lock().unwrap();
        s.reads += 1;
        match s.boxes.get(&(read_cap[..32].to_vec(), index.to_vec())) {
            Some((e, b)) if e + 1 >= s.epoch => {
                if b.is_empty() {
                    Read::Tombstone
                } else {
                    Read::Data(b.clone())
                }
            }
            _ => Read::NotFound,
        }
    }
}

fn voucher_stream(voucher: &[u8]) -> Keypair {
    let seed = hkdf(voucher, b"sim voucher", 80);
    keypair_from_seed(
        &seed[..32].try_into().unwrap(),
        &seed[32..].try_into().unwrap(),
    )
}

impl Backend for World {
    async fn new_keypair(&self) -> Result<Keypair> {
        let mut b = [0u8; 80];
        rand::thread_rng().fill_bytes(&mut b);
        Ok(keypair_from_seed(
            &b[..32].try_into().unwrap(),
            &b[32..].try_into().unwrap(),
        ))
    }

    async fn write_box(&self, write_cap: &[u8], index: &[u8], plaintext: &[u8]) -> Result<()> {
        self.write(read_cap_of(write_cap)?, index, plaintext)
    }

    async fn read_box(&self, read_cap: &[u8], index: &[u8]) -> Result<Read> {
        Ok(self.read(read_cap, index))
    }

    async fn replica_epoch(&self) -> Result<u64> {
        Ok(self.0.lock().unwrap().epoch)
    }

    async fn max_plaintext(&self) -> Result<usize> {
        Ok(self.0.lock().unwrap().max_plaintext)
    }

    // Vouchers without cryptography: the voucher names its stream, the payload is the name, a
    // zero byte and the joiner's read cap, the sealed reply is the reply itself, and caps are not
    // mutated.

    async fn voucher_mint(&self, write_cap: &[u8], name: &str) -> Result<Minted> {
        let mut v = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut v);
        let kp = voucher_stream(&v);
        let payload = [name.as_bytes(), &[0], read_cap_of(write_cap)?].concat();
        Ok(Minted {
            voucher: v.clone().into(),
            payload: payload.into(),
            write_cap: kp.write_cap,
            read_cap: kp.read_cap,
            secret_key: v.into(),
        })
    }

    async fn voucher_derive_stream(&self, voucher: &[u8]) -> Result<(Secret, Secret)> {
        let kp = voucher_stream(voucher);
        Ok((kp.write_cap, kp.read_cap))
    }

    async fn voucher_induct(
        &self,
        _voucher: &[u8],
        payload: &[u8],
        who_reply: &[u8],
    ) -> Result<Inducted> {
        let i = payload
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| Error::Other("sim: not a voucher payload".into()))?;
        Ok(Inducted {
            name: String::from_utf8_lossy(&payload[..i]).into(),
            mutated_read_cap: payload[i + 1..].into(),
            sealed_reply: who_reply.to_vec(),
        })
    }

    async fn voucher_open(
        &self,
        _secret_key: &[u8],
        sealed_reply: &[u8],
        write_cap: &[u8],
    ) -> Result<Opened> {
        Ok(Opened {
            who_reply: sealed_reply.into(),
            mutated_write_cap: write_cap.into(),
        })
    }

    async fn request(&self, node: &[u8; 32], endpoint: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        let handler = self.0.lock().unwrap().handlers.get(&(*node, endpoint.to_vec())).cloned();
        match handler {
            Some(h) => Ok(h(payload.to_vec()).await),
            // Nobody answers; the daemon would retransmit until the caller gives up.
            None => std::future::pending().await,
        }
    }

    async fn services(&self, capability: &str) -> Result<Vec<ServiceNode>> {
        Ok(self.0.lock().unwrap().services.get(capability).cloned().unwrap_or_default())
    }

    // A NIKE and sealed boxes without cryptography, the sizes of X25519-CTIDH1024's: a public key
    // is a hash of the private key, a shared secret a hash of both public keys, and a box the
    // recipient's public key and then the plaintext.

    async fn nike_generate_key_pair(&self, _scheme: &str) -> Result<(Vec<u8>, Secret)> {
        let (public, private) = nike_keypair();
        Ok((public, private.into()))
    }

    async fn nike_derive_secret(&self, _scheme: &str, private: &[u8], public: &[u8]) -> Result<Secret> {
        let ours = nike_public(private);
        let (a, b) = if ours <= public.to_vec() { (ours, public.to_vec()) } else { (public.to_vec(), ours) };
        Ok(hkdf(&[a, b].concat(), b"sim nike secret", 32).into())
    }

    async fn box_seal(&self, _scheme: &str, public: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        Ok([public, plaintext].concat())
    }

    async fn box_open(&self, _scheme: &str, private: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let public = nike_public(private);
        match ciphertext.strip_prefix(public.as_slice()) {
            Some(plaintext) => Ok(plaintext.to_vec()),
            None => Err(Error::Other("sim: box sealed to another key".into())),
        }
    }
}

fn nike_public(private: &[u8]) -> Vec<u8> {
    hkdf(private, b"sim nike public", 160)
}

/// A keypair of the sim's NIKE, as its public and private keys.
pub fn nike_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut private = vec![0u8; 162];
    rand::thread_rng().fill_bytes(&mut private);
    (nike_public(&private), private)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replica_rules() {
        let w = World::default();
        let kp = w.new_keypair().await.unwrap();
        assert_eq!(
            (kp.write_cap.len(), kp.read_cap.len(), kp.first.len()),
            (168, 136, 104)
        );
        assert_eq!(
            w.read_box(&kp.read_cap, &kp.first).await,
            Ok(Read::NotFound)
        );
        w.write_box(&kp.write_cap, &kp.first, b"a").await.unwrap();
        w.write_box(&kp.write_cap, &kp.first, b"a").await.unwrap();
        assert_eq!(
            w.write_box(&kp.write_cap, &kp.first, b"b").await,
            Err(Error::BoxAlreadyExists)
        );
        assert_eq!(w.state().refused.len(), 1);
        assert_eq!(
            w.read_box(&kp.read_cap, &kp.first).await,
            Ok(Read::Data(b"a".to_vec()))
        );
        // A matching rewrite does not store the box again, so it goes when its epoch does.
        w.set_epoch(2);
        w.write_box(&kp.write_cap, &kp.first, b"a").await.unwrap();
        w.set_epoch(3);
        assert_eq!(
            w.read_box(&kp.read_cap, &kp.first).await,
            Ok(Read::NotFound)
        );
        let next = next_index(&kp.first).unwrap();
        w.write_box(&kp.write_cap, &next, b"c").await.unwrap();
        w.write_box(&kp.write_cap, &next, b"").await.unwrap();
        assert_eq!(w.read_box(&kp.read_cap, &next).await, Ok(Read::Tombstone));
        w.state().fail_writes = 1;
        assert!(w.write_box(&kp.write_cap, &kp.first, b"x").await.is_err());
    }

    #[tokio::test]
    async fn vouchers() {
        let w = World::default();
        let joiner = w.new_keypair().await.unwrap();
        let m = w.voucher_mint(&joiner.write_cap, "carol").await.unwrap();
        assert_eq!(
            w.voucher_derive_stream(&m.voucher).await.unwrap(),
            (m.write_cap.clone(), m.read_cap.clone())
        );
        let i = w
            .voucher_induct(&m.voucher, &m.payload, b"reply")
            .await
            .unwrap();
        assert_eq!(
            (i.name.as_str(), i.mutated_read_cap.clone()),
            ("carol", joiner.read_cap.clone())
        );
        let o = w
            .voucher_open(&m.secret_key, &i.sealed_reply, &joiner.write_cap)
            .await
            .unwrap();
        assert_eq!(&*o.who_reply, b"reply");
    }
}
