//! Pigeonhole over Reticulum in Rust, on Beechat's Reticulum-rs: the mesh transport of the
//! Python `MeshBackend`, speaking query mode 2 of `pigeonhole_rns` (katzenpost/pigeonhole_rns#3).
//!
//! A replica announces `pigeonhole.replica` with one byte of flags, bit 0 for a bridge and bit 1
//! for a replica serving Channel queries. The backend opens a Link to the nearest replica
//! announcing bit 1 and sends each query as Channel messages of type [`MSGTYPE`], each one a
//! [`Frame`]: the request id, the piece's index and the piece count, then the piece. The reply
//! comes back the same way under the query's request id. A read query is `0x00 || box id`; a
//! write is `0x01 || box id || signature || ciphertext`, with an empty ciphertext for a
//! tombstone. A reply is a replica result code, and for a box found its signature and
//! ciphertext.
//!
//! BACAP is done here with hpqc under the context [`CONTEXT`], and a box holds its plaintext
//! padded by [`pad`], so boxes cross unchanged between this backend, the Python client and the
//! mixnet. Contact vouchers are hpqc's voucher module, byte compatible with the Python and Go
//! ones.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hpqc::bacap::{MessageBoxIndex, ReadCap, SIGNATURE_SIZE, WriteCap};
use hpqc::rand_core::UnwrapErr;
use hpqc::voucher::{self, VOUCHER_SIZE, VoucherStream};
use reticulum::channel::{Channel, Message};
use reticulum::destination::link::{Link, LinkStatus};
use reticulum::destination::{DestinationDesc, DestinationName};
use reticulum::error::RnsError;
use reticulum::hash::AddressHash;
use reticulum::iface::tcp_client::TcpClient;
use reticulum::packet::PacketType;
use reticulum::transport::{Transport, TransportConfig};
use tokio::sync::{Mutex, broadcast, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::transport::{Backend, Error, Inducted, Keypair, Minted, Opened, Read, Result, Secret};

/// The Channel message type of a [`Frame`].
pub const MSGTYPE: u16 = 0x5048;
/// The BACAP context of Pigeonhole boxes, shared with Katzenpost clients.
pub const CONTEXT: &[u8] = b"pigeonhole context";
/// The Link MTU Reticulum-rs links run at: it sends no MTU signalling, so its peers keep the
/// Reticulum default.
pub const MTU: usize = 500;
/// The most pieces a query or reply is cut into.
pub const MAX_PIECES: usize = 255;
/// The bytes of a [`Frame`] before its piece.
pub const FRAME_HEADER: usize = 4;
/// How long the pieces of one reply are kept waiting for the rest.
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(60);

const READ: u8 = 0;
const WRITE: u8 = 1;
const SUCCESS: u8 = 0;
const NOT_FOUND: u8 = 1;
const ALREADY_EXISTS: u8 = 10;
const TOMBSTONE: u8 = 11;
const EPOCH_BASE: u64 = 1496275200;
const EPOCH_SECONDS: u64 = 7 * 24 * 3600;

/// The payload a Link packet carries at `mtu`: what is left after the interface access code,
/// the header and the token overhead, in whole AES blocks, less the padding byte.
pub fn link_mdu(mtu: usize) -> usize {
    (mtu - 1 - 19 - 48) / 16 * 16 - 1
}

/// The most bytes of a query or reply one [`Frame`] carries at `mtu`: the Link MDU less the
/// Channel's 6 byte envelope and the frame header. 421 at the 500 byte MTU.
pub fn piece_size(mtu: usize) -> usize {
    link_mdu(mtu) - 6 - FRAME_HEADER
}

/// One Channel message of query mode 2: piece `index` of `count` of the query or reply with
/// id `request_id`. On the wire the id is a big endian u16, then the index and the count as
/// one byte each, then the piece.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// The query's id, which its reply repeats.
    pub request_id: u16,
    /// The piece's place, from 0.
    pub index: u8,
    /// The number of pieces.
    pub count: u8,
    /// This piece of the query or reply.
    pub data: Vec<u8>,
}

impl Frame {
    /// The frame's bytes, the Channel message's payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER + self.data.len());
        out.extend_from_slice(&self.request_id.to_be_bytes());
        out.extend_from_slice(&[self.index, self.count]);
        out.extend_from_slice(&self.data);
        out
    }

    /// The frame `b` encodes, or `None` when it is shorter than the header.
    pub fn from_bytes(b: &[u8]) -> Option<Frame> {
        (b.len() >= FRAME_HEADER).then(|| Frame {
            request_id: u16::from_be_bytes([b[0], b[1]]),
            index: b[2],
            count: b[3],
            data: b[FRAME_HEADER..].to_vec(),
        })
    }
}

impl Message for Frame {
    fn unpack(packed: &[u8], message_type: u16) -> std::result::Result<Self, RnsError> {
        if message_type != MSGTYPE {
            return Err(RnsError::ChannelError);
        }
        Frame::from_bytes(packed).ok_or(RnsError::ChannelError)
    }

    fn pack(&self) -> Vec<u8> {
        self.to_bytes()
    }

    fn message_type(&self) -> u16 {
        MSGTYPE
    }
}

/// Cuts `data` into the frames of request `request_id`, at most `piece_size` bytes each; empty
/// data is one empty piece. Fails past [`MAX_PIECES`] pieces.
pub fn split(request_id: u16, data: &[u8], piece_size: usize) -> Result<Vec<Frame>> {
    if piece_size == 0 {
        return Err(Error::Other("piece size 0".into()));
    }
    let count = data.len().div_ceil(piece_size).max(1);
    if count > MAX_PIECES {
        return Err(Error::Other(format!(
            "{} bytes need {count} pieces of {piece_size}",
            data.len()
        )));
    }
    Ok((0..count)
        .map(|i| Frame {
            request_id,
            index: i as u8,
            count: count as u8,
            data: data[(i * piece_size).min(data.len())..((i + 1) * piece_size).min(data.len())]
                .to_vec(),
        })
        .collect())
}

/// Puts frames back together by request id. A frame whose count differs from its request's
/// first frame, or whose index is out of range, drops the request; a request not complete
/// within [`REASSEMBLY_TIMEOUT`] is dropped.
#[derive(Default)]
pub struct Reassembler {
    pending: HashMap<u16, Pending>,
}

/// When a request's first piece came, its piece count, and its pieces by index.
type Pending = (Instant, u8, BTreeMap<u8, Vec<u8>>);

impl Reassembler {
    /// Takes one frame, and returns the whole message once its last piece is in.
    pub fn feed(&mut self, f: Frame) -> Option<Vec<u8>> {
        let now = Instant::now();
        self.pending
            .retain(|_, (started, _, _)| now.duration_since(*started) < REASSEMBLY_TIMEOUT);
        if f.count == 0 || f.index >= f.count {
            self.pending.remove(&f.request_id);
            return None;
        }
        let (_, count, pieces) = self
            .pending
            .entry(f.request_id)
            .or_insert_with(|| (now, f.count, BTreeMap::new()));
        if *count != f.count {
            self.pending.remove(&f.request_id);
            return None;
        }
        pieces.entry(f.index).or_insert(f.data);
        if pieces.len() < *count as usize {
            return None;
        }
        let (_, _, pieces) = self.pending.remove(&f.request_id)?;
        Some(pieces.into_values().flatten().collect())
    }
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

/// The Katzenpost replica epoch at `unix_secs`: weeks since 1496275200.
pub fn epoch_at(unix_secs: u64) -> u64 {
    unix_secs.saturating_sub(EPOCH_BASE) / EPOCH_SECONDS
}

fn other(e: impl std::fmt::Display) -> Error {
    Error::Other(format!("reticulum-rs: {e}"))
}

fn replica_name() -> DestinationName {
    DestinationName::new("pigeonhole", "replica")
}

/// A replica heard announcing Channel queries.
#[derive(Clone, Copy)]
struct Replica {
    desc: DestinationDesc,
    hops: u8,
}

type Replies = Arc<StdMutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>>;

/// The Link and Channel to the entry replica.
struct Conn {
    dest: AddressHash,
    link: Arc<Mutex<Link>>,
    channel: Channel<Frame>,
    replies: Replies,
    reader: JoinHandle<()>,
}

/// Pigeonhole boxes over Reticulum-rs, through the nearest replica announcing Channel queries.
/// Queries are one at a time, on one Link kept open between them and reopened when lost or
/// when a nearer replica is heard.
pub struct ReticulumRsBackend {
    transport: Transport,
    replicas: Arc<StdMutex<HashMap<AddressHash, Replica>>>,
    conn: Mutex<Option<Conn>>,
    box_size: usize,
    next_id: AtomicU16,
    timeout: Duration,
    watchers: Vec<JoinHandle<()>>,
}

impl ReticulumRsBackend {
    /// Starts Reticulum-rs with a TCP client interface to `addr` (a Reticulum TCP server
    /// interface, `host:port`) and waits up to `wait` for a replica. `box_size` is the box
    /// plaintext size, the same on every replica.
    pub async fn connect(addr: &str, box_size: usize, wait: Duration) -> Result<Self> {
        let transport = Transport::new(TransportConfig::default());
        let b = Self::new(transport, box_size).await;
        b.transport
            .iface_manager()
            .lock()
            .await
            .spawn(TcpClient::new(addr), TcpClient::spawn);
        b.wait_for_replica(wait).await?;
        Ok(b)
    }

    /// Uses `transport`, whose interfaces the caller adds, and starts listening for replica
    /// announces.
    pub async fn new(transport: Transport, box_size: usize) -> Self {
        let replicas: Arc<StdMutex<HashMap<AddressHash, Replica>>> = Arc::default();
        let hops: Arc<StdMutex<HashMap<AddressHash, u8>>> = Arc::default();
        let mut rx = transport.iface_rx();
        let h = hops.clone();
        // Reticulum-rs keeps its path table private, so the hop counts come from the announces.
        let hops_watch = tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(m) if m.packet.header.packet_type == PacketType::Announce => {
                        let mut h = h.lock().unwrap();
                        let e = h.entry(m.packet.destination).or_insert(u8::MAX);
                        *e = (*e).min(m.packet.header.hops);
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                    _ => {}
                }
            }
        });
        let mut announces = transport.recv_announces().await;
        let r = replicas.clone();
        let name = replica_name();
        let announce_watch = tokio::spawn(async move {
            loop {
                let a = match announces.recv().await {
                    Ok(a) => a,
                    Err(broadcast::error::RecvError::Closed) => return,
                    Err(_) => continue,
                };
                let desc = a.destination.lock().await.desc;
                if desc.name.hash.as_slice()[..10] != name.hash.as_slice()[..10] {
                    continue;
                }
                let channel = a.app_data.as_slice().first().is_some_and(|f| f & 2 != 0);
                let hops = hops.lock().unwrap().get(&desc.address_hash).copied();
                let mut r = r.lock().unwrap();
                if channel {
                    r.insert(desc.address_hash, Replica { desc, hops: hops.unwrap_or(u8::MAX) });
                } else {
                    r.remove(&desc.address_hash);
                }
            }
        });
        ReticulumRsBackend {
            transport,
            replicas,
            conn: Mutex::new(None),
            box_size,
            next_id: AtomicU16::new(0),
            timeout: Duration::from_secs(60),
            watchers: vec![hops_watch, announce_watch],
        }
    }

    /// Waits up to `wait` for a replica announcing Channel queries.
    pub async fn wait_for_replica(&self, wait: Duration) -> Result<()> {
        timeout(wait, async {
            while self.entry().is_none() {
                sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .map_err(|_| Error::Other("no Pigeonhole replica heard on the mesh".into()))
    }

    /// The entry replica's destination hash and hops away: the nearest replica heard
    /// announcing Channel queries.
    pub fn entry(&self) -> Option<(AddressHash, u8)> {
        self.replicas
            .lock()
            .unwrap()
            .values()
            .min_by_key(|r| r.hops)
            .map(|r| (r.desc.address_hash, r.hops))
    }

    /// The time a query may take, its reply included; 60 seconds unless set.
    pub fn set_timeout(&mut self, t: Duration) {
        self.timeout = t;
    }

    async fn open(&self, desc: DestinationDesc) -> Result<Conn> {
        let link = self.transport.link(desc).await;
        let id = *link.lock().await.id();
        let active = timeout(Duration::from_secs(20), async {
            loop {
                match link.lock().await.status() {
                    LinkStatus::Active => return true,
                    LinkStatus::Closed => return false,
                    _ => sleep(Duration::from_millis(20)).await,
                }
            }
        })
        .await;
        let channel = match active {
            Ok(true) => self.transport.mk_channel::<Frame>(link.clone()).await.ok(),
            _ => None,
        };
        let Some((channel, mut rx)) = channel else {
            let _ = self.transport.link_close(id).await;
            return Err(Error::Other("no Link to the replica".into()));
        };
        let replies: Replies = Arc::default();
        let r = replies.clone();
        let reader = tokio::spawn(async move {
            let mut reassembler = Reassembler::default();
            loop {
                match rx.recv().await {
                    Ok(f) => {
                        let rid = f.request_id;
                        if let Some(data) = reassembler.feed(f)
                            && let Some(tx) = r.lock().unwrap().remove(&rid)
                        {
                            let _ = tx.send(data);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        log::warn!("reticulum-rs: dropped {n} frames");
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        Ok(Conn { dest: desc.address_hash, link, channel, replies, reader })
    }

    async fn close(&self, c: Conn) {
        c.reader.abort();
        let id = *c.link.lock().await.id();
        let _ = self.transport.link_close(id).await;
    }

    /// Sends one query to the entry replica and returns its reply.
    async fn query(&self, q: &[u8]) -> Result<Vec<u8>> {
        let mut conn = self.conn.lock().await;
        let desc = {
            let r = self.replicas.lock().unwrap();
            r.values().min_by_key(|r| r.hops).map(|r| r.desc)
        }
        .ok_or_else(|| Error::Other("no Pigeonhole replica heard on the mesh".into()))?;
        let usable = match &*conn {
            Some(c) => {
                c.dest == desc.address_hash && c.link.lock().await.status() == LinkStatus::Active
            }
            None => false,
        };
        if !usable {
            if let Some(c) = conn.take() {
                self.close(c).await;
            }
            *conn = Some(self.open(desc).await?);
        }
        let c = conn.as_ref().unwrap();
        let rid = self.next_id.fetch_add(1, Ordering::Relaxed);
        let frames = split(rid, q, piece_size(MTU))?;
        let (tx, rx) = oneshot::channel();
        c.replies.lock().unwrap().insert(rid, tx);
        let r = timeout(self.timeout, async {
            for f in &frames {
                loop {
                    match c.channel.send(f).await {
                        Ok(_) => break,
                        // The Channel's window is full, or the Link went down.
                        Err(RnsError::LinkNotReady) => {
                            if c.link.lock().await.status() == LinkStatus::Closed {
                                return Err(Error::Other("Link to the replica closed".into()));
                            }
                            sleep(Duration::from_millis(10)).await;
                        }
                        Err(e) => return Err(other(format!("{e:?}"))),
                    }
                }
            }
            rx.await.map_err(|_| Error::Other("reply lost".into()))
        })
        .await
        .unwrap_or_else(|_| Err(Error::Other("the replica did not answer".into())));
        c.replies.lock().unwrap().remove(&rid);
        if r.is_err()
            && let Some(c) = conn.take()
        {
            self.close(c).await;
        }
        r
    }
}

impl Drop for ReticulumRsBackend {
    fn drop(&mut self) {
        for w in &self.watchers {
            w.abort();
        }
        if let Ok(mut c) = self.conn.try_lock()
            && let Some(c) = c.take()
        {
            c.reader.abort();
        }
    }
}

impl Backend for ReticulumRsBackend {
    async fn new_keypair(&self) -> Result<Keypair> {
        let wc = WriteCap::generate(&mut UnwrapErr(getrandom::SysRng));
        let rc = wc.read_cap().to_bytes();
        Ok(Keypair {
            write_cap: Secret::new(&wc.to_bytes()),
            read_cap: Secret::new(&rc),
            first: rc[32..].to_vec(),
        })
    }

    async fn write_box(&self, write_cap: &[u8], index: &[u8], plaintext: &[u8]) -> Result<()> {
        let q = {
            let wc = WriteCap::from_bytes(write_cap).map_err(other)?;
            let idx = MessageBoxIndex::from_bytes(index).map_err(other)?;
            let pos = wc.position_at(&idx).map_err(other)?;
            let (box_id, ciphertext, sig) = if plaintext.is_empty() {
                let (b, s) = pos.tombstone(CONTEXT).map_err(other)?;
                (b, Vec::new(), s)
            } else {
                pos.encrypt(CONTEXT, &pad(plaintext, self.box_size)?)
                    .map_err(other)?
            };
            [&[WRITE][..], &box_id, &sig, &ciphertext].concat()
        };
        match self.query(&q).await?.first() {
            Some(&SUCCESS) => Ok(()),
            // The replica holds other bytes, or a tombstone where data was written.
            Some(&ALREADY_EXISTS) | Some(&TOMBSTONE) => Err(Error::BoxAlreadyExists),
            Some(c) => Err(Error::Other(format!("replica error {c}"))),
            None => Err(Error::Other("empty reply".into())),
        }
    }

    async fn read_box(&self, read_cap: &[u8], index: &[u8]) -> Result<Read> {
        let rc = ReadCap::from_bytes(read_cap).map_err(other)?;
        let idx = MessageBoxIndex::from_bytes(index).map_err(other)?;
        let box_id = rc.position_at(&idx).map_err(other)?.box_id(CONTEXT).map_err(other)?;
        let reply = self.query(&[&[READ][..], &box_id].concat()).await?;
        match reply.first() {
            Some(&NOT_FOUND) => Ok(Read::NotFound),
            Some(&TOMBSTONE) => Ok(Read::Tombstone),
            Some(&SUCCESS) if reply.len() > SIGNATURE_SIZE => {
                let (sig, ciphertext) = reply[1..].split_at(SIGNATURE_SIZE);
                let pos = rc.position_at(&idx).map_err(other)?;
                let opened = pos.open(CONTEXT, &box_id, ciphertext, sig).map_err(other)?;
                if opened.is_empty() {
                    return Ok(Read::Tombstone);
                }
                Ok(Read::Data(unpad(&opened)?))
            }
            Some(c) => Err(Error::Other(format!("replica error {c}"))),
            None => Err(Error::Other("empty reply".into())),
        }
    }

    /// Mesh replicas keep the Katzenpost replica epoch, so a bridged box is in the same epoch
    /// on both sides.
    async fn replica_epoch(&self) -> Result<u64> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(other)?;
        Ok(epoch_at(now.as_secs()))
    }

    async fn max_plaintext(&self) -> Result<usize> {
        Ok(self.box_size)
    }

    async fn voucher_mint(&self, write_cap: &[u8], name: &str, form: u8) -> Result<Minted> {
        let wc = WriteCap::from_bytes(write_cap).map_err(other)?;
        let rng = &mut UnwrapErr(getrandom::SysRng);
        let m = if form == 1 {
            voucher::mint_long(&wc, name, rng)
        } else {
            voucher::mint_compact(&wc, name, rng)
        };
        Ok(Minted {
            voucher: Secret::new(&m.voucher),
            payload: Secret::new(&m.payload),
            write_cap: Secret::new(&m.stream.write_cap.to_bytes()),
            read_cap: Secret::new(&m.stream.read_cap.to_bytes()),
            secret_key: Secret::new(&m.secret_key),
            version: m.form.version(),
        })
    }

    async fn voucher_derive_stream(&self, v: &[u8]) -> Result<(Secret, Secret)> {
        let s = VoucherStream::derive(&voucher_bytes(v)?);
        Ok((Secret::new(&s.write_cap.to_bytes()), Secret::new(&s.read_cap.to_bytes())))
    }

    async fn voucher_induct(&self, v: &[u8], payload: &[u8], who_reply: &[u8]) -> Result<Inducted> {
        let r = voucher::induct(&voucher_bytes(v)?, payload, who_reply, &mut UnwrapErr(getrandom::SysRng))
            .map_err(other)?;
        Ok(Inducted {
            name: r.display_name,
            mutated_read_cap: Secret::new(&r.mutated_read_cap.to_bytes()),
            sealed_reply: r.sealed_reply,
            version: r.form.version(),
        })
    }

    async fn voucher_open(&self, secret_key: &[u8], sealed_reply: &[u8], write_cap: &[u8]) -> Result<Opened> {
        let wc = WriteCap::from_bytes(write_cap).map_err(other)?;
        let r = voucher::open_reply(secret_key, sealed_reply, &wc).map_err(other)?;
        Ok(Opened {
            who_reply: Secret::new(&r.who_reply),
            mutated_write_cap: Secret::new(&r.mutated_write_cap.to_bytes()),
        })
    }
}

fn voucher_bytes(v: &[u8]) -> Result<[u8; VOUCHER_SIZE]> {
    v.try_into().map_err(|_| Error::Other("voucher is not 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdu_at_500() {
        assert_eq!(link_mdu(500), 431);
        assert_eq!(piece_size(500), 421);
    }

    #[test]
    fn split_reassemble_out_of_order_with_duplicates() {
        let data: Vec<u8> = (0..2000u32).map(|i| i as u8).collect();
        let mut frames = split(9, &data, 421).unwrap();
        assert_eq!(frames.len(), 5);
        frames.reverse();
        frames.insert(1, frames[0].clone());
        let mut r = Reassembler::default();
        let out: Vec<_> = frames.into_iter().filter_map(|f| r.feed(f)).collect();
        assert_eq!(out, vec![data]);
        assert!(split(1, &vec![0; 255 * 421 + 1], 421).is_err());
        assert_eq!(split(1, &[], 421).unwrap()[0].count, 1);
    }

    #[test]
    fn mismatched_count_drops_request() {
        let mut r = Reassembler::default();
        assert_eq!(r.feed(Frame { request_id: 1, index: 0, count: 2, data: vec![1] }), None);
        assert_eq!(r.feed(Frame { request_id: 1, index: 1, count: 3, data: vec![2] }), None);
        assert_eq!(r.feed(Frame { request_id: 1, index: 1, count: 2, data: vec![2] }), None);
    }

    #[test]
    fn pad_roundtrip_and_epoch() {
        let p = pad(b"hi", 10).unwrap();
        assert_eq!(p, [0, 0, 0, 2, b'h', b'i', 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(unpad(&p).unwrap(), b"hi");
        assert!(pad(&[0; 11], 10).is_err());
        assert_eq!(epoch_at(1496275200 + 7 * 24 * 3600 * 3 + 5), 3);
    }
}
