//! Pigeonhole over Reticulum in Rust, on berlinmesh/reticulum: the mesh transport of the Python
//! `MeshBackend`, speaking the query modes of `pigeonhole_rns`.
//!
//! A replica announces `pigeonhole.replica` with one byte of flags: bit 0 for a bridge, bit 1
//! for a replica serving Channel queries (mode 2), bit 3 for one serving no Link requests. The
//! backend opens a Link to the nearest replica and sends each query on it, by default as Channel
//! messages to a replica announcing bit 1 and as a Link request otherwise or when Channel fails
//! ([`QueryMode`]). In mode 2 a query is Channel messages of type [`MSGTYPE`], each one a
//! [`Frame`]: the request id, the piece's index and the piece count, then the piece; the reply
//! comes back the same way under the query's request id. In mode 1 it is a Link request to path
//! `read` or `write`, a Resource when over the Link MDU, as is its response. A read query is
//! `0x00 || box id`; a write is `0x01 || box id || signature || ciphertext`, with an empty
//! ciphertext for a tombstone. A reply is a replica result code, and for a box found its
//! signature and ciphertext.
//!
//! A replica announcing bit 4 serves push: after a read finds no box, [`Backend::watch`]
//! subscribes to it (`0x06 || ttl u16 || box id`, answered `0 || taken u16 || ttl u16`), and the
//! replica sends it once written as Channel messages of type [`PUSH_MSGTYPE`], framed the same
//! way, carrying `box id || reply`. The reply is kept for the read that follows.
//!
//! BACAP is [`boxes`]' with hpqc under the context [`CONTEXT`], and a box holds its plaintext
//! padded by [`pad`], so boxes cross unchanged between this backend, the Python client and the
//! mixnet. Contact vouchers are hpqc's voucher module, byte compatible with the Python and Go
//! ones.

use std::collections::{BTreeMap, HashMap};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hpqc::bacap::SIGNATURE_SIZE;
use hpqc::rand_core::UnwrapErr;
use tokio::sync::{Semaphore, oneshot};
use tokio::time::{sleep, timeout};

use crate::protocols::katzenqt1::boxes;
pub use crate::protocols::katzenqt1::boxes::{CONTEXT, pad, unpad, unpad_allowed};
use crate::transport::{Backend, Error, Inducted, Keypair, Minted, Opened, Pushed, Read, Result, Secret};

mod engine;
use engine::{Cmd, DestHash, Query, Shared};

/// The Channel message type of a [`Frame`].
pub const MSGTYPE: u16 = 0x5048;
/// The Channel message type of a frame of a push, under the replica's own request ids.
pub const PUSH_MSGTYPE: u16 = 0x5049;
/// The Link MTU: this backend sends no MTU signalling, so its Links keep the Reticulum default.
pub const MTU: usize = 500;
/// The most pieces a query or reply is cut into.
pub const MAX_PIECES: usize = 255;
/// The bytes of a [`Frame`] before its piece.
pub const FRAME_HEADER: usize = 4;
/// How long the pieces of one reply are kept waiting for the rest.
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(60);

const READ: u8 = 0;
const WRITE: u8 = 1;
const SUBSCRIBE: u8 = 6;
const PUSH_FLAG: u8 = 16;
const SUCCESS: u8 = 0;
const NOT_FOUND: u8 = 1;
const ALREADY_EXISTS: u8 = 10;
const TOMBSTONE: u8 = 11;
const EPOCH_BASE: u64 = 1496275200;
const EPOCH_SECONDS: u64 = 7 * 24 * 3600;

/// The payload a Link packet carries at `mtu`: what is left after the interface access code,
/// the header and the token overhead, in whole AES blocks, less the padding byte.
pub fn link_mdu(mtu: usize) -> usize {
    reticulum_link::link_mdu(mtu)
}

/// What a Link request wraps its data in: Reticulum packs `[time, path hash, data]` in msgpack,
/// a fixarray byte, a float64 of 9 bytes, a bin8 of 16 and the data's bin16 header.
pub const REQUEST_FRAMING: usize = 1 + 9 + 2 + 16 + 3;
/// A write query less its plaintext: type byte, box ID, signature, the padding's length and the
/// AEAD tag.
pub const WRITE_OVERHEAD: usize = 1 + hpqc::bacap::BOX_ID_SIZE + SIGNATURE_SIZE + 4 + 16;
/// The bytes of a Link packet a mesh box's write leaves spare.
pub const HEADROOM: usize = 16;

/// The largest box plaintext, a multiple of 16 bytes, whose write query fits one Link packet at
/// `mtu` with [`HEADROOM`] to spare, as a Channel frame or as a Link request (as the Python
/// transport sends): `transport::BOX_SIZES`' `mesh`. A read's reply is smaller.
pub fn mesh_box_size(mtu: usize) -> usize {
    (piece_size(mtu).min(link_mdu(mtu) - REQUEST_FRAMING) - WRITE_OVERHEAD - HEADROOM) / 16 * 16
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

/// The Katzenpost replica epoch at `unix_secs`: weeks since 1496275200.
pub fn epoch_at(unix_secs: u64) -> u64 {
    unix_secs.saturating_sub(EPOCH_BASE) / EPOCH_SECONDS
}

fn other(e: impl std::fmt::Display) -> Error {
    Error::Other(format!("reticulum-rs: {e}"))
}

/// How queries go to a replica: Channel first where the replica announces it, falling back to
/// Link requests (`Auto`), or only one way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryMode {
    Auto,
    Request,
    Channel,
}

const CHANNEL_FLAG: u8 = 2;
const NO_REQUESTS_FLAG: u8 = 8;

/// Pigeonhole boxes over berlinmesh/reticulum, through the nearest replica. Each query goes on
/// one Link to it, kept open between queries and reopened when lost or when a nearer replica is
/// heard; several may be in flight.
pub struct ReticulumRsBackend {
    shared: Arc<Shared>,
    cmds: Sender<Cmd>,
    write_size: usize,
    sizes: Vec<usize>,
    timeout: Duration,
    mode: QueryMode,
    /// By replica, whether Channel answered last in `Auto`.
    channel_ok: StdMutex<HashMap<DestHash, bool>>,
    /// Queries in flight, at most [`IN_FLIGHT`], under a replica's queue of 16 per Link.
    in_flight: Semaphore,
}

/// The most queries in flight at once, as `pigeonhole_rns` clients keep.
pub const IN_FLIGHT: usize = 8;

impl ReticulumRsBackend {
    /// Starts berlinmesh/reticulum with a TCP client interface to `addr` (a Reticulum TCP server
    /// interface, `host:port`) and waits up to `wait` for a replica. Boxes are written at the
    /// mesh size, [`mesh_box_size`]; a box of any of `transport::allowed_sizes` is read,
    /// `box_size`, a size the mesh's replicas take, among them.
    pub async fn connect(addr: &str, box_size: usize, wait: Duration) -> Result<Self> {
        let sizes = crate::transport::allowed_sizes(&[mesh_box_size(MTU), box_size])
            .ok_or_else(|| Error::Other(format!("box size {box_size} is out of bounds")))?;
        let (host, port) = addr
            .rsplit_once(':')
            .and_then(|(h, p)| Some((h.trim_matches(['[', ']']), p.parse().ok()?)))
            .ok_or_else(|| Error::Other(format!("{addr} is not host:port")))?;
        let shared = Arc::<Shared>::default();
        let cmds = engine::spawn(host, port, shared.clone()).map_err(other)?;
        let b = ReticulumRsBackend {
            shared,
            cmds,
            write_size: mesh_box_size(MTU),
            sizes,
            timeout: Duration::from_secs(60),
            mode: QueryMode::Auto,
            channel_ok: StdMutex::default(),
            in_flight: Semaphore::new(IN_FLIGHT),
        };
        b.wait_for_replica(wait).await?;
        Ok(b)
    }

    /// Reads boxes of `extra` sizes too; `false`, and nothing changed, when one is out of bounds.
    pub fn allow_sizes(&mut self, extra: &[usize]) -> bool {
        match crate::transport::allowed_sizes(&[&self.sizes[..], extra].concat()) {
            Some(s) => self.sizes = s,
            None => return false,
        }
        true
    }

    /// Waits up to `wait` for a replica this backend can query.
    pub async fn wait_for_replica(&self, wait: Duration) -> Result<()> {
        timeout(wait, async {
            while self.entry().is_none() {
                sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .map_err(|_| Error::Other("no Pigeonhole replica heard on the mesh".into()))
    }

    fn usable(&self, flags: u8) -> bool {
        match self.mode {
            QueryMode::Channel => flags & CHANNEL_FLAG != 0,
            QueryMode::Request => flags & NO_REQUESTS_FLAG == 0,
            QueryMode::Auto => flags & CHANNEL_FLAG != 0 || flags & NO_REQUESTS_FLAG == 0,
        }
    }

    fn entry_replica(&self) -> Option<(DestHash, engine::Replica)> {
        let r = self.shared.replicas.lock().unwrap();
        r.iter().filter(|(_, r)| self.usable(r.flags)).min_by_key(|(_, r)| r.hops).map(|(d, r)| (*d, *r))
    }

    /// The entry replica's destination hash and hops away: the nearest replica heard that this
    /// backend can query in its [`QueryMode`].
    pub fn entry(&self) -> Option<(DestHash, u8)> {
        self.entry_replica().map(|(d, r)| (d, r.hops))
    }

    /// The time a query may take, its reply included; 60 seconds unless set.
    pub fn set_timeout(&mut self, t: Duration) {
        self.timeout = t;
    }

    /// How queries go; [`QueryMode::Auto`] unless set.
    pub fn set_query_mode(&mut self, m: QueryMode) {
        self.mode = m;
    }

    async fn ask(&self, dest: DestHash, channel: bool, path: &'static str, data: &[u8]) -> Result<Vec<u8>> {
        let _permit = self.in_flight.acquire().await.map_err(other)?;
        let (reply, rx) = oneshot::channel();
        let q = Query { dest, channel, path, data: data.to_vec(), deadline: Instant::now() + self.timeout, reply };
        self.cmds.send(Cmd::Query(q)).map_err(|_| Error::Other("reticulum-rs: engine stopped".into()))?;
        rx.await.map_err(|_| Error::Other("reticulum-rs: engine stopped".into()))?.map_err(Error::Other)
    }

    /// Sends one query to the entry replica, a Link request to `path` or Channel frames, and
    /// returns its reply.
    async fn query(&self, path: &'static str, q: &[u8]) -> Result<Vec<u8>> {
        let (dest, r) =
            self.entry_replica().ok_or_else(|| Error::Other("no Pigeonhole replica heard on the mesh".into()))?;
        let channel = r.flags & CHANNEL_FLAG != 0;
        let requests = r.flags & NO_REQUESTS_FLAG == 0;
        let first = match self.mode {
            QueryMode::Channel => true,
            QueryMode::Request => false,
            QueryMode::Auto => channel && self.channel_ok.lock().unwrap().get(&dest).copied().unwrap_or(true),
        };
        let res = self.ask(dest, first, path, q).await;
        if res.is_ok() || self.mode != QueryMode::Auto || !(if first { requests } else { channel }) {
            return res;
        }
        let res = self.ask(dest, !first, path, q).await;
        if res.is_ok() {
            log::info!("reticulum-rs: replica {} answers {}", hex::encode(dest), if first { "Link requests" } else { "on Channel" });
            self.channel_ok.lock().unwrap().insert(dest, !first);
        }
        res
    }
}

impl Drop for ReticulumRsBackend {
    fn drop(&mut self) {
        let _ = self.cmds.send(Cmd::Stop);
    }
}

impl Backend for ReticulumRsBackend {
    async fn new_keypair(&self) -> Result<Keypair> {
        Ok(boxes::new_keypair(&mut UnwrapErr(getrandom::SysRng)))
    }

    async fn write_box(&self, write_cap: &[u8], index: &[u8], plaintext: &[u8]) -> Result<()> {
        let b = boxes::seal(write_cap, index, plaintext, &self.sizes, self.write_size)?;
        let q = [&[WRITE][..], &b.box_id, &b.signature, &b.ciphertext].concat();
        match self.query("write", &q).await?.first() {
            Some(&SUCCESS) => Ok(()),
            // The replica holds other bytes, or a tombstone where data was written.
            Some(&ALREADY_EXISTS) | Some(&TOMBSTONE) => Err(Error::BoxAlreadyExists),
            Some(c) => Err(Error::Other(format!("replica error {c}"))),
            None => Err(Error::Other("empty reply".into())),
        }
    }

    async fn read_box(&self, read_cap: &[u8], index: &[u8]) -> Result<Read> {
        let box_id = boxes::box_id(read_cap, index)?;
        let held = self.shared.pushed.lock().unwrap().remove(&box_id[..]);
        let reply = match held {
            Some(r) => r,
            None => self.query("read", &[&[READ][..], &box_id].concat()).await?,
        };
        match reply.first() {
            Some(&NOT_FOUND) => Ok(Read::NotFound),
            Some(&TOMBSTONE) => Ok(Read::Tombstone),
            Some(&SUCCESS) if reply.len() > SIGNATURE_SIZE => {
                let (sig, ciphertext) = reply[1..].split_at(SIGNATURE_SIZE);
                boxes::open(read_cap, index, ciphertext, sig, &self.sizes)
            }
            Some(c) => Err(Error::Other(format!("replica error {c}"))),
            None => Err(Error::Other("empty reply".into())),
        }
    }

    /// Subscribes to the box on the entry replica when it serves push.
    async fn watch(&self, read_cap: &[u8], index: &[u8]) -> Option<Pushed> {
        let box_id = boxes::box_id(read_cap, index).ok()?.to_vec();
        let dest = self.entry_replica().filter(|(_, r)| r.flags & PUSH_FLAG != 0 && r.flags & CHANNEL_FLAG != 0)?.0;
        let (tx, rx) = oneshot::channel();
        self.shared.waiting.lock().unwrap().insert(box_id.clone(), tx);
        // Pushes come only on Channel, so the subscription goes there. ttl 0 asks for the longest
        // a replica keeps a subscription; a poll renews it.
        match self.ask(dest, true, "subscribe", &[&[SUBSCRIBE, 0, 0][..], &box_id].concat()).await {
            Ok(r) if r.len() == 5 && r[0] == SUCCESS && r[1..3] != [0, 0] => Some(rx),
            _ => {
                self.shared.waiting.lock().unwrap().remove(&box_id);
                None
            }
        }
    }

    /// Mesh replicas keep the Katzenpost replica epoch, so a bridged box is in the same epoch
    /// on both sides.
    async fn replica_epoch(&self) -> Result<u64> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(other)?;
        Ok(epoch_at(now.as_secs()))
    }

    async fn max_plaintext(&self) -> Result<usize> {
        Ok(self.write_size)
    }

    async fn voucher_mint(&self, write_cap: &[u8], name: &str, form: u8) -> Result<Minted> {
        boxes::voucher_mint(write_cap, name, form, &mut UnwrapErr(getrandom::SysRng))
    }

    async fn voucher_derive_stream(&self, v: &[u8]) -> Result<(Secret, Secret)> {
        boxes::voucher_derive_stream(v)
    }

    async fn voucher_induct(&self, v: &[u8], payload: &[u8], who_reply: &[u8]) -> Result<Inducted> {
        boxes::voucher_induct(v, payload, who_reply, &mut UnwrapErr(getrandom::SysRng))
    }

    async fn voucher_open(&self, secret_key: &[u8], sealed_reply: &[u8], write_cap: &[u8]) -> Result<Opened> {
        boxes::voucher_open(secret_key, sealed_reply, write_cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdu_at_500() {
        assert_eq!(link_mdu(500), 431);
        assert_eq!(piece_size(500), 421);
        assert_eq!(mesh_box_size(MTU), crate::transport::box_size("mesh").unwrap());
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
