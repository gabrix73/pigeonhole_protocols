//! The thread under [`super::ReticulumRsBackend`]: berlinmesh/reticulum's TCP uplink, its leaf
//! router (announces, paths, identities), its `LinkDrv` for Link requests and Resources (query
//! mode 1), and [`ChanDrv`], Links that carry Channel (query mode 2 and push). The library's std
//! initiator has no Channel, so `ChanDrv` puts its Link handshake, keepalives and Channel
//! (`reticulum-link`, `reticulum-channel`) together here, as its `LinkDrv` does without Channel.

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{Receiver, RecvTimeoutError, TryRecvError, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reticulum_announce::{compute_name_hash, parse_and_verify_announce_scratch};
use reticulum_channel::{self as channel, Rx, Tx, TxEvent, Verdict};
use reticulum_client::linkdrv::{LinkDrv, LinkEvent, LinkOut, Registry, Route};
use reticulum_client::reqresp::RequestKind;
use reticulum_id::rustcrypto::{EphemeralX25519, LinkSigningKey, RustCryptoSigner};
use reticulum_id::{PublicBlob, Signer, fingerprint};
use reticulum_iface::{IfaceEvent as DriverEvent, IfaceId, IfaceIdAlloc};
use reticulum_ip_iface::{TcpUplink, TcpUplinkConfig};
use reticulum_link::terminus::{Expiry, OnIface, Terminus};
use reticulum_link::{
    CONTEXT_KEEPALIVE, CONTEXT_LINK_RTT, CONTEXT_LINKCLOSE, CONTEXT_LINKPROOF, CONTEXT_NONE, InitiatorKeys,
    KEEPALIVE_PACKET_LEN, KEEPALIVE_PING, KEEPALIVE_PONG, LINK_REQUEST_PAYLOAD_LEN, LinkId, LinkMode, LinkRole,
    LinkState, PROOF_PACKET_LEN, RTT_PAYLOAD_LEN, WatchdogConfig, accept_link_proof, encode_link_request,
    encode_rtt_payload, keepalive_packet, link_id_from_lr_wire, proof_packet, rns_packet_hash, token_len,
};
use reticulum_packet::{DestinationType, Header, HeaderType, MIN_HEADER_LEN, PacketType, TransportType, encode_packet};
use reticulum_router::{CoreEvent, IfaceEvent as RouterEvent, Router};
use tokio::sync::oneshot;

use super::{Frame, MSGTYPE, PUSH_MSGTYPE, Reassembler, piece_size, split, MTU};

const CONTEXT_CHANNEL: u8 = reticulum_packet::context::CHANNEL;
/// Envelopes kept for a resend, and early ones held, per Channel.
const WINDOW: usize = 8;
const HOLD: usize = 16;
const ENVELOPE_CAP: usize = 512;
const TICK_MS: u64 = 250;
const PATH_RETRY_MS: u64 = 3000;

pub type DestHash = [u8; 16];
pub type Reply = oneshot::Sender<Result<Vec<u8>, String>>;

/// A replica heard announcing `pigeonhole.replica`: its flags byte and hops away.
#[derive(Clone, Copy, Debug)]
pub struct Replica {
    pub flags: u8,
    pub hops: u8,
}

/// What the engine and the backend share: the replicas heard, by Box ID the boxes subscribed to,
/// and those pushed and not yet read.
#[derive(Default)]
pub struct Shared {
    pub replicas: Mutex<HashMap<DestHash, Replica>>,
    pub waiting: Mutex<HashMap<Vec<u8>, oneshot::Sender<()>>>,
    pub pushed: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

/// One query to `dest`, as Channel frames or as a Link request to `path`.
pub struct Query {
    pub dest: DestHash,
    pub channel: bool,
    pub path: &'static str,
    pub data: Vec<u8>,
    pub deadline: Instant,
    pub reply: Reply,
}

pub enum Cmd {
    Query(Query),
    Stop,
}

/// Starts the engine on a thread of its own, with a TCP uplink to `host:port`.
pub fn spawn(host: &str, port: u16, shared: Arc<Shared>) -> Result<std::sync::mpsc::Sender<Cmd>, String> {
    let mut private = [0u8; 64];
    getrandom::fill(&mut private).map_err(|e| e.to_string())?;
    let public = RustCryptoSigner::from_private_blob(&private).map_err(|e| format!("{e:?}"))?.public_blob();
    let mut router = Router::new(fingerprint(&public));
    router.set_transport_enabled(false);
    let mut seed = [0u8; 8];
    getrandom::fill(&mut seed).map_err(|e| e.to_string())?;
    router.mix_rng_entropy(u64::from_le_bytes(seed));
    let mut linkdrv = LinkDrv::new(&private, public, Box::new(|b| getrandom::fill(b).is_ok()))
        .map_err(|e| format!("{e:?}"))?;
    // Deadlines are the backend's, per query.
    linkdrv.set_request_timeout(3_600_000);
    let (iface_tx, iface_rx) = sync_channel(4096);
    let uplink = TcpUplink::spawn(TcpUplinkConfig::new(host, port), &IfaceIdAlloc::new(), iface_tx)
        .map_err(|e| format!("uplink to {host}:{port}: {e}"))?;
    let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
    let mut e = Engine {
        router,
        registry: Registry::new(),
        linkdrv,
        chan: ChanDrv::new(),
        iface_rx,
        cmd_rx,
        uplink,
        shared,
        name_hash: compute_name_hash("pigeonhole.replica"),
        held: Vec::new(),
        path_asked: HashMap::new(),
        requests: HashMap::new(),
        next_api: 0,
        frames: HashMap::new(),
        next_rid: 0,
        replies: Reassembler::default(),
        pushes: Reassembler::default(),
        last_tick: 0,
    };
    std::thread::Builder::new()
        .name("reticulum-rs".into())
        .spawn(move || e.run())
        .map_err(|e| e.to_string())?;
    Ok(cmd_tx)
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Fails the queries past their deadline, returning their Links.
fn late<K: Copy + Eq + std::hash::Hash>(m: &mut HashMap<K, InFlight>) -> Vec<LinkId> {
    let t = Instant::now();
    let keys: Vec<K> = m.iter().filter(|(_, f)| t >= f.deadline).map(|(k, _)| *k).collect();
    keys.into_iter()
        .filter_map(|k| m.remove(&k))
        .map(|f| {
            let _ = f.reply.send(Err("the replica did not answer".into()));
            f.link
        })
        .collect()
}

/// A query sent, waiting for its reply on `link`.
struct InFlight {
    link: LinkId,
    reply: Reply,
    deadline: Instant,
}

struct Engine {
    router: Router,
    registry: Registry,
    linkdrv: LinkDrv,
    chan: ChanDrv,
    iface_rx: Receiver<DriverEvent>,
    cmd_rx: Receiver<Cmd>,
    uplink: TcpUplink,
    shared: Arc<Shared>,
    name_hash: [u8; 10],
    /// Queries waiting for a path or a Link.
    held: Vec<Query>,
    path_asked: HashMap<DestHash, u64>,
    /// Link requests by api id, and Channel queries by request id.
    requests: HashMap<u64, InFlight>,
    next_api: u64,
    frames: HashMap<u16, InFlight>,
    next_rid: u16,
    replies: Reassembler,
    pushes: Reassembler,
    last_tick: u64,
}

impl Engine {
    fn run(&mut self) {
        loop {
            match self.iface_rx.recv_timeout(Duration::from_millis(10)) {
                Ok(ev) => self.on_iface(ev),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => std::thread::sleep(Duration::from_millis(10)),
            }
            loop {
                match self.cmd_rx.try_recv() {
                    Ok(Cmd::Query(q)) => self.query(q),
                    Err(TryRecvError::Empty) => break,
                    Ok(Cmd::Stop) | Err(TryRecvError::Disconnected) => return self.stop(),
                }
            }
            let now = now_ms();
            if now.saturating_sub(self.last_tick) >= TICK_MS {
                self.last_tick = now;
                self.tick(now);
            }
            self.drain();
        }
    }

    fn stop(&mut self) {
        self.linkdrv.close_all(&mut self.registry);
        self.chan.close_all(&mut self.registry);
        self.uplink.shutdown();
    }

    fn on_iface(&mut self, ev: DriverEvent) {
        let now = now_ms();
        match ev {
            DriverEvent::Up { iface, parent } => {
                let id = self.registry.attach(iface);
                self.router.handle(CoreEvent::Iface(RouterEvent::Up { iface: id.into(), parent }), now, &mut self.registry);
            }
            DriverEvent::Down { id } => {
                self.router.handle(CoreEvent::Iface(RouterEvent::Down { id }), now, &mut self.registry);
                self.registry.detach(id);
            }
            DriverEvent::Frame { id, packet } => self.on_frame(id, packet, now),
        }
    }

    fn on_frame(&mut self, id: IfaceId, packet: Vec<u8>, now: u64) {
        let hdr = Header::decode(&packet).ok().map(|(h, _)| h);
        match hdr {
            Some(h) if h.packet_type == PacketType::Announce => {
                let mut scratch = [0u8; 512];
                let replica = parse_and_verify_announce_scratch::<RustCryptoSigner>(&packet, &mut scratch)
                    .ok()
                    .filter(|a| a.name_hash == self.name_hash)
                    .map(|a| (a.header.destination_hash, a.app_data.first().copied().unwrap_or(0)));
                self.route(id, packet, now);
                if let Some((dest, flags)) = replica {
                    let hops = self.router.hops_to(&dest).unwrap_or(u8::MAX);
                    self.shared.replicas.lock().unwrap().insert(dest, Replica { flags, hops });
                }
            }
            Some(h) if self.chan.wants(&h.destination_hash) => {
                self.chan.handle_frame(id, &packet, now, &mut self.registry)
            }
            Some(h) if self.linkdrv.wants(&h.destination_hash) => {
                self.linkdrv.handle_frame(id, &packet, now, &mut self.registry)
            }
            _ => self.route(id, packet, now),
        }
    }

    fn route(&mut self, id: IfaceId, packet: Vec<u8>, now: u64) {
        self.router.handle(CoreEvent::Iface(RouterEvent::Frame { id, packet }), now, &mut self.registry);
    }

    fn route_to(&self, dest: &DestHash) -> Option<(Route, PublicBlob)> {
        let p = self.router.path(dest)?;
        let iface = self.router.iface_for_slot(p.iface)?;
        let next_hop = (p.next_hop != *dest).then_some(p.next_hop);
        Some((Route { iface, next_hop }, *self.router.recall_public(dest)?))
    }

    /// Sends `q` on its Link, opening one first, or holds it for a path or a Link.
    fn query(&mut self, q: Query) {
        if Instant::now() >= q.deadline {
            let _ = q.reply.send(Err("the replica did not answer".into()));
            return;
        }
        let now = now_ms();
        let active = if q.channel { self.chan.active(&q.dest) } else { self.linkdrv.link_for_dest(&q.dest).filter(|_| self.linkdrv.is_active(&q.dest)) };
        let Some(link) = active else {
            let opening = if q.channel { self.chan.link(&q.dest).is_some() } else { self.linkdrv.link_for_dest(&q.dest).is_some() };
            if !opening {
                match self.route_to(&q.dest) {
                    Some((route, public)) => {
                        let ok = if q.channel {
                            self.chan.establish(q.dest, &public, route, now, &mut self.registry).is_some()
                        } else {
                            self.linkdrv.establish(q.dest, &public, route, now, &mut self.registry).is_ok()
                        };
                        if !ok {
                            let _ = q.reply.send(Err("no Link to the replica".into()));
                            return;
                        }
                    }
                    None if now >= self.path_asked.get(&q.dest).copied().unwrap_or(0) => {
                        self.router.request_path(&q.dest, now, &mut self.registry);
                        self.path_asked.insert(q.dest, now + PATH_RETRY_MS);
                    }
                    None => {}
                }
            }
            self.held.push(q);
            return;
        };
        let deadline = q.deadline;
        if q.channel {
            let rid = self.next_rid;
            self.next_rid = rid.wrapping_add(1);
            let frames = match split(rid, &q.data, piece_size(MTU)) {
                Ok(f) => f,
                Err(e) => {
                    let _ = q.reply.send(Err(e.to_string()));
                    return;
                }
            };
            for f in frames {
                self.chan.send(&link, MSGTYPE, f.to_bytes(), now, &mut self.registry);
            }
            self.frames.insert(rid, InFlight { link, reply: q.reply, deadline });
        } else {
            let api = self.next_api;
            self.next_api += 1;
            let mut data = vec![0u8; q.data.len() + 5];
            let mut enc = reticulum_msgpack::Encoder::new(&mut data);
            let n = enc.write_bin(&q.data).map(|_| enc.position());
            let sent = n.ok().and_then(|n| {
                self.linkdrv.send_request(&link, api, q.path, Some(&data[..n]), RequestKind::Page, now, &mut self.registry)
            });
            if sent.is_none() {
                let _ = q.reply.send(Err("could not send the request".into()));
                return;
            }
            self.requests.insert(api, InFlight { link, reply: q.reply, deadline });
        }
    }

    fn retry_held(&mut self) {
        for q in std::mem::take(&mut self.held) {
            self.query(q);
        }
    }

    fn tick(&mut self, now: u64) {
        self.router.handle(CoreEvent::Tick, now, &mut self.registry);
        self.linkdrv.tick(now, &mut self.registry);
        self.chan.tick(now, &mut self.registry);
        self.retry_held();
        // A query unanswered in time takes its Link down, as one lost would be.
        for link in late(&mut self.frames) {
            log::debug!("reticulum-rs: a Channel query timed out");
            self.chan.close(&link, &mut self.registry);
        }
        for link in late(&mut self.requests) {
            log::debug!("reticulum-rs: a Link request timed out");
            self.linkdrv.close(&link, &mut self.registry);
        }
    }

    fn drain(&mut self) {
        let mut opened = false;
        while let Some(ev) = self.linkdrv.poll_event() {
            match ev {
                LinkEvent::Established { .. } => {
                    log::debug!("reticulum-rs: request Link up");
                    opened = true
                }
                LinkEvent::Closed { reason, .. } => log::debug!("reticulum-rs: request Link closed: {reason:?}"),
                LinkEvent::Response { api_request_id, content, .. } => {
                    if let Some(f) = self.requests.remove(&api_request_id) {
                        let _ = f.reply.send(Ok(content));
                    }
                }
                LinkEvent::RequestFailed { api_request_id: id, reason } | LinkEvent::ResourceSendFailed { tag: id, reason, .. } => {
                    if let Some(f) = self.requests.remove(&id) {
                        let _ = f.reply.send(Err(reason));
                    }
                }
                LinkEvent::Notice(n) => log::debug!("reticulum-rs: {n}"),
                _ => {}
            }
        }
        while let Some(ev) = self.chan.poll_event() {
            match ev {
                ChanEvent::Established => {
                    log::debug!("reticulum-rs: Channel Link up");
                    opened = true
                }
                ChanEvent::Closed(link) => {
                    log::debug!("reticulum-rs: Channel Link closed");
                    let lost: Vec<u16> = self.frames.iter().filter(|(_, f)| f.link == link).map(|(k, _)| *k).collect();
                    for k in lost {
                        let _ = self.frames.remove(&k).unwrap().reply.send(Err("Link to the replica closed".into()));
                    }
                    // The Link's subscriptions go with it; their watchers wake to read and subscribe again.
                    self.shared.waiting.lock().unwrap().clear();
                    self.replies = Reassembler::default();
                    self.pushes = Reassembler::default();
                }
                ChanEvent::Message(MSGTYPE, data) => {
                    let Some(f) = Frame::from_bytes(&data) else { continue };
                    let rid = f.request_id;
                    if let Some(whole) = self.replies.feed(f)
                        && let Some(q) = self.frames.remove(&rid)
                    {
                        let _ = q.reply.send(Ok(whole));
                    }
                }
                ChanEvent::Message(PUSH_MSGTYPE, data) => {
                    let Some(f) = Frame::from_bytes(&data) else { continue };
                    if let Some(d) = self.pushes.feed(f)
                        && d.len() > 32
                        && let Some(tx) = self.shared.waiting.lock().unwrap().remove(&d[..32])
                    {
                        self.shared.pushed.lock().unwrap().insert(d[..32].to_vec(), d[32..].to_vec());
                        let _ = tx.send(());
                    }
                }
                ChanEvent::Message(t, _) => log::debug!("reticulum-rs: Channel message of type {t:#x} dropped"),
            }
        }
        if opened {
            self.retry_held();
        }
    }
}

/// A Channel Link's own state: how it goes, and its Channel.
struct ChanMeta {
    iface: IfaceId,
    peer_public: PublicBlob,
    rtt_ms: u32,
    tx: Box<Tx<WINDOW, ENVELOPE_CAP>>,
    rx: Box<Rx<HOLD, ENVELOPE_CAP>>,
    /// Messages waiting for room in the send window.
    queue: VecDeque<(u16, Vec<u8>)>,
}

impl OnIface for ChanMeta {
    fn iface(&self) -> u32 {
        self.iface
    }
}

enum ChanEvent {
    Established,
    Closed(LinkId),
    Message(u16, Vec<u8>),
}

/// Initiator Links carrying a Channel (canon `RNS/Channel.py`), at the 500 byte MTU.
struct ChanDrv {
    term: Terminus<ChanMeta, ChanEvent, 4>,
    by_dest: HashMap<DestHash, LinkId>,
}

impl ChanDrv {
    fn new() -> Self {
        ChanDrv {
            term: Terminus::new(Box::new(|b| getrandom::fill(b).is_ok()), WatchdogConfig::defaults()),
            by_dest: HashMap::new(),
        }
    }

    fn wants(&self, id: &LinkId) -> bool {
        self.term.links().get(id).is_some_and(|l| l.state != LinkState::Closed)
    }

    /// The Link to `dest`, pending or up.
    fn link(&self, dest: &DestHash) -> Option<LinkId> {
        self.by_dest.get(dest).copied().filter(|id| self.wants(id))
    }

    fn active(&self, dest: &DestHash) -> Option<LinkId> {
        self.link(dest).filter(|id| {
            self.term.links().get(id).is_some_and(|l| matches!(l.state, LinkState::Active | LinkState::Stale))
        })
    }

    fn poll_event(&mut self) -> Option<ChanEvent> {
        self.term.poll_event()
    }

    /// Sends a Link request to `dest` and holds the Link pending until its proof.
    fn establish(&mut self, dest: DestHash, peer: &PublicBlob, route: Route, now: u64, out: &mut Registry) -> Option<LinkId> {
        if let Some(id) = self.link(&dest) {
            return Some(id);
        }
        let mut keys = InitiatorKeys { eph_secret: [0; 32], sig_seed: [0; 32] };
        let rng = self.term.rng_mut();
        if !rng(&mut keys.eph_secret) || !rng(&mut keys.sig_seed) {
            return None;
        }
        let eph = EphemeralX25519::generate(|b| {
            b.copy_from_slice(&keys.eph_secret[..b.len()]);
            Ok(())
        })
        .ok()?;
        let sig_pub = LinkSigningKey::from_seed(&keys.sig_seed).public_key();
        let mut lr = [0u8; LINK_REQUEST_PAYLOAD_LEN];
        let n = encode_link_request(&eph.public_key(), &sig_pub, None, &mut lr).ok()?;
        // The Link id is the same through relays: it hashes the direct form.
        let hdr1 = Header::new_link_request(dest);
        let mut h = [0u8; MIN_HEADER_LEN];
        hdr1.encode(&mut h).ok()?;
        let id = link_id_from_lr_wire(&h, &lr[..n]);
        let header = match route.next_hop {
            None => hdr1,
            Some(next) => Header {
                header_type: HeaderType::Hdr2,
                transport_type: TransportType::Transport,
                transport_id: Some(next),
                destination_type: DestinationType::Single,
                packet_type: PacketType::LinkRequest,
                ..hdr1
            },
        };
        let mut packet = [0u8; MIN_HEADER_LEN + 16 + LINK_REQUEST_PAYLOAD_LEN];
        let pn = encode_packet(header, &lr[..n], &mut packet).ok()?;
        self.term
            .links_mut()
            .insert_pending(id, fingerprint(peer), LinkMode::Aes256Cbc, LinkRole::Initiator, Some(&keys), now)
            .ok()?;
        self.term.meta_mut().insert(
            id,
            ChanMeta {
                iface: route.iface,
                peer_public: *peer,
                rtt_ms: 0,
                tx: Box::new(Tx::new(0)),
                rx: Box::default(),
                queue: VecDeque::new(),
            },
        );
        self.by_dest.insert(dest, id);
        if !LinkOut::send(out, route.iface, &packet[..pn]) {
            self.finish(&id);
            return None;
        }
        Some(id)
    }

    fn handle_frame(&mut self, _iface: IfaceId, raw: &[u8], now: u64, out: &mut Registry) {
        let Ok((hdr, payload)) = Header::decode(raw) else { return };
        let id = hdr.destination_hash;
        match (hdr.packet_type, hdr.context_byte) {
            (PacketType::Proof, CONTEXT_LINKPROOF) => self.on_link_proof(&id, payload, now, out),
            (PacketType::Proof, CONTEXT_NONE) => self.on_proof(&id, payload, now, out),
            (_, CONTEXT_KEEPALIVE) if payload == [KEEPALIVE_PONG] => {
                let _ = self.term.links_mut().touch(&id, now);
            }
            (_, CONTEXT_LINKCLOSE) => {
                if self.term.peer_close(&id, payload).is_ok() {
                    self.closed(&id);
                }
            }
            (PacketType::Data, CONTEXT_CHANNEL) => self.on_channel(&id, raw, payload, now, out),
            _ => {}
        }
    }

    /// The Link proof: checked against the replica's announced key, then RTT and active.
    fn on_link_proof(&mut self, id: &LinkId, payload: &[u8], now: u64, out: &mut Registry) {
        let Some(link) = self.term.links().get(id).copied() else { return };
        if link.state != LinkState::Pending || link.role != LinkRole::Initiator {
            return;
        }
        let (Some(eph), Some(peer)) = (self.term.links().pending_secret(id), self.term.meta().get(id).map(|m| m.peer_public)) else {
            return;
        };
        let Ok(a) = accept_link_proof(id, &peer, &eph, payload, LinkMode::default()) else {
            log::warn!("reticulum-rs: a Link proof refused");
            return;
        };
        if self.term.links_mut().promote_to_handshake(id, a.sign_key(), a.enc_key(), now).is_err() {
            return;
        }
        let rtt = now.saturating_sub(link.established_tick) as u32;
        let mut pt = [0u8; RTT_PAYLOAD_LEN];
        let Ok(n) = encode_rtt_payload(rtt as f64 / 1000.0, &mut pt) else { return };
        if self.seal_send(id, CONTEXT_LINK_RTT, &pt[..n], out).is_none()
            || self.term.links_mut().promote_to_active(id, now, rtt).is_err()
        {
            return;
        }
        if let Some(m) = self.term.meta_mut().get_mut(id) {
            m.rtt_ms = rtt;
            m.tx.reset(rtt);
        }
        self.term.emit(ChanEvent::Established);
        self.flush(id, now, out);
    }

    /// A proof of one of our envelopes, `packet hash || signature` by the replica's key.
    fn on_proof(&mut self, id: &LinkId, payload: &[u8], now: u64, out: &mut Registry) {
        let Some(m) = self.term.meta_mut().get_mut(id) else { return };
        let (Ok(hash), Ok(sig)) = (
            <[u8; 32]>::try_from(payload.get(..32).unwrap_or_default()),
            <[u8; 64]>::try_from(payload.get(32..96).unwrap_or_default()),
        ) else {
            return;
        };
        if RustCryptoSigner::verify(&m.peer_public, &hash, &sig).is_err() || m.tx.proved(&hash).is_none() {
            return;
        }
        let _ = self.term.links_mut().touch(id, now);
        self.flush(id, now, out);
    }

    fn on_channel(&mut self, id: &LinkId, raw: &[u8], payload: &[u8], now: u64, out: &mut Registry) {
        let Ok(pt) = self.term.open_touch(id, payload, now) else { return };
        let Some(env) = channel::decode(&pt) else { return };
        let Some(m) = self.term.meta_mut().get_mut(id) else { return };
        let verdict = m.rx.receive(&env);
        let mut got = Vec::new();
        if verdict == Verdict::Deliver {
            got.push((env.msgtype, env.payload.to_vec()));
            let mut buf = [0u8; ENVELOPE_CAP];
            while let Some((t, n)) = m.rx.take_ready(&mut buf) {
                got.push((t, buf[..n].to_vec()));
            }
        }
        // Proved only when kept, so the replica sends again what was refused.
        if verdict.prove() {
            self.prove(id, raw, out);
        }
        for (t, d) in got {
            self.term.emit(ChanEvent::Message(t, d));
        }
    }

    fn prove(&mut self, id: &LinkId, raw: &[u8], out: &mut Registry) {
        let (Ok(hash), Some(iface), Some(seed)) = (rns_packet_hash(raw), self.term.iface_of(id), self.term.links().signing_seed(id)) else {
            return;
        };
        let sig = LinkSigningKey::from_seed(seed).sign(&hash);
        let mut packet = [0u8; PROOF_PACKET_LEN];
        if let Some(n) = proof_packet(*id, &hash, &sig, &mut packet) {
            LinkOut::send(out, iface, &packet[..n]);
        }
    }

    /// Seals `plaintext` as link data with `context` and sends it, returning the packet's hash.
    fn seal_send(&mut self, id: &LinkId, context: u8, plaintext: &[u8], out: &mut Registry) -> Option<[u8; 32]> {
        let link = *self.term.links().get(id)?;
        let iface = self.term.iface_of(id)?;
        let mut packet = vec![0u8; MIN_HEADER_LEN + token_len(plaintext.len())];
        let n = link.seal_packet(context, plaintext, self.term.rng_mut(), &mut packet).ok()?;
        LinkOut::send(out, iface, &packet[..n]).then(|| rns_packet_hash(&packet[..n]).ok()).flatten()
    }

    /// Queues a Channel message of type `t` on Link `id`.
    fn send(&mut self, id: &LinkId, t: u16, payload: Vec<u8>, now: u64, out: &mut Registry) {
        if let Some(m) = self.term.meta_mut().get_mut(id) {
            m.queue.push_back((t, payload));
        }
        self.flush(id, now, out);
    }

    /// Sends what the window has room for.
    fn flush(&mut self, id: &LinkId, now: u64, out: &mut Registry) {
        if !self.term.links().get(id).is_some_and(|l| l.state == LinkState::Active || l.state == LinkState::Stale) {
            return;
        }
        loop {
            let Some(m) = self.term.meta_mut().get_mut(id) else { return };
            if !m.tx.ready() {
                return;
            }
            let Some((t, p)) = m.queue.pop_front() else { return };
            let mut env = vec![0u8; channel::HEADER_LEN + p.len()];
            if channel::encode(t, m.tx.next_sequence(), &p, &mut env).is_none() {
                continue;
            }
            let rtt = m.rtt_ms;
            let Some(hash) = self.seal_send(id, CONTEXT_CHANNEL, &env, out) else {
                if let Some(m) = self.term.meta_mut().get_mut(id) {
                    m.queue.push_front((t, p));
                }
                return;
            };
            if let Some(m) = self.term.meta_mut().get_mut(id) {
                m.tx.sent(&env, hash, now, rtt);
            }
        }
    }

    fn tick(&mut self, now: u64, out: &mut Registry) {
        while let Some(e) = self.term.next_expiry(now) {
            match e {
                Expiry::Establishment(id) => self.finish(&id),
                Expiry::Keepalive(id) => {
                    let mut packet = [0u8; KEEPALIVE_PACKET_LEN];
                    if let (Some(iface), Some(n)) = (self.term.iface_of(&id), keepalive_packet(id, KEEPALIVE_PING, &mut packet)) {
                        LinkOut::send(out, iface, &packet[..n]);
                    }
                }
                Expiry::Stale(id) => self.close(&id, out),
            }
        }
        let ids: Vec<LinkId> = self.term.meta().keys().copied().collect();
        for id in ids {
            while let Some(m) = self.term.meta_mut().get_mut(&id) {
                let rtt = m.rtt_ms;
                let (seq, env) = match m.tx.poll(now, rtt) {
                    TxEvent::Idle => break,
                    TxEvent::Teardown => {
                        self.close(&id, out);
                        break;
                    }
                    TxEvent::Resend { seq, envelope } => (seq, envelope.to_vec()),
                };
                match self.seal_send(&id, CONTEXT_CHANNEL, &env, out) {
                    Some(h) => self.term.meta_mut().get_mut(&id).unwrap().tx.resent(seq, h),
                    None => break,
                }
            }
            self.flush(&id, now, out);
        }
    }

    fn close(&mut self, id: &LinkId, out: &mut Registry) {
        if let Some(w) = self.term.close_wire(id) {
            LinkOut::send(out, w.iface, w.as_bytes());
        }
        self.finish(id);
    }

    fn close_all(&mut self, out: &mut Registry) {
        let ids: Vec<LinkId> = self.term.meta().keys().copied().collect();
        for id in ids {
            self.close(&id, out);
        }
    }

    fn finish(&mut self, id: &LinkId) {
        self.term.close(id);
        self.closed(id);
    }

    fn closed(&mut self, id: &LinkId) {
        self.term.links_mut().free_closed();
        self.by_dest.retain(|_, l| l != id);
        self.term.emit(ChanEvent::Closed(*id));
    }
}
