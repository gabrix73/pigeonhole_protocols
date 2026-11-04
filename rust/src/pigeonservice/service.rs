//! The service runtime: links with voucher routers, the directory, and the
//! sessions clients open.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use blake2::{Blake2b, Digest, digest::consts::U32};
use rand::RngCore;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::pigeonservice::Error;
use crate::pigeonservice::cbor::{self, Fields};
use crate::pigeonservice::conn::{Conn, ConnState};
use crate::pigeonservice::directory::Directory;
use crate::pigeonservice::handshake::{self, Pending};
use crate::pigeonservice::lease::{self, MAX_ENTRY_TTL, MAX_LINK_TTL, lease_expiry};
use crate::pigeonservice::link::{open_forward, register, renew};
use crate::pigeonservice::nike::{self, Keypair};
use crate::pigeonservice::pigeonhole::DEFAULT_POLL_INTERVAL;
use crate::transport::{Backend, ServiceNode};
use crate::pigeonservice::wire::{ROUTER_CAPABILITY, RouterRef, ServiceDescriptor, ServiceId, Status};

/// How long an opened voucher is remembered, so one forwarded twice is
/// handled once.
const VOUCHER_DEDUP_TTL: Duration = Duration::from_secs(3600);
/// Bounds the vouchers waiting to be accepted.
const INCOMING_QUEUE_SIZE: usize = 256;
/// Bounds the withdrawal [`Service::close`] sends.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2 * 60);

/// Configures a [`Service`].
#[derive(Clone)]
pub struct Config {
    /// The service's keypair; see [`Keypair::load_or_generate`].
    pub key: Keypair,
    /// Holds the service's state.
    pub data_dir: PathBuf,
    /// The name the service gives itself to clients.
    pub display_name: String,
    /// Whether to advertise the service in every directory in the PKI.
    pub advertise: bool,
    /// How often a pending read is retried.
    pub poll_interval: Duration,
    /// Bounds the sessions [`Service::run`] serves at once.
    pub max_concurrent_sessions: usize,
    /// How long a sent message is kept rewritten.
    pub retention: Duration,
    /// How long a registration with a router has to complete before it is
    /// abandoned and retried on the next rescan.
    pub register_timeout: Duration,
    /// How long a client's handshake may take.
    pub handshake_timeout: Duration,
    /// How often the service looks for new routers.
    pub rescan_interval: Duration,
    /// The lease asked of each router, renewed once half of it has
    /// passed; at most [`MAX_LINK_TTL`].
    pub link_ttl: Duration,
    /// The lease asked of each directory, renewed once half of it has
    /// passed; at most [`MAX_ENTRY_TTL`].
    pub advertise_ttl: Duration,
}

impl Config {
    /// A configuration with the defaults.
    pub fn new(key: Keypair, data_dir: impl Into<PathBuf>) -> Self {
        Config {
            key,
            data_dir: data_dir.into(),
            display_name: "service".into(),
            advertise: true,
            poll_interval: DEFAULT_POLL_INTERVAL,
            max_concurrent_sessions: 64,
            retention: Duration::from_secs(7 * 24 * 3600),
            register_timeout: Duration::from_secs(15 * 60),
            handshake_timeout: Duration::from_secs(10 * 60),
            rescan_interval: Duration::from_secs(10 * 60),
            link_ttl: MAX_LINK_TTL,
            advertise_ttl: MAX_ENTRY_TTL,
        }
    }
}

/// A service's connection with one client. It derefs to its [`Conn`].
pub struct Session<B: Backend> {
    conn: Arc<Conn<B>>,
    id: [u8; 16],
    restored: bool,
    inner: Arc<Inner<B>>,
}

impl<B: Backend> Deref for Session<B> {
    type Target = Conn<B>;

    fn deref(&self) -> &Conn<B> {
        &self.conn
    }
}

impl<B: Backend> Session<B> {
    /// Whether the session was restored from disk rather than opened since
    /// the service started.
    pub fn restored(&self) -> bool {
        self.restored
    }

    /// Ends the session and forgets it.
    pub fn close(self) {
        self.inner.drop_session(&self.id, &self.conn);
    }
}

enum Arrival<B: Backend> {
    Voucher(Vec<u8>),
    Ready(Session<B>),
}

/// A client's arrival: a voucher to induct, or a session that is already
/// open (one restored from disk, or one that took a voucher from
/// [`Service::offer`]).
pub struct Incoming<B: Backend> {
    arrival: Arrival<B>,
    inner: Arc<Inner<B>>,
}

impl<B: Backend> Incoming<B> {
    /// The voucher this arrival carries, for a service that inducts vouchers
    /// its own way; a restored session comes back as the error. The voucher
    /// is forgotten, so it is not offered again after a restart.
    pub fn voucher(self) -> Result<Vec<u8>, Session<B>> {
        match self.arrival {
            Arrival::Voucher(v) => {
                self.inner.forget_voucher(&v);
                Ok(v)
            }
            Arrival::Ready(s) => Err(s),
        }
    }

    /// Runs the service's side of the handshake if one is needed and
    /// returns the session.
    pub async fn handshake(self) -> Result<Session<B>, Error> {
        match self.arrival {
            Arrival::Ready(s) => Ok(s),
            Arrival::Voucher(v) => {
                let inner = &self.inner;
                let cfg = &inner.cfg;
                let res = tokio::time::timeout(cfg.handshake_timeout, handshake::induct(inner.ph.clone(), &v, &cfg.display_name, cfg.poll_interval)).await;
                let session = match res {
                    Ok(Ok(conn)) => Ok(inner.add_session(conn)),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err(Error::Other("handshake timed out".into())),
                };
                inner.forget_voucher(&v);
                session
            }
        }
    }
}

struct LinkState<B: Backend> {
    node: ServiceNode,
    conn: Arc<Conn<B>>,
    /// The link's lease, Unix seconds.
    expiry: AtomicU64,
    /// Cancelled when the link is dropped.
    stop: CancellationToken,
}

impl<B: Backend> LinkState<B> {
    fn new(node: ServiceNode, conn: Conn<B>, expiry: u64) -> Arc<Self> {
        Arc::new(LinkState { node, conn: Arc::new(conn), expiry: AtomicU64::new(expiry), stop: CancellationToken::new() })
    }
}

struct State<B: Backend> {
    links: HashMap<[u8; 32], Arc<LinkState<B>>>,
    registering: HashSet<[u8; 32]>,
    sessions: HashMap<[u8; 16], Arc<Conn<B>>>,
    offers: HashMap<[u8; 32], Pending>,
    vouchers: HashMap<[u8; 32], Instant>,
    /// Vouchers read from links and not yet handled when the service last
    /// stopped.
    unhandled: Vec<Vec<u8>>,
    listening: bool,
    /// The expiry of the last advertisement taken.
    advertised: u64,
}

struct Inner<B: Backend> {
    cfg: Config,
    ph: Arc<B>,
    store: Store,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    incoming_tx: mpsc::Sender<Arrival<B>>,
    incoming_rx: tokio::sync::Mutex<mpsc::Receiver<Arrival<B>>>,
    directories: tokio::sync::OnceCell<Vec<Directory<B>>>,
    state: Mutex<State<B>>,
}

/// A pigeonhole service: it holds links with voucher routers, advertises
/// them, and accepts the clients who reach it through them.
pub struct Service<B: Backend> {
    inner: Arc<Inner<B>>,
}

impl<B: Backend> Clone for Service<B> {
    fn clone(&self) -> Self {
        Service { inner: self.inner.clone() }
    }
}

impl<B: Backend> Service<B> {
    /// Opens the service's state and restores its links, sessions and
    /// offered vouchers. Call [`Service::listen`] or [`Service::run`] to
    /// start it.
    pub fn new(cfg: Config, ph: Arc<B>) -> Result<Self, Error> {
        let store = Store::open(&cfg.data_dir)?;
        let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_QUEUE_SIZE);
        let mut state = State {
            links: HashMap::new(),
            registering: HashSet::new(),
            sessions: HashMap::new(),
            offers: HashMap::new(),
            vouchers: HashMap::new(),
            unhandled: Vec::new(),
            listening: false,
            advertised: 0,
        };
        for raw in store.load(LINKS)? {
            let v = cbor::decode(&raw)?;
            let f = Fields::of(&v)?;
            let node = ServiceNode { node_id_hash: f.array32("NodeIDHash")?, endpoint: f.bytes("Endpoint")?, params: Default::default() };
            let conn = Conn::restore(ph.clone(), &ConnState::from_value(f.get("Conn").ok_or(Error::Decode("link without Conn".into()))?)?, cfg.poll_interval);
            let expiry = f.get("Expiry").map(|_| f.uint("Expiry")).transpose()?.unwrap_or(0);
            state.links.insert(node.node_id_hash, LinkState::new(node, conn, expiry));
        }
        for (key, raw) in store.load_keyed(SESSIONS)? {
            let id: [u8; 16] = key.try_into().map_err(|_| Error::Decode("bad session file name".into()))?;
            state.sessions.insert(id, Arc::new(Conn::restore(ph.clone(), &ConnState::decode(&raw)?, cfg.poll_interval)));
        }
        for raw in store.load(OFFERS)? {
            let p = Pending::decode(&raw)?;
            state.offers.insert(hash(&p.voucher), p);
        }
        for v in store.load(VOUCHERS)? {
            state.vouchers.insert(hash(&v), Instant::now());
            state.unhandled.push(v);
        }
        Ok(Service {
            inner: Arc::new(Inner {
                cfg,
                ph,
                store,
                shutdown: CancellationToken::new(),
                tasks: TaskTracker::new(),
                incoming_tx,
                incoming_rx: tokio::sync::Mutex::new(incoming_rx),
                directories: tokio::sync::OnceCell::new(),
                state: Mutex::new(state),
            }),
        })
    }

    /// The service's ID.
    pub fn id(&self) -> ServiceId {
        ServiceId::from_public_key(&self.inner.cfg.key.public.to_bytes())
    }
    /// The Pigeonhole the service is on.
    pub fn pigeonhole(&self) -> &Arc<B> {
        &self.inner.ph
    }
    /// How often a pending read is retried.
    pub fn poll_interval(&self) -> Duration {
        self.inner.cfg.poll_interval
    }

    /// The service's current descriptor: its key and the routers it holds
    /// links with.
    pub fn descriptor(&self) -> ServiceDescriptor {
        self.inner.descriptor()
    }

    /// Starts the service: resumes its links, registers with every router
    /// in the PKI it has no link with, and advertises itself. Sessions
    /// restored from disk are the first arrivals [`Service::accept`]
    /// returns.
    pub fn listen(&self) -> Result<(), Error> {
        let inner = &self.inner;
        let (links, sessions, offers, unhandled) = {
            let mut st = inner.state.lock().unwrap();
            if st.listening {
                return Err(Error::Other("already listening".into()));
            }
            st.listening = true;
            (
                st.links.values().cloned().collect::<Vec<_>>(),
                st.sessions.iter().map(|(id, c)| (*id, c.clone())).collect::<Vec<_>>(),
                st.offers.values().cloned().collect::<Vec<_>>(),
                std::mem::take(&mut st.unhandled),
            )
        };
        let restored: Vec<Session<B>> = sessions
            .into_iter()
            .map(|(id, conn)| {
                inner.watch_session(id, &conn);
                Session { conn, id, restored: true, inner: inner.clone() }
            })
            .collect();
        let i = inner.clone();
        inner.spawn(async move {
            for s in restored {
                if i.incoming_tx.send(Arrival::Ready(s)).await.is_err() {
                    return;
                }
            }
            for v in unhandled {
                if i.incoming_tx.send(Arrival::Voucher(v)).await.is_err() {
                    return;
                }
            }
        });
        for l in links {
            inner.start_link(l);
        }
        for p in offers {
            inner.await_offer(p);
        }
        let i = inner.clone();
        inner.spawn(async move { i.registrar().await });
        let i = inner.clone();
        inner.spawn(async move { i.refresher().await });
        if !inner.state.lock().unwrap().links.is_empty() {
            let i = inner.clone();
            inner.spawn(async move { i.advertise().await });
        }
        Ok(())
    }

    /// Returns the next client's arrival.
    pub async fn accept(&self) -> Result<Incoming<B>, Error> {
        let mut rx = self.inner.incoming_rx.lock().await;
        tokio::select! {
            a = rx.recv() => a.map(|arrival| Incoming { arrival, inner: self.inner.clone() }).ok_or(Error::Closed),
            _ = self.inner.shutdown.cancelled() => Err(Error::Closed),
        }
    }

    /// Listens and serves each session with `handler` in its own task, at
    /// most `max_concurrent_sessions` at once, until the service closes. A
    /// session ends when its handler returns.
    pub async fn run<F, Fut>(&self, handler: F) -> Result<(), Error>
    where
        F: Fn(Session<B>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.listen()?;
        let handler = Arc::new(handler);
        let sem = Arc::new(Semaphore::new(self.inner.cfg.max_concurrent_sessions.max(1)));
        loop {
            let incoming = match self.accept().await {
                Ok(i) => i,
                Err(Error::Closed) => return Ok(()),
                Err(e) => return Err(e),
            };
            let permit = tokio::select! {
                p = sem.clone().acquire_owned() => p.expect("semaphore is never closed"),
                _ = self.inner.shutdown.cancelled() => return Ok(()),
            };
            let handler = handler.clone();
            let inner = self.inner.clone();
            self.inner.spawn(async move {
                let _permit = permit;
                let session = match incoming.handshake().await {
                    Ok(s) => s,
                    Err(e) => {
                        log::warn!("handshake with a client: {e}");
                        return;
                    }
                };
                // Ends the session when the handler returns or panics.
                let _end = EndSession(inner, session.id, session.conn.clone());
                handler(session).await;
            });
        }
    }

    /// Mints a contact voucher a client can induct directly, without a
    /// router: the service is the joiner and the client the inductor, as
    /// when someone adds a contact in a chat client. The voucher is kept
    /// across restarts until a client uses it; the session it opens is
    /// returned by [`Service::accept`]. Requires [`Service::listen`].
    pub async fn offer(&self) -> Result<Vec<u8>, Error> {
        let inner = &self.inner;
        if !inner.state.lock().unwrap().listening {
            return Err(Error::Other("offer needs a listening service".into()));
        }
        let p = handshake::mint(&*inner.ph, &inner.cfg.display_name).await?;
        let key = hash(&p.voucher);
        inner.store.put(OFFERS, &key, &p.encode())?;
        inner.state.lock().unwrap().offers.insert(key, p.clone());
        let voucher = p.voucher.clone();
        inner.await_offer(p);
        Ok(voucher)
    }

    /// The vouchers from [`Service::offer`] no client has used yet.
    pub fn offers(&self) -> Vec<Vec<u8>> {
        self.inner.state.lock().unwrap().offers.values().map(|p| p.voucher.clone()).collect()
    }

    /// Stops the service and waits for its tasks, withdrawing it from the
    /// directories it is advertised in. Its links with routers are kept for
    /// the next start; a router forgets one that is not renewed within its
    /// lease.
    pub async fn close(&self) {
        let advertised = self.inner.state.lock().unwrap().advertised != 0;
        if advertised && tokio::time::timeout(CLOSE_TIMEOUT, self.inner.withdraw()).await.is_err() {
            log::warn!("withdrawing: timed out");
        }
        self.inner.shutdown.cancel();
        self.inner.tasks.close();
        self.inner.tasks.wait().await;
    }
}

struct EndSession<B: Backend>(Arc<Inner<B>>, [u8; 16], Arc<Conn<B>>);

impl<B: Backend> Drop for EndSession<B> {
    fn drop(&mut self) {
        self.0.drop_session(&self.1, &self.2);
    }
}

fn hash(b: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::digest(b).into()
}

impl<B: Backend> Inner<B> {
    /// Spawns a task that stops when the service shuts down.
    fn spawn(&self, f: impl Future<Output = ()> + Send + 'static) {
        let shutdown = self.shutdown.clone();
        self.tasks.spawn(async move {
            tokio::select! {
                _ = f => {}
                _ = shutdown.cancelled() => {}
            }
        });
    }

    fn descriptor(&self) -> ServiceDescriptor {
        let mut routers: Vec<RouterRef> = self
            .state
            .lock()
            .unwrap()
            .links
            .values()
            .map(|l| RouterRef { node_id_hash: l.node.node_id_hash, endpoint: String::from_utf8_lossy(&l.node.endpoint).into_owned() })
            .collect();
        routers.sort_by_key(|r| r.node_id_hash);
        ServiceDescriptor { nike_scheme: nike::SCHEME.into(), public_key: self.cfg.key.public.to_bytes(), routers }
    }

    fn add_session(self: &Arc<Self>, conn: Conn<B>) -> Session<B> {
        let mut id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut id);
        let conn = Arc::new(conn);
        self.state.lock().unwrap().sessions.insert(id, conn.clone());
        self.watch_session(id, &conn);
        self.save_session(&id, &conn.state());
        Session { conn, id, restored: false, inner: self.clone() }
    }

    fn watch_session(self: &Arc<Self>, id: [u8; 16], conn: &Arc<Conn<B>>) {
        let inner = Arc::downgrade(self);
        conn.on_change(Some(Arc::new(move |st: &ConnState| {
            if let Some(inner) = inner.upgrade() {
                inner.save_session(&id, st);
            }
        })));
    }

    fn save_session(&self, id: &[u8; 16], st: &ConnState) {
        if !self.state.lock().unwrap().sessions.contains_key(id) {
            return;
        }
        if let Err(e) = self.store.put(SESSIONS, id, &st.encode()) {
            log::error!("saving a session: {e}");
        }
    }

    /// Forgets a session, unless the service is shutting down: then the
    /// session is kept to resume on the next start.
    fn drop_session(&self, id: &[u8; 16], conn: &Conn<B>) {
        if self.shutdown.is_cancelled() {
            return;
        }
        conn.on_change(None);
        self.state.lock().unwrap().sessions.remove(id);
        if let Err(e) = self.store.delete(SESSIONS, id) {
            log::error!("deleting a session: {e}");
        }
    }

    fn await_offer(self: &Arc<Self>, p: Pending) {
        let inner = self.clone();
        self.spawn(async move {
            let conn = match p.wait(inner.ph.clone(), inner.cfg.poll_interval).await {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("an offered voucher failed: {e}");
                    return;
                }
            };
            let key = hash(&p.voucher);
            let session = inner.add_session(conn);
            inner.state.lock().unwrap().offers.remove(&key);
            if let Err(e) = inner.store.delete(OFFERS, &key) {
                log::error!("deleting an offer: {e}");
            }
            let _ = inner.incoming_tx.send(Arrival::Ready(session)).await;
        });
    }

    fn save_link(&self, l: &LinkState<B>) {
        let v = cbor::map(vec![
            ("NodeIDHash", cbor::bytes(&l.node.node_id_hash)),
            ("Endpoint", cbor::bytes(&l.node.endpoint)),
            ("Conn", l.conn.state().to_value()),
            ("Expiry", cbor::uint(l.expiry.load(Ordering::Relaxed))),
        ]);
        if let Err(e) = self.store.put(LINKS, &l.node.node_id_hash, &cbor::encode(&v)) {
            log::error!("saving a link: {e}");
        }
    }

    /// Forgets a link, so the next rescan registers with its router again,
    /// and advertises without it.
    async fn drop_link(&self, l: &Arc<LinkState<B>>) {
        {
            let mut st = self.state.lock().unwrap();
            if !st.links.get(&l.node.node_id_hash).is_some_and(|x| Arc::ptr_eq(x, l)) {
                return;
            }
            st.links.remove(&l.node.node_id_hash);
        }
        l.stop.cancel();
        if let Err(e) = self.store.delete(LINKS, &l.node.node_id_hash) {
            log::error!("deleting a link: {e}");
        }
        self.advertise().await;
    }

    fn forget_voucher(&self, voucher: &[u8]) {
        if let Err(e) = self.store.delete(VOUCHERS, &hash(voucher)) {
            log::error!("forgetting a voucher: {e}");
        }
    }

    /// Starts reading a link. read_link saves the link itself, after
    /// storing each voucher it reads, so a crash loses none.
    fn start_link(self: &Arc<Self>, l: Arc<LinkState<B>>) {
        let inner = self.clone();
        self.spawn(async move { inner.read_link(l).await });
    }

    /// Reads the vouchers one router forwards. A link that fails to read is
    /// dropped, so the next rescan registers with its router again.
    async fn read_link(&self, l: Arc<LinkState<B>>) {
        loop {
            let msg = tokio::select! {
                m = l.conn.recv() => m,
                _ = l.stop.cancelled() => return,
            };
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    log::error!("reading a link: {e}");
                    self.drop_link(&l).await;
                    return;
                }
            };
            let voucher = match open_forward(&*self.ph, &self.cfg.key, &msg).await {
                Ok(v) if v.len() == 32 && !self.seen(&v) => v,
                Ok(_) => {
                    self.save_link(&l);
                    continue;
                }
                Err(e) => {
                    log::warn!("a router forwarded something that does not open: {e}");
                    self.save_link(&l);
                    continue;
                }
            };
            if let Err(e) = self.store.put(VOUCHERS, &hash(&voucher), &voucher) {
                log::error!("saving a voucher: {e}");
            }
            self.save_link(&l);
            if self.incoming_tx.send(Arrival::Voucher(voucher)).await.is_err() {
                return;
            }
        }
    }

    fn seen(&self, voucher: &[u8]) -> bool {
        let key = hash(voucher);
        let now = Instant::now();
        let mut st = self.state.lock().unwrap();
        st.vouchers.retain(|_, at| now.duration_since(*at) <= VOUCHER_DEDUP_TTL);
        st.vouchers.insert(key, now).is_some()
    }

    /// Registers with routers it has no link with, whenever it rescans the
    /// PKI.
    async fn registrar(self: Arc<Self>) {
        loop {
            self.register_all().await;
            crate::pigeonservice::pigeonhole::sleep(self.cfg.rescan_interval).await;
        }
    }

    async fn register_all(self: &Arc<Self>) {
        let nodes = match self.ph.services(ROUTER_CAPABILITY).await {
            Ok(n) => n,
            Err(e) => {
                log::warn!("listing routers: {e}");
                return;
            }
        };
        let now = lease::now();
        for node in nodes {
            let renewing = {
                let mut st = self.state.lock().unwrap();
                let renewing = st.links.get(&node.node_id_hash).filter(|l| l.expiry.load(Ordering::Relaxed) < now + self.cfg.link_ttl.as_secs() / 2).cloned();
                if (st.links.contains_key(&node.node_id_hash) && renewing.is_none()) || !st.registering.insert(node.node_id_hash) {
                    continue;
                }
                renewing
            };
            let inner = self.clone();
            self.spawn(async move {
                let id = node.node_id_hash;
                if let Some(l) = renewing {
                    inner.renew(&l).await;
                    inner.state.lock().unwrap().registering.remove(&id);
                    return;
                }
                let expiry = lease_expiry(inner.cfg.link_ttl);
                let res = tokio::time::timeout(inner.cfg.register_timeout, async {
                    let pending = register(&*inner.ph, &inner.cfg.key, &node, expiry).await?;
                    pending.wait(inner.ph.clone(), inner.cfg.poll_interval).await
                })
                .await;
                inner.state.lock().unwrap().registering.remove(&id);
                let conn = match res {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => return log::warn!("registering with router {}: {e}", hex8(&id)),
                    Err(_) => return log::warn!("registering with router {}: timed out", hex8(&id)),
                };
                let l = LinkState::new(node, conn, expiry);
                inner.save_link(&l);
                inner.state.lock().unwrap().links.insert(id, l.clone());
                inner.start_link(l);
                log::info!("linked with router {}", hex8(&id));
                inner.advertise().await;
            });
        }
        let due = {
            let st = self.state.lock().unwrap();
            !st.links.is_empty() && st.advertised < now + self.cfg.advertise_ttl.as_secs() / 2
        };
        if due {
            self.advertise().await;
        }
    }

    /// Asks the router for a new lease on a link. A router that no longer
    /// knows the link is left for the next rescan to register with again.
    async fn renew(&self, l: &Arc<LinkState<B>>) {
        let expiry = lease_expiry(self.cfg.link_ttl);
        match tokio::time::timeout(self.cfg.register_timeout, renew(&*self.ph, &self.cfg.key, &l.node, expiry)).await {
            Ok(Ok(())) => {
                l.expiry.store(expiry, Ordering::Relaxed);
                self.save_link(l);
            }
            Ok(Err(Error::Status(s))) if s == Status::UnknownService as u8 || s == Status::Stale as u8 => {
                log::warn!("router {} forgot our link: status {s}", hex8(&l.node.node_id_hash));
                self.drop_link(l).await;
            }
            Ok(Err(e)) => log::warn!("renewing with router {}: {e}", hex8(&l.node.node_id_hash)),
            Err(_) => log::warn!("renewing with router {}: timed out", hex8(&l.node.node_id_hash)),
        }
    }

    async fn directories(&self) -> Option<&Vec<Directory<B>>> {
        if !self.cfg.advertise {
            return None;
        }
        self.directories
            .get_or_try_init(|| Directory::all(self.ph.clone(), Some(self.cfg.key.clone()), self.cfg.poll_interval))
            .await
            .map_err(|e| log::warn!("listing directories: {e}"))
            .ok()
    }

    async fn advertise(&self) {
        let Some(dirs) = self.directories().await else { return };
        let d = self.descriptor();
        let expiry = lease_expiry(self.cfg.advertise_ttl);
        let mut granted = None;
        for dir in dirs {
            match dir.advertise(&d, expiry).await {
                Ok(e) => granted = Some(granted.map_or(e, |g: u64| g.min(e))),
                Err(e) => log::warn!("advertising: {e}"),
            }
        }
        if let Some(g) = granted {
            self.state.lock().unwrap().advertised = g;
        }
    }

    async fn withdraw(&self) {
        let Some(dirs) = self.directories().await else { return };
        let id = ServiceId::from_public_key(&self.cfg.key.public.to_bytes());
        for dir in dirs {
            if let Err(e) = dir.withdraw(id).await {
                log::warn!("withdrawing: {e}");
            }
        }
        self.state.lock().unwrap().advertised = 0;
    }

    /// Rewrites recently sent boxes on links and sessions, so they survive
    /// replica garbage collection.
    async fn refresher(&self) {
        let every = (self.cfg.retention / 7).max(Duration::from_secs(60));
        loop {
            tokio::time::sleep(every).await;
            let conns: Vec<Arc<Conn<B>>> = {
                let st = self.state.lock().unwrap();
                st.links.values().map(|l| l.conn.clone()).chain(st.sessions.values().cloned()).collect()
            };
            for c in conns {
                if let Err(e) = c.refresh(self.cfg.retention).await {
                    log::warn!("refreshing: {e}");
                }
            }
        }
    }
}

fn hex8(b: &[u8]) -> String {
    b[..8].iter().map(|x| format!("{x:02x}")).collect()
}

const LINKS: &str = "links";
const SESSIONS: &str = "sessions";
const OFFERS: &str = "offers";
const VOUCHERS: &str = "vouchers";

type Stored = (Vec<u8>, Vec<u8>);

/// The service's state on disk: one file per link, session and offer.
struct Store {
    dir: PathBuf,
}

impl Store {
    fn open(dir: &Path) -> Result<Self, Error> {
        // The state holds stream capabilities, voucher secrets and plaintext.
        for sub in [LINKS, SESSIONS, OFFERS, VOUCHERS] {
            std::fs::create_dir_all(dir.join(sub))?;
            std::fs::set_permissions(dir.join(sub), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Store { dir: dir.to_path_buf() })
    }

    fn path(&self, kind: &str, key: &[u8]) -> PathBuf {
        let name: String = key.iter().map(|b| format!("{b:02x}")).collect();
        self.dir.join(kind).join(name)
    }

    fn put(&self, kind: &str, key: &[u8], data: &[u8]) -> Result<(), Error> {
        let path = self.path(kind, key);
        let tmp = path.with_extension("tmp");
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?.write_all(data)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn delete(&self, kind: &str, key: &[u8]) -> Result<(), Error> {
        match std::fs::remove_file(self.path(kind, key)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }

    /// Every stored item of a kind, with its key.
    fn load_keyed(&self, kind: &str) -> Result<Vec<Stored>, Error> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(self.dir.join(kind))? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else { continue };
            if name.len() % 2 != 0 || !name.bytes().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let key = (0..name.len()).step_by(2).map(|i| u8::from_str_radix(&name[i..i + 2], 16).unwrap()).collect();
            out.push((key, std::fs::read(&path)?));
        }
        Ok(out)
    }

    fn load(&self, kind: &str) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self.load_keyed(kind)?.into_iter().map(|(_, v)| v).collect())
    }
}
