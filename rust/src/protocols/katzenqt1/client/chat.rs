//! The client itself: one task owns the engine and the store, and every step's changes are saved
//! before any of its work starts.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use crate::protocols::katzenqt1::engine::{Action, Attachment, Chat, ChatId, Engine, Input, Line, State};
use crate::protocols::katzenqt1::member::Key;
use crate::protocols::katzenqt1::wire as wire;
use crate::transport::Backend;
use tokio::sync::{mpsc, oneshot, watch};

use crate::protocols::katzenqt1::client::exec::{Executor, Outcome};
use crate::protocols::katzenqt1::client::exec::Files;
use crate::protocols::katzenqt1::client::store::{Options, Store, StoreError, StoreFiles};
use crate::secret::Secret;
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    Closed,
    NameTaken,
    EmptyName,
    NoSuchChat,
    NotJoined,
    AlreadyAdding,
    NotAVoucher,
    NoSuchMember,
    RemoveSelf,
    FileTooLarge,
    EmptyMessage,
    /// The state is sealed, and not with the key given, or none was given; or it was changed.
    Locked,
    /// The state is not sealed but a key was given: [`Store::reseal`] seals it.
    Unsealed,
    /// The state could not be saved, so the client stopped.
    Store(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ClientError::*;
        f.write_str(match self {
            Closed => "client: closed",
            NameTaken => "client: a group already has that name",
            EmptyName => "client: a group needs a name",
            NoSuchChat => "client: no such group",
            NotJoined => "client: the group has not been joined yet",
            AlreadyAdding => "client: already adding a member",
            NotAVoucher => "client: not a voucher code",
            NoSuchMember => "client: no such member",
            RemoveSelf => "client: we cannot remove ourselves",
            FileTooLarge => "client: file too large to send",
            EmptyMessage => "client: nothing to send",
            Locked => "client: the state is sealed with another key, or changed",
            Unsealed => "client: the state is not sealed",
            Store(e) => return write!(f, "client: {e}"),
        })
    }
}

impl std::error::Error for ClientError {}

pub type Result<T> = std::result::Result<T, ClientError>;

pub struct Config {
    /// Holds the state and the files it names.
    pub state_dir: PathBuf,
    /// Our display name, when the state has none yet.
    pub name: String,
    /// How often the replicas' epoch is asked for.
    pub epoch_poll: Duration,
    /// For tests only: see [`Options::no_sync`].
    pub no_sync: bool,
    /// The key of 32 bytes that seals the state, if it is sealed: see [`Options::key`].
    pub key: Option<Secret>,
}

fn store_error(x: StoreError) -> ClientError {
    match x {
        StoreError::Locked => ClientError::Locked,
        StoreError::Unsealed => ClientError::Unsealed,
        x => ClientError::Store(x.to_string()),
    }
}

/// What changed; an app asks for what it shows with [`Client::chats`] and [`Client::lines`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Event {
    pub chat: ChatId,
    /// The group is gone.
    pub removed: bool,
    /// The lines added or changed.
    pub lines: Vec<usize>,
    /// The lines deleted.
    pub dropped: Vec<usize>,
    /// Set when the client stopped.
    pub error: Option<String>,
}

type Check = Box<dyn FnOnce(&State) -> Result<()> + Send>;
type Query = Box<dyn FnOnce(&State) + Send>;

enum Request {
    Step(Input, Option<Check>, Option<oneshot::Sender<Result<()>>>),
    Query(Query),
}

/// A katzenqt1 group chat client. Its methods may be called from any task.
pub struct Client {
    inbox: mpsc::UnboundedSender<Request>,
    stop: watch::Sender<bool>,
    subs: Arc<Mutex<Vec<mpsc::UnboundedSender<Event>>>>,
    error: Arc<Mutex<Option<String>>>,
    loop_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    dir: PathBuf,
    files: StoreFiles,
}

struct Worker<B: Backend> {
    exec: Arc<Executor<Arc<B>, StoreFiles>>,
    inbox: mpsc::UnboundedSender<Request>,
    stop: watch::Receiver<bool>,
}

impl<B: Backend> Clone for Worker<B> {
    fn clone(&self) -> Self {
        Worker {
            exec: self.exec.clone(),
            inbox: self.inbox.clone(),
            stop: self.stop.clone(),
        }
    }
}

async fn sleep_or_stop(stop: &mut watch::Receiver<bool>, ms: u64) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis(ms)) => true,
        _ = stop.wait_for(|s| *s) => false,
    }
}

impl<B: Backend> Worker<B> {
    /// Whether an action tried again is still of use.
    async fn wanted(&self, a: &Action) -> bool {
        let (tx, rx) = oneshot::channel();
        let a = a.clone();
        let q: Query = Box::new(move |s| {
            let _ = tx.send(s.wanted(&a));
        });
        self.inbox.send(Request::Query(q)).is_ok() && rx.await.unwrap_or(false)
    }

    /// Carry out an action after waiting `ms`, and hand the engine what came of it.
    fn launch(&self, a: Action, ms: u64) {
        let w = self.clone();
        tokio::spawn(async move {
            let mut stop = w.stop.clone();
            if ms > 0 && !(sleep_or_stop(&mut stop, ms).await && w.wanted(&a).await) {
                return;
            }
            let o = tokio::select! {
                o = w.exec.perform(a, |ms| { let mut s = w.stop.clone(); async move { sleep_or_stop(&mut s, ms).await; } }) => o,
                _ = stop.wait_for(|s| *s) => return,
            };
            match o {
                Outcome::Retry(a, ms) => w.launch(a, ms),
                Outcome::Later(input, ms) => {
                    if sleep_or_stop(&mut stop, ms).await {
                        let _ = w.inbox.send(Request::Step(input, None, None));
                    }
                }
                Outcome::Done(input) => {
                    let _ = w.inbox.send(Request::Step(input, None, None));
                }
                Outcome::Nothing => {}
            }
        });
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn notify(
    subs: &Mutex<Vec<mpsc::UnboundedSender<Event>>>,
    ch: &crate::protocols::katzenqt1::engine::Changes,
) {
    let mut ids: BTreeSet<&ChatId> = ch.chats.iter().collect();
    ids.extend(ch.lines.keys());
    ids.extend(ch.dropped.keys());
    ids.extend(ch.removed.iter());
    let events: Vec<Event> = ids
        .into_iter()
        .map(|id| Event {
            chat: id.clone(),
            removed: ch.removed.contains(id),
            lines: ch
                .lines
                .get(id)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default(),
            dropped: ch
                .dropped
                .get(id)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default(),
            error: None,
        })
        .collect();
    let mut subs = subs.lock().unwrap();
    subs.retain(|s| events.iter().all(|e| s.send(e.clone()).is_ok()));
}

fn new_id() -> ChatId {
    hex::encode(rand::random::<[u8; 16]>())
}

/// A member as a group's view lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberView {
    pub key: Key,
    pub name: String,
}

/// A group as an app shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatView {
    pub id: ChatId,
    pub name: String,
    /// The group is ours to read and write.
    pub joined: bool,
    /// Our key in the group, once joined.
    pub me: Key,
    /// The voucher code to hand a member of the group, while joining.
    pub code: String,
    /// A voucher is being made to join with.
    pub minting: bool,
    /// A member is being added.
    pub adding: bool,
    /// Those we read.
    pub members: Vec<MemberView>,
    /// How many boxes are still to be written.
    pub unsent: usize,
}

/// A line as an app shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineView {
    pub line: Line,
    /// We sent it.
    pub mine: bool,
    /// A member acknowledged it.
    pub acked: bool,
    /// Its sender's name.
    pub from: String,
}

fn view_of(c: &Chat) -> ChatView {
    ChatView {
        id: c.id.clone(),
        name: c.name.clone(),
        joined: c.group.is_some(),
        me: c.group.as_ref().map(|g| g.me()).unwrap_or_default(),
        code: c
            .joining
            .as_ref()
            .map(|j| j.code.clone())
            .unwrap_or_default(),
        minting: c.joining.as_ref().is_some_and(|j| j.code.is_empty()),
        adding: c.inducting.is_some(),
        members: c.group.as_ref().map_or_else(Vec::new, |g| {
            g.readers
                .keys()
                .map(|k| MemberView {
                    key: k.clone(),
                    name: c.names.get(k).cloned().unwrap_or_else(|| "?".into()),
                })
                .collect()
        }),
        unsent: c.jobs.len(),
    }
}

fn line_of(c: &Chat, l: &Line) -> LineView {
    let mine = l.notice.is_none() && c.group.as_ref().is_some_and(|g| g.me() == l.sender);
    let from = if l.notice.is_some() {
        String::new()
    } else if mine {
        "me".into()
    } else {
        c.names
            .get(&l.sender)
            .cloned()
            .unwrap_or_else(|| "?".into())
    };
    LineView {
        line: l.clone(),
        mine,
        acked: c.acknowledged(l),
        from,
    }
}

impl Client {
    /// Load the state in `cfg.state_dir` and carry on with whatever was under way.
    pub async fn open<B: Backend>(cfg: Config, backend: B) -> Result<Client> {
        let mut st = Store::open(
            &cfg.state_dir,
            Options {
                no_sync: cfg.no_sync,
                key: cfg.key,
            },
        )
        .map_err(store_error)?;
        let state = st.load(&cfg.name).map_err(store_error)?;
        let files = st.files();
        let backend = Arc::new(backend);
        let max = backend
            .max_plaintext()
            .await
            .map_err(|e| ClientError::Store(e.to_string()))?;
        let mut eng = Engine::new(state, max);
        // The replicas' epoch before anything is written, when the backend can say; the epoch
        // watcher reports it again later.
        if let Ok(e) = backend.replica_epoch().await {
            eng.epoch = e as usize;
        }
        let res = eng.resume(now());
        st.commit(&eng.state, &res)
            .map_err(|e| ClientError::Store(e.to_string()))?;
        let (inbox, mut rx) = mpsc::unbounded_channel();
        let (stop, stop_rx) = watch::channel(false);
        let worker = Worker {
            exec: Arc::new(Executor {
                backend: backend.clone(),
                files: st.files(),
            }),
            inbox: inbox.clone(),
            stop: stop_rx.clone(),
        };
        let subs: Arc<Mutex<Vec<mpsc::UnboundedSender<Event>>>> = Arc::default();
        let error: Arc<Mutex<Option<String>>> = Arc::default();
        for a in res.actions {
            worker.launch(a, 0);
        }
        // The epoch watcher.
        {
            let (inbox, mut stop, backend, poll) = (
                inbox.clone(),
                stop_rx.clone(),
                backend.clone(),
                cfg.epoch_poll,
            );
            tokio::spawn(async move {
                loop {
                    if let Ok(e) = backend.replica_epoch().await {
                        let _ =
                            inbox.send(Request::Step(Input::Epoch { n: e as usize }, None, None));
                    }
                    if !sleep_or_stop(&mut stop, poll.as_millis() as u64).await {
                        return;
                    }
                }
            });
        }
        let (subs2, error2, stop_tx) = (subs.clone(), error.clone(), stop.clone());
        let mut stop_loop = stop_rx;
        let loop_task = tokio::spawn(async move {
            loop {
                let r = tokio::select! {
                    r = rx.recv() => r,
                    _ = stop_loop.wait_for(|s| *s) => None,
                };
                let Some(r) = r else { return };
                match r {
                    Request::Query(q) => q(&eng.state),
                    Request::Step(input, check, done) => {
                        if let Some(check) = check
                            && let Err(e) = check(&eng.state)
                        {
                            if let Some(d) = done {
                                let _ = d.send(Err(e));
                            }
                            continue;
                        }
                        let res = eng.step(now(), input);
                        if let Err(e) = st.commit(&eng.state, &res) {
                            // What the step did is not on disk, so none of it may go out: stop.
                            let msg = e.to_string();
                            *error2.lock().unwrap() = Some(msg.clone());
                            for s in subs2.lock().unwrap().iter() {
                                let _ = s.send(Event {
                                    error: Some(msg.clone()),
                                    ..Event::default()
                                });
                            }
                            if let Some(d) = done {
                                let _ = d.send(Err(ClientError::Store(msg)));
                            }
                            let _ = stop_tx.send(true);
                            return;
                        }
                        if let Some(d) = done {
                            let _ = d.send(Ok(()));
                        }
                        notify(&subs2, &res.changes);
                        for a in res.actions {
                            worker.launch(a, 0);
                        }
                    }
                }
            }
        });
        Ok(Client {
            inbox,
            stop,
            subs,
            error,
            loop_task: Mutex::new(Some(loop_task)),
            dir: cfg.state_dir,
            files,
        })
    }

    fn stopped(&self) -> ClientError {
        match &*self.error.lock().unwrap() {
            Some(e) => ClientError::Store(e.clone()),
            None => ClientError::Closed,
        }
    }

    async fn run(
        &self,
        input: Input,
        check: impl FnOnce(&State) -> Result<()> + Send + 'static,
    ) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.inbox
            .send(Request::Step(input, Some(Box::new(check)), Some(tx)))
            .map_err(|_| self.stopped())?;
        rx.await.map_err(|_| self.stopped())?
    }

    async fn query<T: Send + 'static>(
        &self,
        f: impl FnOnce(&State) -> T + Send + 'static,
    ) -> Result<T> {
        let (tx, rx) = oneshot::channel();
        self.inbox
            .send(Request::Query(Box::new(move |s| {
                let _ = tx.send(f(s));
            })))
            .map_err(|_| self.stopped())?;
        rx.await.map_err(|_| self.stopped())
    }

    /// What changes from now on.
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<Event> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.subs.lock().unwrap().push(tx);
        rx
    }

    /// Why the client stopped, if it did.
    pub fn error(&self) -> Option<String> {
        self.error.lock().unwrap().clone()
    }

    /// Stop all work under way; nothing is lost, since a client opened on the same state
    /// carries on with it.
    pub async fn close(&self) {
        let _ = self.stop.send(true);
        let t = self.loop_task.lock().unwrap().take();
        if let Some(t) = t {
            let _ = t.await;
        }
        self.subs.lock().unwrap().clear();
    }

    /// Found a group.
    pub async fn create(&self, name: &str) -> Result<ChatId> {
        let id = new_id();
        self.run(
            Input::Create {
                chat: id.clone(),
                name: name.into(),
            },
            name_free(name.into()),
        )
        .await?;
        Ok(id)
    }

    /// Mint a voucher to join a group we will call `name`; its code shows in the group's view
    /// once minted, for a member of the group to invite with.
    pub async fn join(&self, name: &str) -> Result<ChatId> {
        let id = new_id();
        self.run(
            Input::Join {
                chat: id.clone(),
                name: name.into(),
            },
            name_free(name.into()),
        )
        .await?;
        Ok(id)
    }

    /// Add the member whose voucher code is `code`.
    pub async fn invite(&self, id: &str, code: &str) -> Result<()> {
        let valid = base64::engine::general_purpose::STANDARD
            .decode(code)
            .is_ok();
        self.run(
            Input::Induct {
                chat: id.into(),
                code: code.into(),
            },
            joined(id.into(), move |c| {
                if c.inducting.is_some() {
                    return Err(ClientError::AlreadyAdding);
                }
                if !valid {
                    return Err(ClientError::NotAVoucher);
                }
                Ok(())
            }),
        )
        .await
    }

    pub async fn send(&self, id: &str, text: &str) -> Result<()> {
        if text.is_empty() {
            return Err(ClientError::EmptyMessage);
        }
        self.run(
            Input::Send {
                chat: id.into(),
                text: text.into(),
            },
            joined(id.into(), |_| Ok(())),
        )
        .await
    }

    pub async fn send_file(&self, id: &str, name: &str, bytes: Vec<u8>) -> Result<()> {
        if bytes.len() > wire::MAX_FILE {
            return Err(ClientError::FileTooLarge);
        }
        self.run(
            Input::SendFile {
                chat: id.into(),
                name: name.into(),
                bytes,
            },
            joined(id.into(), |_| Ok(())),
        )
        .await
    }

    /// Look again for messages missed.
    pub async fn scan(&self, id: &str) -> Result<()> {
        self.run(
            Input::Scan { chat: id.into() },
            joined(id.into(), |_| Ok(())),
        )
        .await
    }

    /// Stop reading a member and delete what they sent; they can still read the group.
    pub async fn remove(&self, id: &str, who: Key) -> Result<()> {
        let w = who.clone();
        self.run(
            Input::RemoveMember {
                chat: id.into(),
                who,
            },
            joined(id.into(), move |c| {
                let g = c.group.as_ref().unwrap();
                if g.me() == w {
                    return Err(ClientError::RemoveSelf);
                }
                if !g.readers.contains_key(&w) {
                    return Err(ClientError::NoSuchMember);
                }
                Ok(())
            }),
        )
        .await
    }

    /// Forget a group and delete all it holds here.
    pub async fn leave(&self, id: &str) -> Result<()> {
        self.run(Input::Leave { chat: id.into() }, exists(id.into()))
            .await
    }

    /// Delete a group's lines here.
    pub async fn clear(&self, id: &str) -> Result<()> {
        self.run(Input::Clear { chat: id.into() }, exists(id.into()))
            .await
    }

    pub async fn rename(&self, id: &str, to: &str) -> Result<()> {
        let (i, t) = (id.to_string(), to.to_string());
        self.run(
            Input::Rename {
                chat: id.into(),
                to: to.into(),
            },
            move |s| {
                if s.chat(&i).is_none() {
                    return Err(ClientError::NoSuchChat);
                }
                if t.is_empty() {
                    return Err(ClientError::EmptyName);
                }
                if s.chat_named(&t).is_some_and(|o| o.id != i) {
                    return Err(ClientError::NameTaken);
                }
                Ok(())
            },
        )
        .await
    }

    /// Our groups, in the order made.
    pub async fn chats(&self) -> Result<Vec<ChatView>> {
        self.query(|s| s.chats.iter().map(view_of).collect()).await
    }

    pub async fn chat(&self, id: &str) -> Result<ChatView> {
        let id = id.to_string();
        self.query(move |s| s.chat(&id).map(view_of))
            .await?
            .ok_or(ClientError::NoSuchChat)
    }

    /// A group's lines after the one with id `after` (all of them for `None`), oldest first.
    pub async fn lines(&self, id: &str, after: Option<usize>) -> Result<Vec<LineView>> {
        let id = id.to_string();
        self.query(move |s| {
            s.chat(&id).map(|c| {
                c.log
                    .iter()
                    .filter(|l| after.is_none_or(|a| l.id > a))
                    .map(|l| line_of(c, l))
                    .collect()
            })
        })
        .await?
        .ok_or(ClientError::NoSuchChat)
    }

    /// The one member of a group whose name, or the start of whose key in hex, is `who`.
    pub async fn member_named(&self, id: &str, who: &str) -> Result<Key> {
        let v = self.chat(id).await?;
        let found: Vec<&MemberView> = v
            .members
            .iter()
            .filter(|m| m.name == who || who.len() >= 4 && hex::encode(&m.key).starts_with(who))
            .collect();
        match found[..] {
            [m] => Ok(m.key.clone()),
            _ => Err(ClientError::NoSuchMember),
        }
    }

    /// Where an attachment is kept; sealed, if the state is.
    pub fn file_path(&self, a: &Attachment) -> PathBuf {
        self.dir.join(&a.file)
    }

    /// An attachment's bytes, opened if the state is sealed.
    pub fn read_file(&self, a: &Attachment) -> Result<Zeroizing<Vec<u8>>> {
        self.files
            .read(&a.file)
            .map(Zeroizing::new)
            .map_err(|e| ClientError::Store(e.to_string()))
    }
}

fn name_free(name: String) -> impl FnOnce(&State) -> Result<()> + Send + 'static {
    move |s| {
        if name.is_empty() {
            return Err(ClientError::EmptyName);
        }
        if s.chat_named(&name).is_some() {
            return Err(ClientError::NameTaken);
        }
        Ok(())
    }
}

fn exists(id: String) -> impl FnOnce(&State) -> Result<()> + Send + 'static {
    move |s| s.chat(&id).map(|_| ()).ok_or(ClientError::NoSuchChat)
}

fn joined(
    id: String,
    then: impl FnOnce(&Chat) -> Result<()> + Send + 'static,
) -> impl FnOnce(&State) -> Result<()> + Send + 'static {
    move |s| {
        let c = s.chat(&id).ok_or(ClientError::NoSuchChat)?;
        if c.group.is_none() {
            return Err(ClientError::NotJoined);
        }
        then(c)
    }
}
