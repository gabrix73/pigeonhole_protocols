//! Members, each a client engine, over the in-memory Pigeonhole, on a logical clock that moves
//! only when told to: as group_chat_client's client scenarios and core tests drive them.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use pigeonhole_protocols::protocols::katzenqt1::client::store::{Options, Store};
use pigeonhole_protocols::protocols::katzenqt1::client::{Executor, Files, Outcome};
use pigeonhole_protocols::protocols::katzenqt1::engine::{
    Action, Chat, Engine, Input, Line, State, Status, StepResult, plain,
};
use pigeonhole_protocols::protocols::katzenqt1::member::Key;
use pigeonhole_protocols::protocols::katzenqt1::wire as wire;
use pigeonhole_protocols::transport::Backend;
use pigeonhole_protocols::transport::sim::World as Sim;

#[derive(Clone, Default)]
pub struct MemFiles(pub Arc<Mutex<HashMap<String, Vec<u8>>>>);

impl Files for MemFiles {
    fn read(&self, name: &str) -> std::io::Result<Vec<u8>> {
        self.0
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, name.to_string()))
    }

    fn remove(&self, name: &str) -> std::io::Result<()> {
        self.0.lock().unwrap().remove(name);
        Ok(())
    }
}

pub struct Member {
    pub name: String,
    pub eng: Engine,
    pub files: MemFiles,
    /// When set, keeps the member's state on disk, saved after every step as a client does.
    pub st: Option<(Store, tempfile::TempDir)>,
}

/// Told of each action done; when it says so, the member restarts from what is on disk, before
/// (lost) or after (kept) what came of the action is taken in.
pub type Crash = Box<dyn FnMut(usize, &Action) -> Option<bool>>;

pub enum Later {
    Act(Action),
    In(Input),
}

pub struct World {
    pub sim: Sim,
    pub members: Vec<Member>,
    pub queue: Vec<(usize, Action)>,
    pub later: Vec<(u64, usize, Later)>,
    pub clock: u64,
    pub held: HashSet<usize>,
    pub epoch: u64,
    pub rt: tokio::runtime::Runtime,
    pub crash: Option<Crash>,
    pub restarts: HashMap<usize, usize>,
    /// Check after each step that all the state on disk is what the engine holds.
    pub check_saved: bool,
    /// Keep the state of every member on disk, even of those a scenario brings in later.
    pub disk: bool,
    /// For a member, the kind of its next action to fail, or whose box to fill with other bytes
    /// first.
    pub fail_next: HashMap<usize, String>,
    /// For a member, the kind of its next action whose outcome is kept back until the member
    /// is released: the action is done, the member has yet to hear so.
    pub delay_next: HashMap<usize, String>,
    pub delayed: HashMap<usize, Vec<Input>>,
    pub clobber_next: HashMap<usize, String>,
    /// The last reply to its voucher each member opened, by chat.
    pub opened: HashMap<(usize, String), Input>,
    /// Members who reply to a voucher as katzenqt does for a conversation that keeps no rosters:
    /// with the members' read caps alone.
    pub rosterless: HashSet<usize>,
}

/// An action's or an input's kind, as Go names it without its `Do`.
pub fn kind_of(x: &impl std::fmt::Debug) -> String {
    let s = format!("{x:?}");
    s.split([' ', '{', '(']).next().unwrap_or("").to_string()
}

pub fn bytes_of(n: usize, seed: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + seed) % 251) as u8).collect()
}

impl Default for World {
    fn default() -> Self {
        World {
            sim: Sim::default(),
            members: Vec::new(),
            queue: Vec::new(),
            later: Vec::new(),
            clock: 0,
            held: HashSet::new(),
            epoch: 1,
            rt: tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
            crash: None,
            restarts: HashMap::new(),
            check_saved: false,
            disk: false,
            fail_next: HashMap::new(),
            delay_next: HashMap::new(),
            delayed: HashMap::new(),
            rosterless: HashSet::new(),
            clobber_next: HashMap::new(),
            opened: HashMap::new(),
        }
    }
}

impl World {
    pub fn who(&mut self, name: &str) -> usize {
        if let Some(i) = self.members.iter().position(|m| m.name == name) {
            return i;
        }
        self.members.push(Member {
            name: name.into(),
            eng: Engine::new(
                State {
                    me: name.into(),
                    chats: Vec::new(),
                },
                1530,
            ),
            files: MemFiles::default(),
            st: None,
        });
        self.members.len() - 1
    }

    pub fn feed(&mut self, i: usize, input: Input) {
        if let Input::Opened { chat, .. } = &input {
            self.opened.insert((i, chat.clone()), input.clone());
        }
        let res = self.members[i].eng.step(0, input);
        self.release(i, res);
    }

    /// Save what a step changed, then queue the work it asks for.
    pub fn release(&mut self, i: usize, res: StepResult) {
        let m = &mut self.members[i];
        match &mut m.st {
            Some((st, _)) => {
                st.commit(&m.eng.state, &res).unwrap();
                if self.check_saved {
                    let u = st.unsaved(&m.eng.state).unwrap();
                    assert!(u.is_empty(), "{}: changed without saying so: {u:?}", m.name);
                }
            }
            None => {
                let mut files = m.files.0.lock().unwrap();
                for f in &res.files {
                    files.insert(f.file.clone(), f.bytes.clone());
                }
            }
        }
        self.queue.extend(res.actions.into_iter().map(|a| (i, a)));
    }

    /// Keep every member's state on disk from now on.
    pub fn on_disk(&mut self) {
        for m in &mut self.members {
            if m.st.is_some() {
                continue;
            }
            let dir = tempfile::TempDir::new_in(
                std::env::var("TMPDIR")
                    .unwrap_or_else(|_| format!("{}/scratch/tmp", std::env::var("HOME").unwrap())),
            )
            .unwrap();
            let mut st = Store::open(dir.path(), Options { no_sync: true, key: None }).unwrap();
            // What the member did before it had a store is saved now.
            let mut all = StepResult::default();
            for c in &m.eng.state.chats {
                all.changes.chats.insert(c.id.clone());
                all.changes
                    .lines
                    .insert(c.id.clone(), c.log.iter().map(|l| l.id).collect());
            }
            st.commit(&m.eng.state, &all).unwrap();
            m.st = Some((st, dir));
        }
    }

    /// Stop member `i`, as a crash would: what it had under way is lost, and it starts again from
    /// what is on disk.
    pub fn restart(&mut self, i: usize) {
        *self.restarts.entry(i).or_default() += 1;
        self.queue.retain(|q| q.0 != i);
        self.later.retain(|l| l.1 != i);
        let m = &mut self.members[i];
        let (st, _) = m.st.as_mut().expect("a member on disk");
        let state = st.load(&m.name).unwrap();
        m.eng = Engine::new(state, 1530);
        let res = m.eng.resume(0);
        self.release(i, res);
    }

    fn files_of(&self, i: usize) -> Box<dyn Files> {
        match &self.members[i].st {
            Some((st, _)) => Box::new(st.files()),
            None => Box::new(self.members[i].files.clone()),
        }
    }

    pub fn file(&self, i: usize, name: &str) -> Option<Vec<u8>> {
        self.files_of(i).read(name).ok()
    }

    pub fn act(&mut self) -> bool {
        let Some(k) = self.queue.iter().position(|q| !self.held.contains(&q.0)) else {
            return false;
        };
        let (who, mut a) = self.queue.remove(k);
        if self.rosterless.contains(&who)
            && let Action::Seal { who_reply, .. } = &mut a
        {
            let full = wire::ReplyWho::from_bytes(who_reply).unwrap();
            *who_reply = wire::ReplyWho {
                please_adds: full
                    .please_adds
                    .into_iter()
                    .filter(Option::is_some)
                    .collect(),
                ..wire::ReplyWho::default()
            }
            .to_bytes()
            .into();
        }
        let crash = self.crash.as_mut().and_then(|c| c(who, &a));
        let x = Executor {
            backend: self.sim.clone(),
            files: self.files_of(who),
        };
        let kind = kind_of(&a);
        let o = if self.fail_next.get(&who) == Some(&kind) {
            self.fail_next.remove(&who);
            let (chat, what) = match &a {
                Action::Create { chat, .. } => (chat.clone(), "new stream"),
                Action::Mint { chat, .. } => (chat.clone(), "mint a voucher"),
                _ => panic!("cannot fail {kind}"),
            };
            Outcome::Done(Input::Failed {
                chat,
                what: format!("{what} failed: injected"),
            })
        } else {
            if self.clobber_next.get(&who) == Some(&kind) {
                self.clobber_next.remove(&who);
                self.clobber(&a);
            }
            self.rt.block_on(x.perform(a, |_| async {}))
        };
        if let Some(lost) = crash {
            if !lost && let Outcome::Done(input) = o {
                self.feed(who, input);
            }
            self.restart(who);
            return true;
        }
        match o {
            Outcome::Done(input) if self.delay_next.get(&who) == Some(&kind) => {
                self.delay_next.remove(&who);
                self.delayed.entry(who).or_default().push(input);
            }
            Outcome::Retry(a, ms) => self.later.push((self.clock + ms, who, Later::Act(a))),
            Outcome::Later(input, ms) => self.later.push((self.clock + ms, who, Later::In(input))),
            Outcome::Done(input) => self.feed(who, input),
            Outcome::Nothing => {}
        }
        true
    }

    /// Fill the box a write is for with other bytes.
    fn clobber(&mut self, a: &Action) {
        let (Action::Write {
            write_cap, index, ..
        }
        | Action::WriteChunk {
            write_cap, index, ..
        }) = a
        else {
            panic!("not a write: {}", kind_of(a));
        };
        self.rt
            .block_on(self.sim.write_box(write_cap, index, b"clobbered"))
            .unwrap();
    }

    /// Let the network run until `stop` on the logical clock.
    pub fn run_to(&mut self, stop: u64) {
        loop {
            if self.act() {
                continue;
            }
            let due = self
                .later
                .iter()
                .filter(|l| l.0 <= stop && !self.held.contains(&l.1))
                .map(|l| l.0)
                .min();
            let Some(due) = due else {
                self.clock = self.clock.max(stop);
                return;
            };
            let (now, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut self.later)
                .into_iter()
                .partition(|l| l.0 <= due && !self.held.contains(&l.1));
            self.later = rest;
            self.clock = self.clock.max(due);
            for (_, who, l) in now {
                match l {
                    // As a client does, an action is tried again only while it is of use.
                    Later::Act(a) => {
                        if self.members[who].eng.state.wanted(&a) {
                            self.queue.push((who, a));
                        }
                    }
                    Later::In(input) => self.feed(who, input),
                }
            }
        }
    }

    /// Run one action, or move the clock on to the next thing due; false when there is nothing
    /// left at all.
    pub fn tick(&mut self) -> bool {
        if self.act() {
            return true;
        }
        let Some(due) = self
            .later
            .iter()
            .filter(|l| !self.held.contains(&l.1))
            .map(|l| l.0)
            .min()
        else {
            return false;
        };
        self.run_to(due);
        true
    }

    /// Run until `done` holds or the clock passes `limit` milliseconds from now.
    pub fn run_until(&mut self, done: impl Fn(&World) -> bool, limit: u64) -> bool {
        let start = self.clock;
        while !done(self) {
            if self.clock > start + limit || !self.tick() {
                return done(self);
            }
        }
        true
    }

    pub fn chat(&self, i: usize, group: &str) -> Option<&Chat> {
        self.members[i].eng.state.chat(group)
    }

    /// The member whose key `k` is: the truth, for printing.
    pub fn name_of(&self, k: &Key) -> String {
        for m in &self.members {
            for c in &m.eng.state.chats {
                if c.group.as_ref().is_some_and(|g| &g.me() == k) {
                    return m.name.clone();
                }
            }
        }
        "?".into()
    }

    pub fn code(&self, i: usize, group: &str) -> String {
        self.chat(i, group)
            .and_then(|c| c.joining.as_ref())
            .map_or(String::new(), |j| j.code.clone())
    }

    pub fn says(&self, i: usize, chat: &str, text: &str) -> bool {
        self.chat(i, chat)
            .is_some_and(|c| c.log.iter().any(|l| l.notice.is_none() && l.text == text))
    }

    pub fn noticed(&self, i: usize, chat: &str, text: &str) -> bool {
        self.chat(i, chat).is_some_and(|c| {
            c.log.iter().any(|l| {
                l.notice
                    .as_ref()
                    .is_some_and(|n| plain(n).starts_with(text))
            })
        })
    }

    pub fn joined(&self, i: usize, chat: &str) -> bool {
        self.chat(i, chat).is_some_and(|c| c.group.is_some())
    }

    pub fn idle(&self) -> bool {
        self.members
            .iter()
            .all(|m| m.eng.state.chats.iter().all(|c| c.jobs.is_empty()))
    }

    fn first_of(c: &Chat) -> u64 {
        wire::counter(&c.write_cap[c.write_cap.len() - wire::INDEX_SIZE..])
    }

    fn mark(c: &Chat, l: &Line) -> &'static str {
        match l.status {
            Status::Pending => " …",
            Status::Sent if c.acknowledged(l) => " ✓✓",
            Status::Sent => " ✓",
        }
    }

    pub fn show(&self, i: usize, group: &str) -> Vec<String> {
        let Some(c) = self.chat(i, group) else {
            return vec!["no such group".into()];
        };
        c.log
            .iter()
            .map(|l| match &l.notice {
                Some(n) => format!("— {}", plain(n)),
                None => {
                    let mine = c.group.as_ref().is_some_and(|g| g.me() == l.sender);
                    format!(
                        "{}{}: {}",
                        self.name_of(&l.sender),
                        if mine { Self::mark(c, l) } else { "" },
                        l.text.replace('\n', " | ")
                    )
                }
            })
            .collect()
    }

    pub fn members_of(&self, i: usize, group: &str) -> Vec<String> {
        let Some(c) = self.chat(i, group) else {
            return vec!["no such group".into()];
        };
        let Some(g) = &c.group else {
            return vec!["not joined".into()];
        };
        let mut names: Vec<String> = g.readers.keys().map(|k| self.name_of(k)).collect();
        names.sort();
        let s = names.join(" ").trim().to_string();
        vec![if s.is_empty() { "nobody".into() } else { s }]
    }

    pub fn acked(&self, i: usize, group: &str) -> Vec<String> {
        let Some(c) = self.chat(i, group) else {
            return vec!["no such group".into()];
        };
        let Some(g) = &c.group else {
            return vec!["not joined".into()];
        };
        let first = Self::first_of(c);
        let mut acks: Vec<String> = g
            .ledger
            .acked_by
            .iter()
            .map(|(k, n)| format!("{}:{}", self.name_of(k), n - first))
            .collect();
        acks.sort();
        vec![if acks.is_empty() {
            "none".into()
        } else {
            acks.join(" ")
        }]
    }

    pub fn state_of(&self, i: usize, group: &str) -> Vec<String> {
        let Some(c) = self.chat(i, group) else {
            return vec!["no such group".into()];
        };
        let mut parts = vec![if c.group.is_some() {
            "joined".to_string()
        } else {
            "not joined".to_string()
        }];
        if let Some(j) = &c.joining {
            parts.push(if j.code.is_empty() {
                "minting".into()
            } else {
                "awaiting a reply".into()
            });
        }
        if c.inducting.is_some() {
            parts.push("adding a member".into());
        }
        if !c.jobs.is_empty() {
            parts.push(format!("{} to write", c.jobs.len()));
        }
        vec![parts.join(", ")]
    }

    pub fn jobs(&self, i: usize, group: &str) -> Vec<String> {
        let Some(c) = self.chat(i, group) else {
            return vec!["no such group".into()];
        };
        if c.jobs.is_empty() {
            return vec!["none".into()];
        }
        let first = Self::first_of(c);
        c.jobs
            .iter()
            .map(|j| {
                let at = j.index.as_ref().map_or("next box".into(), |x| {
                    format!("box {}", wire::counter(x) - first)
                });
                let what = if j.token.is_some() {
                    "message"
                } else if j.box_.is_empty() {
                    "tombstone"
                } else {
                    "rewrite"
                };
                format!("{what} to {at}, {} bytes", j.box_.len())
            })
            .collect()
    }

    pub fn refused(&self) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for r in &self.sim.state().refused {
            let (mut name, mut n) = ("?".to_string(), r.idx64);
            for m in &self.members {
                for c in &m.eng.state.chats {
                    if c.write_cap.len() > 64 && c.write_cap[32..64] == r.stream[..] {
                        name = m.name.clone();
                        n = r.idx64 - Self::first_of(c);
                    }
                }
            }
            let s = format!("{name}@{n}");
            if !names.contains(&s) {
                names.push(s);
            }
        }
        vec![if names.is_empty() {
            "none".into()
        } else {
            names.join(" ")
        }]
    }

    pub fn pending(&self, i: usize) -> Vec<String> {
        let mut kinds: Vec<String> = self
            .queue
            .iter()
            .filter(|q| q.0 == i)
            .map(|q| kind_of(&q.1))
            .chain(self.later.iter().filter(|l| l.1 == i).map(|l| match &l.2 {
                Later::Act(a) => kind_of(a),
                Later::In(input) => kind_of(input),
            }))
            .collect();
        if kinds.is_empty() {
            return vec!["none".into()];
        }
        kinds.sort();
        vec![kinds.join(" ")]
    }

    pub fn files_held(&self, i: usize) -> Vec<String> {
        let names: BTreeMap<String, ()> = self.members[i]
            .files
            .0
            .lock()
            .unwrap()
            .keys()
            .map(|k| (k.clone(), ()))
            .collect();
        if names.is_empty() {
            return vec!["none".into()];
        }
        names.into_keys().collect()
    }

    /// How a member's copy of the file called `name` in `group` compares with what was sent.
    pub fn file_got(&self, i: usize, group: &str, name: &str) -> Vec<String> {
        let Some(a) = self.chat(i, group).and_then(|c| {
            c.log
                .iter()
                .find_map(|l| l.attachment.as_ref().filter(|a| a.name == name))
        }) else {
            return vec!["no such file".into()];
        };
        match self.file(i, &a.file) {
            None => vec!["not kept".into()],
            Some(b) if b != bytes_of(a.size, name.len()) => {
                vec![format!("{} bytes, not as sent", b.len())]
            }
            Some(b) => vec![format!("{} bytes, as sent", b.len())],
        }
    }

    /// Restart member `i`: from disk if it keeps its state there, or else from the state it
    /// holds, which is all saved.
    pub fn restart_any(&mut self, i: usize) {
        if self.members[i].st.is_some() {
            self.restart(i);
            return;
        }
        self.queue.retain(|q| q.0 != i);
        self.later.retain(|l| l.1 != i);
        let res = self.members[i].eng.resume(0);
        self.release(i, res);
    }

    pub fn command(&mut self, words: &[&str]) -> Result<Vec<String>, String> {
        let id = |g: &str| g.to_string();
        match words {
            ["create", w, g] => {
                let i = self.who(w);
                self.feed(
                    i,
                    Input::Create {
                        chat: id(g),
                        name: id(g),
                    },
                );
            }
            ["join", w, g] => {
                let i = self.who(w);
                self.feed(
                    i,
                    Input::Join {
                        chat: id(g),
                        name: id(g),
                    },
                );
            }
            ["invite", w, g, new, rest @ ..] => {
                let theirs = rest.first().copied().unwrap_or(g);
                let n = self.who(new);
                let code = self.code(n, theirs);
                if code.is_empty() {
                    return Ok(vec![format!("{new} has no voucher code")]);
                }
                let i = self.who(w);
                self.feed(i, Input::Induct { chat: id(g), code });
            }
            ["send", w, g, text @ ..] => {
                let i = self.who(w);
                self.feed(
                    i,
                    Input::Send {
                        chat: id(g),
                        text: text.join(" "),
                    },
                );
            }
            ["remove", w, g, gone] => {
                let i = self.who(w);
                let n = self.who(gone);
                let Some(k) = self
                    .chat(n, g)
                    .and_then(|c| c.group.as_ref())
                    .map(|g| g.me())
                else {
                    return Ok(vec![format!("{gone} is not in {g}")]);
                };
                self.feed(
                    i,
                    Input::RemoveMember {
                        chat: id(g),
                        who: k,
                    },
                );
            }
            ["scan", w, g] => {
                let i = self.who(w);
                self.feed(i, Input::Scan { chat: id(g) });
            }
            ["leave", w, g] => {
                let i = self.who(w);
                self.feed(i, Input::Leave { chat: id(g) });
            }
            ["run"] => self.run_to(self.clock + 600000),
            ["run", s] => self.run_to(self.clock + s.parse::<u64>().unwrap() * 1000),
            ["hold", w] => {
                let i = self.who(w);
                self.held.insert(i);
            }
            ["release", w] => {
                let i = self.who(w);
                self.held.remove(&i);
                for input in self.delayed.remove(&i).unwrap_or_default() {
                    self.feed(i, input);
                }
            }
            ["delay-next", w, kind] => {
                let i = self.who(w);
                self.delay_next.insert(i, kind.to_string());
            }
            ["epoch"] => {
                self.epoch += 1;
                self.sim.set_epoch(self.epoch);
                for i in 0..self.members.len() {
                    self.feed(
                        i,
                        Input::Epoch {
                            n: self.epoch as usize,
                        },
                    );
                }
            }
            ["fail-writes", n] => self.sim.state().fail_writes = n.parse().unwrap(),
            ["show", w, g] => {
                let i = self.who(w);
                return Ok(self.show(i, g));
            }
            ["members", w, g] => {
                let i = self.who(w);
                return Ok(self.members_of(i, g));
            }
            ["acked", w, g] => {
                let i = self.who(w);
                return Ok(self.acked(i, g));
            }
            ["state", w, g] => {
                let i = self.who(w);
                return Ok(self.state_of(i, g));
            }
            ["jobs", w, g] => {
                let i = self.who(w);
                return Ok(self.jobs(i, g));
            }
            ["refused"] => return Ok(self.refused()),
            ["invite-code", w, g, code] => {
                let i = self.who(w);
                self.feed(
                    i,
                    Input::Induct {
                        chat: id(g),
                        code: code.to_string(),
                    },
                );
            }
            ["send-file", w, g, name, size] => {
                let i = self.who(w);
                self.feed(
                    i,
                    Input::SendFile {
                        chat: id(g),
                        name: name.to_string(),
                        bytes: bytes_of(size.parse().unwrap(), name.len()),
                    },
                );
            }
            ["file", w, g, name] => {
                let i = self.who(w);
                return Ok(self.file_got(i, g, name));
            }
            ["voucher-file", w, g] => {
                let i = self.who(w);
                return Ok(vec![match self.file(i, &format!("voucher-{g}.txt")) {
                    None => "none".into(),
                    Some(b) if b != format!("{}\n", self.code(i, g)).into_bytes() => {
                        "not the code".into()
                    }
                    Some(_) => "the code".into(),
                }]);
            }
            ["files", w] => {
                let i = self.who(w);
                return Ok(self.files_held(i));
            }
            ["pending", w] => {
                let i = self.who(w);
                return Ok(self.pending(i));
            }
            ["restart", w] => {
                let i = self.who(w);
                self.restart_any(i);
            }
            ["fail-next", w, kind] => {
                let i = self.who(w);
                self.fail_next.insert(i, kind.to_string());
            }
            ["clobber-next", w, kind] => {
                let i = self.who(w);
                self.clobber_next.insert(i, kind.to_string());
            }
            ["reopen", w, g] => {
                let i = self.who(w);
                let Some(o) = self.opened.get(&(i, id(g))).cloned() else {
                    return Ok(vec!["nothing to reopen".into()]);
                };
                self.feed(i, o);
            }
            ["repeat", k, rest @ ..] if !rest.is_empty() => {
                let mut out = Vec::new();
                for _ in 0..k.parse::<usize>().unwrap() {
                    out = self.command(rest)?;
                }
                return Ok(out);
            }
            _ => return Err(format!("not a command: {}", words.join(" "))),
        }
        Ok(Vec::new())
    }

    /// Run a scenario: the script with every checked command's output replaced by what it printed
    /// now.
    pub fn run_script(&mut self, script: &str) -> Result<String, String> {
        let mut lines: Vec<&str> = script.split('\n').collect();
        if lines.last() == Some(&"") {
            lines.pop();
        }
        let mut out: Vec<String> = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            out.push(line.into());
            i += 1;
            let cmd = line.split('#').next().unwrap_or("").trim();
            if cmd.is_empty() {
                continue;
            }
            let words: Vec<&str> = cmd.split_whitespace().collect();
            let printed = self.command(&words)?;
            if self.disk {
                self.on_disk();
            }
            if i < lines.len() && lines[i] == "----" {
                out.push("----".into());
                i += 1;
                while i < lines.len() && !lines[i].trim().is_empty() {
                    i += 1;
                }
                out.extend(printed);
            }
        }
        Ok(out.join("\n") + "\n")
    }
}
