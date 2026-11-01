use indexmap::IndexMap;
use crate::protocols::katzenqt1::wire::{
    Ack, IntroAt, IntroRef, Introduction, JoinReply, Member, Number, PREFIX_SIZE, ROSTER_MAX,
    Roster as WireRoster, RosterEntry, membership_hash, prefix_of,
};

use crate::protocols::katzenqt1::member::Secret;
use crate::protocols::katzenqt1::member::rosters::{Entry, KnownEntry, Rosters, Started};
use crate::protocols::katzenqt1::member::{
    At, Effect, Event, Index, Induction, Invitee, Key, Ledger, Message, Payload, ReadResult,
    Reader, Retention, SentBox, counter, key_of, start_of,
};

/// How many of its own indexes a member derives at a time.
pub const POOL_SIZE: usize = 4;

/// What stands in a roster for a member known only by its place.
fn placeholder(place: usize) -> Key {
    let mut k = b"retired".to_vec();
    k.push(place as u8);
    k
}

/// A roster index a composed message assigns, and to whose Introduction; `None` for the one it
/// carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NumberAt {
    pub index: usize,
    pub at: Option<At>,
}

/// What a composed message acknowledges of a stream: what had been published before, and now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckedRun {
    pub before: Option<Index>,
    pub now: Index,
}

/// What a composed message does once it has a box.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pending {
    pub numbers: Vec<NumberAt>,
    pub introduced: Option<Key>,
    pub acks: IndexMap<Key, AckedRun>,
    pub control: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    pub token: usize,
    pub message: Message,
}

/// A box content was delivered from.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReceivedAt {
    pub sender: Key,
    pub index: Index,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    /// Our own read cap: our key and our stream's first index.
    pub read_cap: Secret,
    pub policy: Retention,
    /// How many boxes behind it a reader keeps one a scan stepped past.
    pub recheck: usize,
    pub rosters: Rosters,
    pub readers: IndexMap<Key, Reader>,
    pub sent: SentBox,
    pub ledger: Ledger,
    pub epoch: usize,
    pub pool: Vec<Index>,
    /// The furthest of our own indexes derived so far.
    pub tip: Index,
    pub deriving: bool,
    /// Content waiting for an index.
    pub outbox: Vec<Vec<u8>>,
    /// The messages composed that have no box yet, by token.
    pub pending: IndexMap<usize, Pending>,
    pub tokens: usize,
    /// The Introductions read whose member we have not numbered yet.
    pub unnumbered: Vec<At>,
    /// Owed in our next message, once we have read our Introduction.
    pub introduced_at: Option<IntroRef>,
    /// Our introducer, until we have read our Introduction.
    pub joined_through: Option<Key>,
    /// Each IntroducedAt read before the Introduction it names.
    pub awaiting_start: IndexMap<Key, Index>,
    /// Whether this member picks the boxes it writes, as it does driven by events. A client that
    /// writes for itself takes that over with its first call to write, and from then on the member
    /// writes nothing by itself: its pool would name boxes the client hands out too.
    pub allocates: bool,
    /// The content delivered, by sender and box, and the epoch it came, while the policy keeps
    /// received content only for a time.
    pub received: IndexMap<ReceivedAt, usize>,
}

impl Group {
    fn new(read_cap: Vec<u8>, policy: Retention, recheck: usize) -> Group {
        let start = start_of(&read_cap);
        Group {
            read_cap: read_cap.into(),
            policy,
            recheck,
            rosters: Rosters::default(),
            readers: IndexMap::new(),
            sent: SentBox::default(),
            ledger: Ledger::default(),
            epoch: 0,
            pool: vec![start.clone()],
            tip: start,
            deriving: false,
            outbox: Vec::new(),
            pending: IndexMap::new(),
            tokens: 0,
            unnumbered: Vec::new(),
            introduced_at: None,
            joined_through: None,
            awaiting_start: IndexMap::new(),
            allocates: true,
            received: IndexMap::new(),
        }
    }

    /// Our own key.
    pub fn me(&self) -> Key {
        key_of(&self.read_cap)
    }

    fn follow(&mut self, read_cap: &[u8], start: Index) {
        self.readers
            .insert(key_of(read_cap), Reader::new(read_cap.to_vec(), start));
    }

    /// Read the stream of `read_cap` from its start, unless we read it already.
    fn follow_if_new(&mut self, read_cap: &[u8]) {
        if !self.readers.contains_key(&key_of(read_cap)) {
            self.follow(read_cap, start_of(read_cap));
        }
    }

    /// Start a group with `founders`' read caps, ours among them.
    pub fn found<T: AsRef<[u8]>>(
        read_cap: &[u8],
        founders: &[T],
        policy: Retention,
        recheck: usize,
    ) -> Group {
        let mut g = Group::new(read_cap.to_vec(), policy, recheck);
        let keys: Vec<Key> = founders.iter().map(|c| key_of(c.as_ref())).collect();
        g.rosters.found(&keys);
        for c in founders {
            if key_of(c.as_ref()) != g.me() {
                g.follow(c.as_ref(), start_of(c.as_ref()));
            }
        }
        g
    }

    /// Join a group from what our introducer handed us.
    pub fn joined(read_cap: &[u8], reply: &JoinReply, policy: Retention, recheck: usize) -> Group {
        let mut g = Group::new(read_cap.to_vec(), policy, recheck);
        let me = g.me();
        let mut order: Vec<Key> = reply
            .members
            .iter()
            .enumerate()
            .map(|(place, m)| {
                m.as_ref()
                    .map_or_else(|| placeholder(place), |m| key_of(&m.read_cap))
            })
            .collect();
        order.push(me.clone());
        let mut entries: IndexMap<Key, crate::protocols::katzenqt1::member::Roster> = IndexMap::new();
        for (place, ro) in reply.rosters.iter().enumerate() {
            let (Some(ro), Some(owner)) = (ro, order.get(place)) else {
                continue;
            };
            let mut r = crate::protocols::katzenqt1::member::Roster::new();
            for e in ro {
                r.insert(
                    e.index,
                    Entry {
                        key: e.place.and_then(|p| order.get(p).cloned()),
                        prefix: None,
                    },
                );
            }
            entries.insert(owner.clone(), r);
        }
        for i in &reply.introductions {
            if let (Some(by), Some(m)) = (order.get(i.by), order.get(i.member)) {
                g.rosters.introductions.insert(
                    At {
                        introducer: by.clone(),
                        index: i.index.clone(),
                    },
                    m.clone(),
                );
            }
        }
        for m in reply.members.iter().flatten() {
            g.rosters.learn(&key_of(&m.read_cap));
        }
        g.rosters.learn(&me);
        let introducer = order.get(reply.introducer).cloned().unwrap_or_default();
        let mut own = entries.get(&introducer).cloned().unwrap_or_default();
        own.insert(
            reply.newcomer,
            Entry {
                key: Some(me.clone()),
                prefix: None,
            },
        );
        entries.insert(me, own);
        g.rosters.entries = entries;
        for m in reply.members.iter().flatten() {
            g.follow(&m.read_cap, m.start.clone());
        }
        g.joined_through = Some(introducer);
        g
    }

    // Reading

    fn heard(&self, stream: &Key) -> Vec<u64> {
        self.ledger
            .heard
            .get(stream)
            .map(|h| h.values().copied().collect())
            .unwrap_or_default()
    }

    fn scan_stream(&mut self, stream: &Key) -> Vec<Effect> {
        let heard = self.heard(stream);
        let recheck = self.recheck;
        self.readers
            .get_mut(stream)
            .map(|r| r.scan(&heard, recheck))
            .unwrap_or_default()
    }

    /// Whether `member` is in our roster, or will be once what we have composed is written.
    fn numbered(&self, member: &Key) -> bool {
        self.rosters.index_of(&self.me(), member).is_some()
            || self.pending.values().any(|p| {
                p.introduced.as_ref() == Some(member)
                    || p.numbers.iter().any(|n| {
                        n.at.as_ref()
                            .is_some_and(|a| self.rosters.introductions.get(a) == Some(member))
                    })
            })
    }

    /// `member`'s roster began as `introducer`'s, through the index `introducer` gave it.
    fn begin_roster(&mut self, member: &Key, introducer: &Key) {
        if let Some(place) = self.rosters.index_of(introducer, member) {
            self.rosters.started.insert(
                member.clone(),
                Started {
                    introducer: introducer.clone(),
                    top: place,
                },
            );
        }
    }

    /// `member` says it joined through the Introduction at `index`.
    fn started(&mut self, member: &Key, index: &Index) {
        let found = self
            .rosters
            .introductions
            .iter()
            .find(|(a, n)| *n == member && &a.index == index)
            .map(|(a, _)| a.introducer.clone());
        match found {
            Some(introducer) => self.begin_roster(member, &introducer),
            None => {
                self.awaiting_start.insert(member.clone(), index.clone());
            }
        }
    }

    /// Our own Introduction by the introducer we joined through: say where, in IntroducedAt.
    fn note_own(&mut self, introducer: &Key, index: &Index, new: &Key) {
        if new == &self.me()
            && self.joined_through.as_ref() == Some(introducer)
            && let Some(place) = self.rosters.index_of(&self.me(), introducer)
        {
            self.introduced_at = Some(IntroRef {
                introducer: place,
                index: index.clone(),
            });
            self.joined_through = None;
        }
    }

    /// An IntroducedAt read earlier named this Introduction.
    fn note_awaited(&mut self, introducer: &Key, index: &Index, new: &Key) {
        if self.awaiting_start.get(new) == Some(index) {
            self.awaiting_start.shift_remove(new);
            self.begin_roster(new, introducer);
        }
    }

    /// Read the new member's stream, and owe it a number.
    fn note_new(&mut self, introducer: &Key, index: &Index, intro: &Introduction) {
        let new = key_of(&intro.read_cap);
        if new == self.me() || self.numbered(&new) {
            return;
        }
        self.follow_if_new(&intro.read_cap);
        let a = At {
            introducer: introducer.clone(),
            index: index.clone(),
        };
        if !self.unnumbered.contains(&a) {
            self.unnumbered.push(a);
        }
    }

    fn introduced(&mut self, introducer: &Key, index: &Index, intro: &Introduction) {
        let new = key_of(&intro.read_cap);
        self.rosters.introductions.insert(
            At {
                introducer: introducer.clone(),
                index: index.clone(),
            },
            new.clone(),
        );
        self.rosters.learn(&new);
        self.note_own(introducer, index, &new);
        self.note_awaited(introducer, index, &new);
        self.note_new(introducer, index, intro);
    }

    /// Take one acknowledgement `sender` sent: of our own stream, it counts only for a box the
    /// Sent-box check finds; of another's, it is heard.
    fn take_ack(&mut self, sender: &Key, a: Ack) {
        match self.rosters.resolve(sender, a.member) {
            None => {}
            Some(acked) if acked == self.me() => {
                if self.sent.check_at(a.idx64) {
                    self.ledger.acked(sender, a.idx64);
                }
            }
            Some(acked) => self.ledger.hear(&acked, a.idx64, sender),
        }
    }

    fn deliver(&mut self, sender: &Key, index: &Index, m: &Message) -> Vec<Effect> {
        let Some(content) = &m.content else {
            return Vec::new();
        };
        if self.policy.keep_received.is_some() {
            self.received.insert(
                ReceivedAt {
                    sender: sender.clone(),
                    index: index.clone(),
                },
                self.epoch,
            );
        }
        vec![Effect::Deliver {
            sender: sender.clone(),
            index: index.clone(),
            content: content.clone(),
        }]
    }

    fn ingest(&mut self, sender: &Key, index: &Index, m: &Message) -> Vec<Effect> {
        for n in &m.numbers {
            let e = match (&n.prefix, &m.introduction) {
                (Some(p), _) => Entry {
                    key: None,
                    prefix: Some(p.clone()),
                },
                (None, Some(i)) => Entry {
                    key: Some(key_of(&i.read_cap)),
                    prefix: None,
                },
                (None, None) => Entry::default(),
            };
            self.rosters.number(sender, n.index, e);
        }
        if let Some(i) = &m.introduction {
            self.introduced(sender, index, i);
        }
        if let Some(at) = &m.introduced_at {
            self.started(sender, &at.index);
        }
        for &a in &m.acks {
            self.take_ack(sender, a);
        }
        self.deliver(sender, index, m)
    }

    fn box_read(
        &mut self,
        stream: &Key,
        index: &Index,
        result: ReadResult,
        next: Option<Index>,
    ) -> Vec<Effect> {
        let recheck = self.recheck;
        let Some(r) = self.readers.get_mut(stream) else {
            return Vec::new();
        };
        let (m, es) = r.found(index, result, next, recheck);
        match m {
            None => es,
            Some(m) => {
                let mut out = self.ingest(stream, index, &m);
                out.extend(es);
                out
            }
        }
    }

    // Writing

    /// The next index of our roster, counting what is composed.
    fn size(&self) -> usize {
        self.pending
            .values()
            .flat_map(|p| &p.numbers)
            .fold(self.rosters.size(&self.me()), |m, n| m.max(n.index + 1))
    }

    /// Whether our roster has an index left for one more member. Without one an Introduction
    /// numbers nobody, and its member cannot join.
    pub fn room(&self) -> bool {
        self.size() < ROSTER_MAX
    }

    /// Our view of the group, as a message we make ourselves says it: ourselves and every member
    /// we read, but for `leaving`.
    pub fn membership(&self, leaving: Option<&Key>) -> Vec<u8> {
        let caps: Vec<&[u8]> = std::iter::once(&self.read_cap[..])
            .chain(self.readers.values().map(|r| &r.read_cap[..]))
            .filter(|c| leaving != Some(&key_of(c)))
            .collect();
        membership_hash(&caps).to_vec()
    }

    fn owes_control(&self) -> bool {
        !self.ledger.holding() && (self.introduced_at.is_some() || !self.numberable().is_empty())
    }

    /// Whom a control message would number now: each member whose Introduction we have read,
    /// while our roster has room, once per key prefix, so that the Numbers field can name each.
    /// One whose prefix is taken waits for the next control message.
    fn numberable(&self) -> Vec<(At, Key)> {
        let mut out: Vec<(At, Key)> = Vec::new();
        let size = self.size();
        for a in &self.unnumbered {
            let Some(new) = self.rosters.introductions.get(a) else {
                continue;
            };
            let p = prefix_of(new);
            if size + out.len() < ROSTER_MAX
                && p.len() == PREFIX_SIZE
                && !out.iter().any(|(_, k)| prefix_of(k) == p)
            {
                out.push((a.clone(), new.clone()));
            }
        }
        out
    }

    /// Number whom `numberable` names, and say where we were introduced.
    fn control(&mut self) -> (Message, Pending) {
        let mut m = Message {
            introduced_at: self.introduced_at.clone(),
            membership_hash: Some(self.membership(None)),
            ..Message::default()
        };
        let mut p = Pending {
            control: true,
            ..Pending::default()
        };
        let mut left = self.unnumbered.clone();
        for (next, (a, new)) in (self.size()..).zip(self.numberable()) {
            m.numbers.push(Number {
                index: next,
                prefix: Some(prefix_of(&new).to_vec()),
            });
            p.numbers.push(NumberAt {
                index: next,
                at: Some(a.clone()),
            });
            if let Some(i) = left.iter().position(|x| *x == a) {
                left.remove(i);
            }
        }
        self.unnumbered = left;
        self.introduced_at = None;
        (m, p)
    }

    fn release(&mut self) {
        self.ledger.induction = Induction::Idle;
        self.ledger.invitee = None;
        self.ledger.commit = false;
        self.ledger.starts = IndexMap::new();
    }

    fn hold(&mut self) {
        self.ledger.induction = Induction::Inducting;
        self.ledger.starts = self
            .readers
            .iter()
            .map(|(k, r)| (k.clone(), r.next.clone()))
            .collect();
    }

    /// The Introduction of the member read by `read_cap`, numbering it next unless it is numbered
    /// already, and what it does once written.
    fn introduction_of(&self, name: &str, read_cap: &[u8]) -> (Message, Pending) {
        let new = key_of(read_cap);
        let mut m = Message {
            introduction: Some(Introduction {
                name: name.into(),
                read_cap: read_cap.to_vec(),
            }),
            membership_hash: Some(self.membership(Some(&new))),
            ..Message::default()
        };
        let mut p = Pending {
            introduced: Some(new.clone()),
            control: true,
            ..Pending::default()
        };
        if !self.numbered(&new) && self.room() {
            let n = self.size();
            m.numbers = vec![Number {
                index: n,
                prefix: None,
            }];
            p.numbers = vec![NumberAt { index: n, at: None }];
        }
        (m, p)
    }

    fn introduction(&mut self, name: &str, read_cap: &[u8]) -> (Message, Pending) {
        let out = self.introduction_of(name, read_cap);
        self.follow_if_new(read_cap);
        self.release();
        out
    }

    /// Acknowledge every stream we read whose run has moved on since we last did, keyed by our
    /// roster index and naming each box by its Idx64.
    fn with_acks(&mut self, m: &mut Message, p: &mut Pending) {
        for KnownEntry { index, key } in self.rosters.known(&self.me()) {
            let Some(r) = key.and_then(|k| self.readers.get(&k)) else {
                continue;
            };
            let Some(owed) = self.ledger.owed(&r.stream, r.run()) else {
                continue;
            };
            m.acks.push(Ack {
                member: index,
                idx64: counter(&owed),
            });
            let stream = r.stream.clone();
            p.acks.insert(
                stream.clone(),
                AckedRun {
                    before: self.ledger.published.get(&stream).cloned(),
                    now: owed.clone(),
                },
            );
            self.ledger.published.insert(stream, owed);
        }
    }

    fn stage(&mut self, m: Message, p: Pending) -> Outgoing {
        self.tokens += 1;
        self.pending.insert(self.tokens, p);
        Outgoing {
            token: self.tokens,
            message: m,
        }
    }

    /// The message `token` landed in the box `index` of our stream.
    pub fn written(&mut self, token: usize, index: &Index, plaintext: Option<Payload>) {
        self.allocates = false;
        self.landed(token, index, plaintext);
    }

    /// The message `token` landed in the box `index` of our stream, which we picked or our client
    /// did.
    fn landed(&mut self, token: usize, index: &Index, plaintext: Option<Payload>) {
        let Some(p) = self.pending.get(&token).cloned() else {
            return;
        };
        let me = self.me();
        for n in &p.numbers {
            let key = match &n.at {
                Some(a) => self.rosters.introductions.get(a).cloned(),
                None => p.introduced.clone(),
            };
            self.rosters
                .number(&me, n.index, Entry { key, prefix: None });
        }
        if let Some(new) = &p.introduced {
            self.rosters.learn(new);
            self.rosters.introductions.insert(
                At {
                    introducer: me,
                    index: index.clone(),
                },
                new.clone(),
            );
        }
        self.pending.shift_remove(&token);
        self.sent
            .record(index.clone(), plaintext, p.control, self.epoch);
    }

    fn write(&mut self, o: Outgoing) -> Vec<Effect> {
        if self.pool.is_empty() {
            return Vec::new();
        }
        let index = self.pool.remove(0);
        self.landed(o.token, &index, Some(Payload::Message(o.message.clone())));
        vec![Effect::WriteBox {
            index,
            payload: Payload::Message(o.message),
        }]
    }

    /// The message to send next: control if owed, else the oldest content.
    fn next(&mut self) -> (Message, Pending) {
        if self.owes_control() {
            return self.control();
        }
        let content = (!self.outbox.is_empty()).then(|| self.outbox.remove(0));
        (
            Message {
                content,
                ..Message::default()
            },
            Pending::default(),
        )
    }

    /// Write what is owed.
    fn flush(&mut self) -> Vec<Effect> {
        let mut es = Vec::new();
        for _ in 0..self.pool.len() {
            if !self.allocates
                || self.pool.is_empty()
                || !(self.owes_control() || !self.outbox.is_empty())
            {
                break;
            }
            let (mut m, mut p) = self.next();
            self.with_acks(&mut m, &mut p);
            let o = self.stage(m, p);
            es.extend(self.write(o));
        }
        if self.allocates && self.pool.len() < 2 && !self.deriving {
            self.deriving = true;
            es.push(Effect::DeriveIndexes {
                stream: self.me(),
                start: self.tip.clone(),
                count: POOL_SIZE,
            });
        }
        es
    }

    fn settled(&self) -> bool {
        self.unnumbered.is_empty()
            && self.outbox.is_empty()
            && self.readers.values().all(|r| r.mode == crate::protocols::katzenqt1::member::Mode::Idle)
    }

    /// What to hand a new member, which will start our stream at `own_start`.
    pub fn reply(&self, own_start: &Index) -> JoinReply {
        let order = self.rosters.known(&self.me());
        let size = order.last().map_or(0, |e| e.index + 1);
        let mut place: IndexMap<Key, usize> = IndexMap::new();
        for e in &order {
            if let Some(k) = &e.key {
                place.insert(k.clone(), e.index);
            }
        }
        let key_at = |index: usize| {
            order
                .iter()
                .find(|e| e.index == index)
                .and_then(|e| e.key.clone())
        };
        let me = self.me();
        let members = (0..size)
            .map(|index| {
                let k = key_at(index)?;
                if k == me {
                    return Some(Member {
                        read_cap: self.read_cap.to_vec(),
                        start: own_start.clone(),
                    });
                }
                let r = self.readers.get(&k)?;
                Some(Member {
                    read_cap: r.read_cap.to_vec(),
                    start: self.ledger.starts.get(&k).unwrap_or(&r.next).clone(),
                })
            })
            .collect();
        let rosters = (0..size)
            .map(|index| {
                let known = key_at(index)
                    .map(|k| self.rosters.known(&k))
                    .unwrap_or_default();
                if known.is_empty() {
                    return None;
                }
                let r: WireRoster = known
                    .into_iter()
                    .map(|e| RosterEntry {
                        index: e.index,
                        place: e.key.and_then(|k| place.get(&k).copied()),
                    })
                    .collect();
                Some(r)
            })
            .collect();
        let introductions = self
            .rosters
            .introductions
            .iter()
            .filter_map(|(a, k)| {
                Some(IntroAt {
                    by: *place.get(&a.introducer)?,
                    index: a.index.clone(),
                    member: *place.get(k)?,
                })
            })
            .collect();
        JoinReply {
            members,
            rosters,
            introductions,
            introducer: place.get(&me).copied().unwrap_or(0),
            newcomer: size,
        }
    }

    /// Stage the Introduction of the member read by `read_cap`.
    pub fn introduce_now(&mut self, name: &str, read_cap: &[u8]) -> Outgoing {
        self.allocates = false;
        let (m, p) = self.introduction(name, read_cap);
        self.stage(m, p)
    }

    fn commit_induction(&mut self) -> Vec<Effect> {
        let Some(inv) = self.ledger.invitee.clone() else {
            return Vec::new();
        };
        let head = self.pool.first().cloned().unwrap_or_default();
        let reply = self.reply(&head);
        let (m, p) = self.introduction(&inv.name, &inv.read_cap);
        let o = self.stage(m, p);
        let mut es = self.write(o);
        es.push(Effect::SendJoinReply {
            to: inv.read_cap,
            reply,
        });
        es.extend(self.flush());
        es
    }

    /// Do whatever has become possible: write what is owed, finish catching up, commit an
    /// induction.
    fn progress(&mut self) -> Vec<Effect> {
        let mut es = self.flush();
        if self.ledger.induction == Induction::CatchingUp && self.settled() {
            self.hold();
        }
        if self.ledger.induction == Induction::Inducting
            && self.ledger.commit
            && self.allocates
            && !self.pool.is_empty()
        {
            es.extend(self.commit_induction());
        }
        es
    }

    fn derived(&mut self, indexes: Vec<Index>) -> Vec<Effect> {
        self.deriving = false;
        if let Some(last) = indexes.last() {
            self.tip = last.clone();
        }
        self.pool.extend(indexes);
        self.progress()
    }

    fn invite(&mut self, name: String, read_cap: Secret, commit: bool) -> Vec<Effect> {
        self.ledger.induction = Induction::CatchingUp;
        self.ledger.invitee = Some(Invitee { name, read_cap });
        self.ledger.commit = commit;
        let mut es: Vec<Effect> = self.readers.values_mut().flat_map(|r| r.read()).collect();
        es.extend(self.progress());
        es
    }

    // Membership and time

    /// Stop reading `member` and forget its key, keeping its places.
    pub fn remove(&mut self, member: &Key) {
        let token = match self.rosters.index_of(&self.me(), member) {
            Some(place) => placeholder(place),
            None => [b"retired:".as_slice(), &member[..member.len().min(8)]].concat(),
        };
        self.rosters.retire(member, &token);
        self.readers.shift_remove(member);
        self.ledger.forget(member);
        let intros = &self.rosters.introductions;
        self.unnumbered.retain(|a| intros.get(a) != Some(&token));
    }

    fn everyone_acked(readers: &IndexMap<Key, Reader>, ledger: &Ledger, idx64: u64) -> bool {
        readers
            .keys()
            .all(|k| ledger.acked_by.get(k).is_some_and(|&s| idx64 <= s))
    }

    fn on_epoch(&mut self, epoch: usize) -> Vec<Effect> {
        self.epoch = epoch;
        let (readers, ledger) = (&self.readers, &self.ledger);
        self.sent.retain(epoch, &self.policy, |k| {
            Group::everyone_acked(readers, ledger, k)
        });
        let mut es = Vec::new();
        if self.policy.keep_received.is_none() {
            self.received.clear();
        }
        if let Some(keep) = self.policy.keep_received {
            let expired: Vec<ReceivedAt> = self
                .received
                .iter()
                .filter(|(_, at)| **at + keep <= epoch)
                .map(|(k, _)| k.clone())
                .collect();
            for k in &expired {
                es.push(Effect::Expire {
                    sender: k.sender.clone(),
                    index: k.index.clone(),
                });
            }
            self.received.retain(|k, _| !expired.contains(k));
        }
        let (readers, ledger) = (&self.readers, &self.ledger);
        es.extend(
            self.sent
                .backfill(epoch, |k| Group::everyone_acked(readers, ledger, k)),
        );
        es
    }

    // Driven by events

    pub fn handle(&mut self, e: Event) -> Vec<Effect> {
        match e {
            Event::Send { content } => {
                self.outbox.push(content);
                self.progress()
            }
            Event::Read { stream } => self
                .readers
                .get_mut(&stream)
                .map(|r| r.read())
                .unwrap_or_default(),
            Event::Scan { stream } => self.scan_stream(&stream),
            Event::BoxRead {
                stream,
                index,
                result,
                next,
            } => {
                let mut es = self.box_read(&stream, &index, result, next);
                es.extend(self.progress());
                es
            }
            Event::IndexesDerived { indexes, .. } => self.derived(indexes),
            Event::Walked {
                stream,
                target,
                skipped,
                steps,
            } => {
                let recheck = self.recheck;
                self.readers
                    .get_mut(&stream)
                    .map(|r| r.walked(target, &skipped, steps, recheck))
                    .unwrap_or_default()
            }
            Event::Invite { name, read_cap } => self.invite(name, read_cap, false),
            Event::Introduce { name, read_cap } => {
                if self.ledger.induction == Induction::Idle {
                    return self.invite(name, read_cap, true);
                }
                self.ledger.commit = true;
                self.progress()
            }
            Event::Remove { member } => {
                self.remove(&member);
                Vec::new()
            }
            Event::EpochChanged { epoch } => self.on_epoch(epoch),
        }
    }

    // Driven by a client that reads and writes for itself

    /// A box read on `stream`, in order: its message, or `None` for one that holds nothing we can
    /// use.
    pub fn observe(
        &mut self,
        stream: &Key,
        index: &Index,
        m: Option<Message>,
        next: &Index,
    ) -> Vec<Effect> {
        let Some(r) = self.readers.get_mut(stream) else {
            return Vec::new();
        };
        r.next = index.clone();
        r.mode = crate::protocols::katzenqt1::member::Mode::Reading;
        let es = self.box_read(stream, index, ReadResult::Data(m), Some(next.clone()));
        if let Some(r) = self.readers.get_mut(stream) {
            r.mode = crate::protocols::katzenqt1::member::Mode::Idle;
        }
        es.into_iter()
            .filter(|e| matches!(e, Effect::Deliver { .. } | Effect::Expire { .. }))
            .collect()
    }

    /// The messages to send now, in order: a control message if one is owed, then `content`. Each
    /// takes effect when written.
    pub fn compose(&mut self, content: Option<Vec<u8>>) -> Vec<Outgoing> {
        self.allocates = false;
        let mut owed = Vec::new();
        if self.owes_control() {
            owed.push(self.control());
        }
        if let Some(c) = content {
            owed.push((
                Message {
                    content: Some(c),
                    ..Message::default()
                },
                Pending::default(),
            ));
        }
        owed.into_iter()
            .map(|(mut m, mut p)| {
                self.with_acks(&mut m, &mut p);
                self.stage(m, p)
            })
            .collect()
    }

    /// The message `token` will never be written: whatever it acknowledged is owed again, and
    /// whoever it numbered still needs numbering.
    pub fn abandoned(&mut self, token: usize) {
        let Some(p) = self.pending.shift_remove(&token) else {
            return;
        };
        for (stream, a) in &p.acks {
            if self.ledger.published.get(stream) == Some(&a.now) {
                match &a.before {
                    Some(b) => {
                        self.ledger.published.insert(stream.clone(), b.clone());
                    }
                    None => {
                        self.ledger.published.shift_remove(stream);
                    }
                }
            }
        }
        if p.introduced.is_none() {
            self.unnumbered
                .extend(p.numbers.into_iter().filter_map(|n| n.at));
        }
    }

    /// Begin inducting a member, starting each stream where we have read it now. Anything owed
    /// goes out first.
    pub fn begin_induction(&mut self) -> Vec<Outgoing> {
        let out = self.compose(None);
        self.hold();
        out
    }

    pub fn cancel_induction(&mut self) {
        self.release();
    }

    /// Who `owner` numbered `index`, if this member can tell.
    pub fn resolve(&self, owner: &Key, index: usize) -> Option<Key> {
        self.rosters.resolve(owner, index)
    }
}
