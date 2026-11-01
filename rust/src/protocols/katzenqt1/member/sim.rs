//! katzenqt's group chat scenarios (its groupchat/sim.py), run through the member: the same
//! replica rules, the same seeded keys and the same way of printing what each member read,
//! wrote, acknowledged and resolved.

use indexmap::IndexMap;
use crate::protocols::katzenqt1::wire::{JoinReply, Message, counter as idx64_of, key_of as wire_key_of};
use rand::{Rng, SeedableRng, rngs::StdRng};
use serde_json::{Value, json};
use sha3::digest::{ExtendableOutput, Update, XofReader};

use crate::protocols::katzenqt1::member::{
    Effect, Event, Group, Index, Key, Outgoing, Payload, ReadResult, Retention, WALK_LIMIT,
    next_index, trace, walk_with,
};

/// shake_256("{name}/{n}"), the nth draw of katzenqt's seeded randomness.
fn draw(name: &str, n: usize, size: usize) -> Vec<u8> {
    let mut h = sha3::Shake256::default();
    h.update(format!("{name}/{n}").as_bytes());
    let mut out = vec![0u8; size];
    h.finalize_xof().read(&mut out);
    out
}

/// The read cap katzenqt's WriteCap.generate(seeded(name)) makes: a signing seed, then an HKDF
/// state and a starting index, as BACAP picks one.
fn read_cap_of(name: &str) -> Vec<u8> {
    let seed: [u8; 32] = draw(name, 1, 32).try_into().unwrap();
    let pk = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    let hkdf_state = draw(name, 2, 32);
    let mut r = draw(name, 3, 16);
    r[7] &= 0x3f;
    r[15] &= 0x3f;
    let idx = u64::from_le_bytes(r[..8].try_into().unwrap())
        + u64::from_le_bytes(r[8..].try_into().unwrap());
    let mut index = idx.to_le_bytes().to_vec();
    index.extend([0u8; 64]);
    index.extend(hkdf_state);
    [pk.as_slice(), &next_index(&index).unwrap()].concat()
}

fn step(i: &[u8]) -> Index {
    next_index(i).unwrap_or_default()
}

/// What a box holds: a message, or a tombstone.
type Stored = Option<Message>;

#[derive(Default)]
struct Replica {
    epoch: usize,
    buckets: Vec<(usize, Vec<(Index, Stored)>)>,
}

impl Replica {
    fn kept(&self) -> Vec<usize> {
        if self.epoch == 0 {
            vec![0]
        } else {
            vec![self.epoch, self.epoch - 1]
        }
    }

    fn bucket(&self, e: usize) -> &[(Index, Stored)] {
        self.buckets.iter().find(|b| b.0 == e).map_or(&[], |b| &b.1)
    }

    fn read(&self, index: &Index) -> Option<&Stored> {
        self.kept()
            .into_iter()
            .find_map(|e| self.bucket(e).iter().find(|s| &s.0 == index).map(|s| &s.1))
    }

    /// A write to a box still kept succeeds only with what it holds already, and a tombstone is
    /// always stored.
    fn write(&mut self, index: &Index, b: Stored) -> &'static str {
        if b.is_some()
            && let Some(old) = self.read(index)
        {
            return if old == &b { "same" } else { "refused" };
        }
        let mut bucket: Vec<(Index, Stored)> = self
            .bucket(self.epoch)
            .iter()
            .filter(|s| &s.0 != index)
            .cloned()
            .collect();
        bucket.push((index.clone(), b));
        let e = self.epoch;
        self.buckets.retain(|x| x.0 != e);
        self.buckets.push((e, bucket));
        "stored"
    }

    fn advance(&mut self) {
        self.epoch += 1;
        let kept = self.kept();
        self.buckets.retain(|b| kept.contains(&b.0));
    }
}

struct SimMember {
    name: String,
    read_cap: Vec<u8>,
    /// Our stream's indexes from its first, WALK_LIMIT of them.
    chain: Vec<Index>,
    group: Option<Group>,
    inbox: Vec<(Key, Index, String)>,
    seen: Vec<((Key, Index), Message)>,
    reported: i128,
    passive: bool,
    unwritten: Vec<Outgoing>,
    next_own: Index,
    cursors: IndexMap<Key, Index>,
}

impl SimMember {
    fn key(&self) -> Key {
        wire_key_of(&self.read_cap).to_vec()
    }

    fn ordinal_of(&self, index: &Index) -> Option<usize> {
        self.chain.iter().position(|i| i == index)
    }

    /// Which box of our stream an Idx64 names.
    fn ordinal_at(&self, idx64: u64) -> Option<usize> {
        let first = idx64_of(&self.chain[0]);
        (first <= idx64 && idx64 - first < WALK_LIMIT).then(|| (idx64 - first) as usize)
    }
}

#[derive(Clone, Copy)]
enum Opt {
    Flag(bool),
    Nothing,
    Num(usize),
}

/// Told of every call made on a member, as a trace line.
pub type Recorder<'a> = &'a mut dyn FnMut(Value);

struct World<'a> {
    replica: Replica,
    members: Vec<SimMember>,
    options: Vec<(String, Opt)>,
    record: Option<Recorder<'a>>,
}

type R<T> = Result<T, String>;

enum Fetched {
    Data(Message),
    Tombstone,
    NotFound,
}

impl Fetched {
    fn value(&self) -> &'static str {
        match self {
            Fetched::Tombstone => "tombstone",
            _ => "not found",
        }
    }

    fn result(&self) -> ReadResult {
        match self {
            Fetched::Data(m) => ReadResult::Data(Some(m.clone())),
            Fetched::Tombstone => ReadResult::Tombstone,
            Fetched::NotFound => ReadResult::NotFound,
        }
    }

    fn message(&self) -> Option<Message> {
        match self {
            Fetched::Data(m) => Some(m.clone()),
            _ => None,
        }
    }
}

impl<'a> World<'a> {
    fn option(&self, name: &str) -> Option<Opt> {
        self.options.iter().find(|o| o.0 == name).map(|o| o.1)
    }

    fn flag(&self, name: &str) -> bool {
        matches!(self.option(name), Some(Opt::Flag(true)))
    }

    fn policy(&self) -> Retention {
        let num = |n: &str, d: Option<usize>| match self.option(n) {
            Some(Opt::Num(k)) => Some(k),
            Some(Opt::Nothing) => None,
            _ => d,
        };
        Retention {
            window: num("window", Some(3)),
            keep_sent: num("keep_sent", None),
            keep_received: num("keep_received", None),
            discard_acked: !matches!(self.option("discard_acked"), Some(Opt::Flag(false))),
        }
    }

    fn recheck(&self) -> usize {
        match self.option("recheck") {
            Some(Opt::Num(k)) => k,
            _ => 256,
        }
    }

    fn new_member(&mut self, name: &str) -> usize {
        let read_cap = read_cap_of(name);
        let mut chain = vec![read_cap[32..].to_vec()];
        while chain.len() < WALK_LIMIT as usize {
            chain.push(step(chain.last().unwrap()));
        }
        let m = SimMember {
            name: name.into(),
            read_cap,
            chain,
            group: None,
            inbox: Vec::new(),
            seen: Vec::new(),
            reported: -1,
            passive: false,
            unwritten: Vec::new(),
            next_own: Vec::new(),
            cursors: IndexMap::new(),
        };
        match self.members.iter().position(|o| o.name == name) {
            Some(i) => {
                self.members[i] = m;
                i
            }
            None => {
                self.members.push(m);
                self.members.len() - 1
            }
        }
    }

    fn member(&mut self, name: &str) -> usize {
        match self.members.iter().position(|m| m.name == name) {
            Some(i) => i,
            None => self.new_member(name),
        }
    }

    fn existing(&self, name: &str) -> R<usize> {
        self.members
            .iter()
            .position(|m| m.name == name)
            .ok_or_else(|| format!("no member {name}"))
    }

    fn group_of(&self, i: usize) -> R<&Group> {
        self.members[i]
            .group
            .as_ref()
            .ok_or_else(|| format!("{} has not joined", self.members[i].name))
    }

    fn by_key(&self, k: &[u8]) -> Option<usize> {
        self.members.iter().position(|m| m.key() == k)
    }

    fn name_of(&self, k: Option<&Key>) -> String {
        match k {
            Some(k) if k.starts_with(b"retired") => "removed".into(),
            Some(k) => self
                .by_key(k)
                .map_or("?".into(), |i| self.members[i].name.clone()),
            None => "?".into(),
        }
    }

    /// name@n: the nth box of its stream.
    fn at_index(&self, k: &[u8], index: &Index) -> R<String> {
        let m = &self.members[self.by_key(k).ok_or("no member with that key")?];
        Ok(format!(
            "{}@{}",
            m.name,
            m.ordinal_of(index).map_or("None".into(), |n| n.to_string())
        ))
    }

    fn at_idx64(&self, k: &[u8], idx64: u64) -> R<String> {
        let m = &self.members[self.by_key(k).ok_or("no member with that key")?];
        Ok(format!(
            "{}@{}",
            m.name,
            m.ordinal_at(idx64).map_or("None".into(), |n| n.to_string())
        ))
    }

    /// Which stream's box an Idx64 names.
    fn where_idx64(&self, idx64: u64) -> String {
        self.members
            .iter()
            .find_map(|m| m.ordinal_at(idx64).map(|n| format!("{}@{n}", m.name)))
            .unwrap_or("?".into())
    }

    /// Who has a key starting with `p`: the truth.
    fn prefixed(&self, p: &[u8]) -> String {
        let found: Vec<&SimMember> = self
            .members
            .iter()
            .filter(|m| m.key().starts_with(p))
            .collect();
        if found.len() == 1 {
            found[0].name.clone()
        } else {
            "?".into()
        }
    }

    /// Who the Introduction in the box `index` introduced: the truth, from its introducer's
    /// records.
    fn introduced(&self, index: &[u8]) -> String {
        for m in &self.members {
            let Some(g) = &m.group else { continue };
            let Some(r) = g.sent.records.get(&idx64_of(index)) else {
                continue;
            };
            if r.index == index
                && let Some(Payload::Message(msg)) = &r.plaintext
                && let Some(i) = &msg.introduction
            {
                return i.name.clone();
            }
        }
        "?".into()
    }

    fn show_msg(&self, m: &Message) -> String {
        let mut parts = Vec::new();
        if let Some(c) = &m.content {
            parts.push(format!("\"{}\"", String::from_utf8_lossy(c)));
        }
        if let Some(i) = &m.introduction {
            parts.push(format!("introduces {}", i.name));
        }
        if let Some(r) = &m.introduced_at {
            parts.push(format!("introduced-at {}", self.introduced(&r.index)));
        }
        if !m.numbers.is_empty() {
            let ns: Vec<String> = m
                .numbers
                .iter()
                .map(|n| {
                    let who = match (&n.prefix, &m.introduction) {
                        (Some(p), _) => {
                            if p.is_empty() {
                                "?".into()
                            } else {
                                self.prefixed(p)
                            }
                        }
                        (None, Some(i)) => i.name.clone(),
                        (None, None) => "?".into(),
                    };
                    format!("{}:{who}", n.index)
                })
                .collect();
            parts.push(format!("numbers {}", ns.join(" ")));
        }
        if !m.acks.is_empty() {
            let mut acks = m.acks.clone();
            acks.sort_by_key(|a| a.member);
            let s: Vec<String> = acks
                .iter()
                .map(|a| format!("{}:{}", a.member, self.where_idx64(a.idx64)))
                .collect();
            parts.push(format!("acks {}", s.join(" ")));
        }
        if parts.is_empty() {
            "(empty)".into()
        } else {
            parts.join(" ")
        }
    }

    fn fetch(&self, index: &Index) -> (Fetched, Option<Index>) {
        match self.replica.read(index) {
            None => (Fetched::NotFound, None),
            Some(None) => (Fetched::Tombstone, Some(step(index))),
            Some(Some(m)) => (Fetched::Data(m.clone()), Some(step(index))),
        }
    }

    fn store_ok(&mut self, index: &Index, b: Stored) -> R<()> {
        match self.replica.write(index, b) {
            "stored" | "same" => Ok(()),
            r => Err(format!("a write was {r}")),
        }
    }

    fn show_read(
        &mut self,
        i: usize,
        stream: &Key,
        index: &Index,
        f: &Fetched,
        recheck: bool,
    ) -> R<Vec<String>> {
        let at = self.at_index(stream, index)?;
        if let Fetched::Data(m) = f {
            let shown = format!("{at} {}", self.show_msg(m));
            let seen = &mut self.members[i].seen;
            seen.retain(|e| e.0 != (stream.clone(), index.clone()));
            seen.push(((stream.clone(), index.clone()), m.clone()));
            return Ok(vec![shown]);
        }
        if recheck {
            return Ok(vec![format!("{at} recheck: {}", f.value())]);
        }
        let mut lines = vec![format!("{at} {}", f.value())];
        let Some(o) = self.by_key(stream) else {
            return Ok(lines);
        };
        if let (Fetched::NotFound, Some(here)) = (f, self.members[o].ordinal_of(index))
            && let Some(h) = self.group_of(i)?.ledger.heard.get(stream)
        {
            for (by, &heard) in h {
                if self.members[o]
                    .ordinal_at(heard)
                    .is_some_and(|there| there >= here)
                {
                    lines.push(format!(
                        "  stuck: {} acked {}",
                        self.name_of(Some(by)),
                        self.at_idx64(stream, heard)?
                    ));
                }
            }
        }
        Ok(lines)
    }

    fn rec(&mut self, call: &str, i: usize, more: Value, result: Value) {
        if self.record.is_none() {
            return;
        }
        let m = &self.members[i];
        let g = m.group.as_ref().unwrap();
        let l = trace::line(call, &m.key(), &m.name, trace::args(g, more), result, g);
        (self.record.as_mut().unwrap())(l);
    }

    fn handle(&mut self, i: usize, e: Event) -> R<Vec<Effect>> {
        let ev = trace::event(&e);
        let es = self.members[i]
            .group
            .as_mut()
            .ok_or("not joined")?
            .handle(e);
        self.rec("handle", i, json!({"event": ev}), trace::effects(&es));
        Ok(es)
    }

    fn make_passive(&mut self, i: usize) {
        if self.flag("passive") {
            let m = &mut self.members[i];
            m.passive = true;
            m.next_own = m.chain[0].clone();
        }
    }

    fn join(&mut self, i: usize, reply: &JoinReply) -> R<Vec<String>> {
        if self.members[i].group.is_some() {
            return Ok(vec![format!("{} already joined", self.members[i].name)]);
        }
        let g = Group::joined(
            &self.members[i].read_cap,
            reply,
            self.policy(),
            self.recheck(),
        );
        self.members[i].group = Some(g);
        let rc = trace::h_pub(&self.members[i].read_cap);
        self.rec(
            "joined",
            i,
            json!({"read_cap": rc, "reply": trace::join_reply(reply)}),
            Value::Null,
        );
        let e = self.replica.epoch;
        self.handle(i, Event::EpochChanged { epoch: e })?;
        self.make_passive(i);
        Ok(Vec::new())
    }

    /// Hand `event` to member `i` and carry out its effects, depth first, until there are none
    /// left.
    fn drive(&mut self, i: usize, event: Event) -> R<Vec<String>> {
        let mut out = Vec::new();
        let mut pending = self.handle(i, event)?;
        while !pending.is_empty() {
            let e = pending.remove(0);
            let mut follow = None;
            match e {
                Effect::WriteBox { index, payload } => match payload {
                    Payload::Message(m) => self.store_ok(&index, Some(m))?,
                    Payload::Bytes(_) => {
                        return Err("a member asked to write bytes it was never given".into());
                    }
                },
                Effect::WriteTombstone { index } => self.store_ok(&index, None)?,
                Effect::ReadBox {
                    stream,
                    index,
                    recheck,
                    ..
                } => {
                    let (f, next) = self.fetch(&index);
                    out.extend(self.show_read(i, &stream, &index, &f, recheck)?);
                    follow = Some(Event::BoxRead {
                        stream,
                        index,
                        result: f.result(),
                        next,
                    });
                }
                Effect::DeriveIndexes {
                    stream,
                    start,
                    count,
                } => {
                    let mut is: Vec<Index> = Vec::new();
                    for _ in 0..count.max(1) {
                        is.push(step(is.last().unwrap_or(&start)));
                    }
                    follow = Some(Event::IndexesDerived {
                        stream,
                        indexes: is,
                    });
                }
                Effect::Walk {
                    stream,
                    start,
                    targets,
                    keep,
                } => {
                    let (target, skipped, steps) =
                        walk_with(|b| Ok::<_, ()>(step(b)), &start, &targets, keep).unwrap();
                    follow = Some(Event::Walked {
                        stream,
                        target,
                        skipped,
                        steps,
                    });
                }
                Effect::Deliver {
                    sender,
                    index,
                    content,
                } => self.members[i].inbox.push((
                    sender,
                    index,
                    String::from_utf8_lossy(&content).into(),
                )),
                Effect::Expire { sender, index } => self.members[i]
                    .inbox
                    .retain(|d| !(d.0 == sender && d.1 == index)),
                Effect::SendJoinReply { to, reply } => {
                    let n = self
                        .by_key(wire_key_of(&to))
                        .ok_or("a join reply to no member")?;
                    out.extend(self.join(n, &reply)?);
                }
            }
            if let Some(f) = follow {
                let mut more = self.handle(i, f)?;
                more.extend(pending);
                pending = more;
            }
        }
        Ok(out)
    }

    fn written(&mut self, i: usize, token: usize, index: &Index, p: Payload) {
        let pj = trace::payload(&p);
        self.members[i]
            .group
            .as_mut()
            .unwrap()
            .written(token, index, Some(p));
        self.rec(
            "written",
            i,
            json!({"token": token as u64, "index": trace::h_pub(index), "payload": pj}),
            Value::Null,
        );
    }

    /// Write what member `i` has composed, in order, as a client's own write queue would.
    fn land(&mut self, i: usize) -> R<()> {
        for o in std::mem::take(&mut self.members[i].unwritten) {
            let at = self.members[i].next_own.clone();
            self.store_ok(&at, Some(o.message.clone()))?;
            self.written(i, o.token, &at, Payload::Message(o.message));
            self.members[i].next_own = step(&at);
        }
        Ok(())
    }

    fn queue(&mut self, i: usize, out: Vec<Outgoing>) -> R<()> {
        self.members[i].unwritten.extend(out);
        if !self.flag("delay_writes") {
            self.land(i)?;
        }
        Ok(())
    }

    /// What member `i` has written since a command last printed it.
    fn written_since(&mut self, i: usize) -> R<Vec<String>> {
        let g = self.group_of(i)?;
        let mut keys: Vec<u64> = g.sent.records.keys().copied().collect();
        keys.sort();
        let mut lines = Vec::new();
        let mut reported = self.members[i].reported;
        for k in keys {
            let r = &g.sent.records[&k];
            if (k as i128) > reported
                && let Some(Payload::Message(m)) = &r.plaintext
            {
                lines.push(format!(
                    "{} {}",
                    self.at_index(&self.members[i].key(), &r.index)?,
                    self.show_msg(m)
                ));
                reported = k as i128;
            }
        }
        self.members[i].reported = reported;
        Ok(lines)
    }

    fn read_passively(&mut self, i: usize, owner: usize) -> R<Vec<String>> {
        let okey = self.members[owner].key();
        let Some(r) = self.group_of(i)?.readers.get(&okey) else {
            return Ok(Vec::new());
        };
        let mut cursor = self.members[i]
            .cursors
            .get(&okey)
            .cloned()
            .unwrap_or_else(|| r.next.clone());
        let mut out = Vec::new();
        loop {
            let (f, next) = self.fetch(&cursor);
            out.extend(self.show_read(i, &okey, &cursor, &f, false)?);
            let Some(next) = next else { break };
            let m = f.message();
            let mj = m.as_ref().map(trace::message);
            let es = self.members[i]
                .group
                .as_mut()
                .unwrap()
                .observe(&okey, &cursor, m, &next);
            self.rec("observe", i, json!({"stream": trace::h_pub(&okey), "index": trace::h_pub(&cursor), "message": mj, "next": trace::h_pub(&next)}), trace::effects(&es));
            for e in es {
                if let Effect::Deliver {
                    sender,
                    index,
                    content,
                } = e
                {
                    self.members[i].inbox.push((
                        sender,
                        index,
                        String::from_utf8_lossy(&content).into(),
                    ));
                }
            }
            cursor = next;
        }
        self.members[i].cursors.insert(okey, cursor);
        Ok(out)
    }

    fn compose(&mut self, i: usize, content: Option<Vec<u8>>) -> Vec<Outgoing> {
        let cj = content.as_deref().map(trace::h_pub);
        let out = self.members[i].group.as_mut().unwrap().compose(content);
        self.rec("compose", i, json!({"content": cj}), trace::outgoings(&out));
        out
    }

    fn invite(&mut self, who: &str, new: &str) -> R<Vec<String>> {
        let i = self.existing(who)?;
        if self.members[i].passive {
            self.land(i)?;
            let out = self.members[i]
                .group
                .as_mut()
                .ok_or("not joined")?
                .begin_induction();
            self.rec("begin_induction", i, json!({}), trace::outgoings(&out));
            self.queue(i, out)?;
            self.land(i)?;
            return self.written_since(i);
        }
        let n = self.member(new);
        let rc = self.members[n].read_cap.clone();
        let mut out = self.drive(
            i,
            Event::Invite {
                name: new.into(),
                read_cap: rc.into(),
            },
        )?;
        out.extend(self.written_since(i)?);
        Ok(out)
    }

    fn introduce(&mut self, who: &str, new: &str) -> R<Vec<String>> {
        let i = self.existing(who)?;
        if self.members[i].passive {
            if self.group_of(i)?.ledger.induction != crate::protocols::katzenqt1::member::Induction::Inducting {
                self.invite(who, new)?;
            }
            let own = self.members[i].next_own.clone();
            let reply = self.group_of(i)?.reply(&own);
            self.rec(
                "reply",
                i,
                json!({"own_start": trace::h_pub(&own)}),
                trace::join_reply(&reply),
            );
            let n = self.member(new);
            let rc = self.members[n].read_cap.clone();
            let o = self.members[i]
                .group
                .as_mut()
                .unwrap()
                .introduce_now(new, &rc);
            self.rec(
                "introduce_now",
                i,
                json!({"name": new, "read_cap": trace::h_pub(&rc)}),
                trace::outgoing(&o),
            );
            self.queue(i, vec![o])?;
            self.land(i)?;
            let mut out = self.join(n, &reply)?;
            out.extend(self.written_since(i)?);
            return Ok(out);
        }
        let n = self.member(new);
        let rc = self.members[n].read_cap.clone();
        let mut out = self.drive(
            i,
            Event::Introduce {
                name: new.into(),
                read_cap: rc.into(),
            },
        )?;
        out.extend(self.written_since(i)?);
        Ok(out)
    }

    fn joined_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .members
            .iter()
            .filter(|m| m.group.is_some())
            .map(|m| m.name.clone())
            .collect();
        names.sort();
        names
    }

    fn backfill(&mut self, who: &str) -> R<Vec<String>> {
        let i = self.existing(who)?;
        let e = self.replica.epoch;
        self.drive(i, Event::EpochChanged { epoch: e })
    }

    fn command(&mut self, words: &[&str]) -> R<Vec<String>> {
        let count = |w: &[&str]| w.first().map_or(1, |s| s.parse().unwrap_or(0));
        match words {
            ["option", o, v] => {
                if !self.members.is_empty() {
                    return Err("set options before new-group".into());
                }
                let value = match *v {
                    "on" => Opt::Flag(true),
                    "off" => Opt::Flag(false),
                    "none" => Opt::Nothing,
                    n => Opt::Num(n.parse().unwrap_or(0)),
                };
                self.options.insert(0, (o.replace('-', "_"), value));
                Ok(Vec::new())
            }
            ["new-group", names @ ..] => {
                let founders: Vec<usize> = names.iter().map(|n| self.new_member(n)).collect();
                let caps: Vec<Vec<u8>> = founders
                    .iter()
                    .map(|&i| self.members[i].read_cap.clone())
                    .collect();
                for &i in &founders {
                    self.members[i].group = Some(Group::found(
                        &self.members[i].read_cap,
                        &caps,
                        self.policy(),
                        self.recheck(),
                    ));
                    let fs: Vec<Value> = caps.iter().map(|c| trace::h_pub(c)).collect();
                    let rc = trace::h_pub(&self.members[i].read_cap);
                    self.rec(
                        "found",
                        i,
                        json!({"read_cap": rc, "founders": fs}),
                        Value::Null,
                    );
                    self.make_passive(i);
                }
                Ok(Vec::new())
            }
            ["send", who, text @ ..] => {
                let i = self.existing(who)?;
                let content = text.join(" ").into_bytes();
                if self.members[i].passive {
                    let out = self.compose(i, Some(content));
                    self.queue(i, out)?;
                    return self.written_since(i);
                }
                let mut out = self.drive(i, Event::Send { content })?;
                out.extend(self.written_since(i)?);
                Ok(out)
            }
            ["invite", who, new] => self.invite(who, new),
            ["introduce", who, new] => self.introduce(who, new),
            ["land", who] => {
                let i = self.existing(who)?;
                self.land(i)?;
                Ok(Vec::new())
            }
            ["abandon", who] => {
                let i = self.existing(who)?;
                let control = |m: &Message| {
                    m.introduction.is_some() || !m.numbers.is_empty() || m.introduced_at.is_some()
                };
                if let Some(o) = self.members[i]
                    .unwritten
                    .iter()
                    .rev()
                    .find(|o| !control(&o.message))
                    .cloned()
                {
                    self.members[i].unwritten.retain(|x| x.token != o.token);
                    self.members[i]
                        .group
                        .as_mut()
                        .ok_or("not joined")?
                        .abandoned(o.token);
                    self.rec(
                        "abandoned",
                        i,
                        json!({"token": o.token as u64}),
                        Value::Null,
                    );
                }
                Ok(Vec::new())
            }
            ["remove", who, gone] => {
                let i = self.existing(who)?;
                let k = self.members[self.existing(gone)?].key();
                self.drive(i, Event::Remove { member: k })
            }
            [c @ ("read" | "scan"), who, owner] => {
                let i = self.existing(who)?;
                let o = self.existing(owner)?;
                if self.members[i].passive {
                    return self.read_passively(i, o);
                }
                let k = self.members[o].key();
                self.drive(
                    i,
                    if *c == "read" {
                        Event::Read { stream: k }
                    } else {
                        Event::Scan { stream: k }
                    },
                )
            }
            ["epoch", n @ ..] => {
                for _ in 0..count(n) {
                    self.replica.advance();
                }
                Ok(Vec::new())
            }
            ["backfill", who] => self.backfill(who),
            ["tick", n @ ..] => {
                let mut out = Vec::new();
                for _ in 0..count(n) {
                    self.replica.advance();
                    for name in self.joined_names() {
                        out.extend(self.backfill(&name)?);
                    }
                }
                Ok(out)
            }
            ["roster", who, owner] => {
                let known = self
                    .group_of(self.existing(who)?)?
                    .rosters
                    .known(&self.members[self.existing(owner)?].key());
                let Some(top) = known.iter().map(|e| e.index).max() else {
                    return Ok(vec!["unknown".into()]);
                };
                let names: Vec<String> = (0..=top)
                    .map(|n| {
                        self.name_of(
                            known
                                .iter()
                                .find(|e| e.index == n)
                                .and_then(|e| e.key.as_ref()),
                        )
                    })
                    .collect();
                Ok(vec![names.join(" ")])
            }
            ["acks", who, owner, n] => {
                let w = self.existing(who)?;
                let sender = &self.members[self.existing(owner)?];
                let at = &sender.chain[n.parse::<usize>().unwrap_or(0)];
                let Some(msg) = self.members[w]
                    .seen
                    .iter()
                    .find(|s| s.0 == (sender.key(), at.clone()))
                    .map(|s| s.1.clone())
                else {
                    return Ok(vec!["not read".into()]);
                };
                let g = self.group_of(w)?;
                let mut acks = msg.acks.clone();
                acks.sort_by_key(|a| a.member);
                let parts: Vec<String> = acks
                    .iter()
                    .map(|a| {
                        format!(
                            "{}={}",
                            self.name_of(g.resolve(&sender.key(), a.member).as_ref()),
                            self.where_idx64(a.idx64)
                        )
                    })
                    .collect();
                Ok(vec![if parts.is_empty() {
                    "none".into()
                } else {
                    parts.join(" ")
                }])
            }
            ["acked", who] => {
                let i = self.existing(who)?;
                let g = self.group_of(i)?;
                let mut acked: Vec<(&Key, &u64)> = g.ledger.acked_by.iter().collect();
                acked.sort_by(|a, b| a.0.cmp(b.0));
                let mut parts = Vec::new();
                for (k, idx64) in acked {
                    if let Some(r) = g.sent.records.get(idx64) {
                        parts.push(format!(
                            "{}:{}",
                            self.name_of(Some(k)),
                            self.at_index(&self.members[i].key(), &r.index)?
                        ));
                    }
                }
                Ok(vec![if parts.is_empty() {
                    "none".into()
                } else {
                    parts.join(" ")
                }])
            }
            ["inbox", who] => {
                let m = &self.members[self.existing(who)?];
                let lines = m
                    .inbox
                    .iter()
                    .map(|(s, x, t)| Ok(format!("{} \"{t}\"", self.at_index(s, x)?)))
                    .collect::<R<Vec<_>>>()?;
                Ok(if lines.is_empty() {
                    vec!["empty".into()]
                } else {
                    lines
                })
            }
            ["peek", owner, n] => {
                let o = &self.members[self.existing(owner)?];
                let (f, _) = self.fetch(&o.chain[n.parse::<usize>().unwrap_or(0)].clone());
                Ok(vec![match &f {
                    Fetched::Data(m) => self.show_msg(m),
                    other => other.value().into(),
                }])
            }
            _ => Err(format!("unknown command {}", words.join(" "))),
        }
    }
}

fn words(cmd: &str) -> Vec<&str> {
    cmd.split(' ').filter(|w| !w.is_empty()).collect()
}

/// Run a scenario, returning it with every checked command's output replaced by what it printed
/// now. With `record`, every call on a member is recorded.
pub fn run(script: &str, record: Option<Recorder>) -> Result<String, String> {
    let mut w = World {
        replica: Replica::default(),
        members: Vec::new(),
        options: Vec::new(),
        record,
    };
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
        let printed = w.command(&words(cmd))?;
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

/// A scenario of `steps` random commands, each followed by what it printed, chosen from what the
/// world allows as it runs: for differential tests against katzenqt's simulator and Lean's model.
pub fn random_script(seed: u64, steps: usize, record: Option<Recorder>) -> Result<String, String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut w = World {
        replica: Replica::default(),
        members: Vec::new(),
        options: Vec::new(),
        record,
    };
    let mut out: Vec<String> = Vec::new();
    let mut emit = |w: &mut World, cmd: String| -> R<()> {
        let printed = w.command(&words(&cmd))?;
        out.push(cmd);
        out.push("----".into());
        out.extend(printed);
        out.push(String::new());
        Ok(())
    };
    if rng.gen_range(0..3) == 0 {
        emit(&mut w, "option passive on".into())?;
    }
    if rng.gen_range(0..3) == 0 {
        emit(&mut w, "option delay-writes on".into())?;
    }
    for o in ["window", "keep-sent", "keep-received"] {
        if rng.gen_range(0..4) == 0 {
            emit(&mut w, format!("option {o} {}", rng.gen_range(1..4)))?;
        }
    }
    if rng.gen_range(0..4) == 0 {
        emit(&mut w, "option discard-acked off".into())?;
    }
    if rng.gen_range(0..4) == 0 {
        emit(&mut w, format!("option recheck {}", rng.gen_range(1..5)))?;
    }
    let names = [
        "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
    ];
    let founders = rng.gen_range(1..4);
    emit(&mut w, format!("new-group {}", names[..founders].join(" ")))?;
    for _ in 0..steps {
        let joined = w.joined_names();
        let fresh: Vec<&str> = names
            .iter()
            .copied()
            .filter(|n| !joined.iter().any(|j| j == n))
            .collect();
        let actor = joined[rng.gen_range(0..joined.len())].clone();
        let other = joined[rng.gen_range(0..joined.len())].clone();
        let n = rng.gen_range(0..5);
        let r = rng.gen_range(0..100);
        let pick_fresh = |rng: &mut StdRng| fresh[rng.gen_range(0..fresh.len())];
        let cmd = match r {
            0..25 => format!("send {actor} m{}", rng.gen_range(0..1000)),
            25..30 if !fresh.is_empty() => format!("invite {actor} {}", pick_fresh(&mut rng)),
            30..37 if !fresh.is_empty() => format!("introduce {actor} {}", pick_fresh(&mut rng)),
            37..42 => format!("land {actor}"),
            42..44 => format!("abandon {actor}"),
            44..46 if actor != other => format!("remove {actor} {other}"),
            46..62 => format!("read {actor} {other}"),
            62..68 => format!("scan {actor} {other}"),
            68..71 => "epoch".into(),
            71..74 => "tick".into(),
            74..77 => format!("backfill {actor}"),
            77..82 => format!("roster {actor} {other}"),
            82..87 => format!("acks {actor} {other} {n}"),
            87..91 => format!("acked {actor}"),
            91..95 => format!("inbox {actor}"),
            _ => format!("peek {other} {n}"),
        };
        emit(&mut w, cmd)?;
    }
    Ok(out.join("\n") + "\n")
}
