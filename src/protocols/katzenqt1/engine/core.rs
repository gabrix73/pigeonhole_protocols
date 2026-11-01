use std::collections::{HashMap, HashSet};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use crate::protocols::katzenqt1::member::{
    Effect, Event, Group, Index, Key, Outgoing, Payload, ReadResult, Retention,
};
use crate::protocols::katzenqt1::wire as wire;
use crate::transport::Secret;
use wire::{Chunk, FileUpload, MAX_FILE};

use crate::protocols::katzenqt1::engine::io::{Action, FileWrite, Input, Outcome, StepResult};
use crate::protocols::katzenqt1::engine::notice::{Notice, NoticeKind, size_text};
use crate::protocols::katzenqt1::engine::state::*;

/// How many boxes of an upload are written at once.
pub const WINDOW: usize = 8;

/// How long to wait, in milliseconds, before reading a box that was not there, after `n` misses
/// before.
pub fn backoff(n: usize) -> u64 {
    60000u64.min(2000 << n.min(5))
}

/// How a voucher is handed to a member of the group.
pub fn voucher_code(voucher: &[u8]) -> String {
    STANDARD.encode(voucher)
}

/// A name without control characters.
pub fn sanitize(name: &str) -> String {
    let s: String = name
        .chars()
        .filter(|&c| !((c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32))))
        .collect();
    if s.is_empty() { "unnamed".into() } else { s }
}

type StreamKey = (ChatId, Key);
type JobKey = (ChatId, usize);

/// What is under way on the network; not saved, since a restart begins it again.
#[derive(Default)]
struct Flight {
    writing: HashSet<ChatId>,
    /// The streams with a read out or a wake pending.
    reading: HashSet<StreamKey>,
    /// The reads of each stream that found nothing, in a row.
    misses: HashMap<StreamKey, usize>,
    /// The uploads with a substream being made or indexes being derived.
    uploading: HashSet<JobKey>,
    /// The index of each box of an upload from the first not yet written on, as far as derived.
    ahead: HashMap<JobKey, Vec<Index>>,
    /// The boxes of each upload being written.
    chunks_out: HashMap<JobKey, HashSet<usize>>,
    /// The boxes of an upload written after one not yet written, with the index after each.
    landed: HashMap<JobKey, Vec<(usize, Index)>>,
    /// The uploads whose message is being read back from its file.
    loading: HashSet<JobKey>,
    /// Each upload's message, once made or read back.
    blobs: HashMap<JobKey, Vec<u8>>,
    /// What each download has read: the index of its next box, and the boxes so far.
    fetched: HashMap<StreamKey, (Index, Vec<Vec<u8>>)>,
    /// The bytes of a file a download just brought, while the member reads the message without
    /// them.
    arriving: HashMap<(Key, Index), Vec<u8>>,
}

impl Flight {
    fn forget(&mut self, chat: &str) {
        self.writing.remove(chat);
        self.reading.retain(|k| k.0 != chat);
        self.misses.retain(|k, _| k.0 != chat);
        self.fetched.retain(|k, _| k.0 != chat);
        self.uploading.retain(|k| k.0 != chat);
        self.loading.retain(|k| k.0 != chat);
        self.ahead.retain(|k, _| k.0 != chat);
        self.chunks_out.retain(|k, _| k.0 != chat);
        self.landed.retain(|k, _| k.0 != chat);
        self.blobs.retain(|k, _| k.0 != chat);
    }
}

pub struct Engine {
    pub state: State,
    pub max_plaintext: usize,
    /// The replicas' epoch as last reported; a group made now starts there, so that what it
    /// writes before the next report is not taken for hundreds of epochs old when the report
    /// comes.
    pub epoch: usize,
    flight: Flight,
}

/// What a step is working with, apart from the conversation it works on.
struct Cx<'a> {
    out: &'a mut StepResult,
    flight: &'a mut Flight,
    now: i64,
    max: usize,
    me: &'a str,
}

/// The box an outgoing message is written as. A message the member makes itself carries the
/// membership hash it stamped when composed, an Introduction the hash before the member it
/// introduces, so a rewrite writes the same box; content carries the hash it was composed with.
fn box_of(o: &Outgoing) -> Option<Vec<u8>> {
    wire::box_of(&o.message)
}

fn file_text(a: &Attachment) -> String {
    format!("[file {}, {}]", a.name, size_text(a.size))
}

fn attachment_file(c: &Chat, id: usize, now: i64, name: &str) -> String {
    format!("attachments/{}/{now}-{id}-{name}", slug(&c.name))
}

/// Holds the voucher code we minted to join `group`, for the user to copy whole.
fn voucher_file(group: &str) -> String {
    format!("voucher-{}.txt", slug(group))
}

/// What a box holds, as a member reads it.
fn message_of(plaintext: &[u8]) -> Option<wire::Message> {
    match wire::unframe(plaintext) {
        Chunk::Final(cbor) => wire::message_from_cbor(&cbor),
        _ => None,
    }
}

/// A member as a notice names them: me, or the name they chose after ~.
fn label(c: &Chat, key: &Key) -> String {
    if c.group.as_ref().is_some_and(|g| &g.me() == key) {
        return "me".into();
    }
    format!("~{}", c.names.get(key).map_or("?", String::as_str))
}

fn read_result(o: &Outcome) -> (ReadResult, Option<Index>) {
    match o {
        Outcome::NotFound => (ReadResult::NotFound, None),
        Outcome::Tombstone { next } => (ReadResult::Tombstone, Some(next.clone())),
        Outcome::Data { plaintext, next } => {
            (ReadResult::Data(message_of(plaintext)), Some(next.clone()))
        }
    }
}

impl Cx<'_> {
    fn emit(&mut self, a: Action) {
        self.out.actions.push(a);
    }

    fn keep(&mut self, file: String, bytes: Vec<u8>) {
        self.out.files.push(FileWrite { file, bytes });
    }

    fn dirty(&mut self, c: &Chat) {
        self.out.changes.chats.insert(c.id.clone());
    }

    fn line_changed(&mut self, c: &Chat, id: usize) {
        self.out
            .changes
            .lines
            .entry(c.id.clone())
            .or_default()
            .insert(id);
    }

    fn line_dropped(&mut self, c: &Chat, id: usize) {
        if let Some(m) = self.out.changes.lines.get_mut(&c.id) {
            m.remove(&id);
        }
        self.out
            .changes
            .dropped
            .entry(c.id.clone())
            .or_default()
            .insert(id);
    }

    /// Add a line, returning its id.
    fn say(&mut self, c: &mut Chat, mut l: Line) -> usize {
        l.id = c.fresh();
        l.time = self.now;
        let id = l.id;
        c.log.push(l);
        self.dirty(c);
        self.line_changed(c, id);
        if c.log.len() > MAX_LOG {
            let n = c.log.len() - MAX_LOG;
            for l in c.log.drain(..n).collect::<Vec<_>>() {
                if let Some(a) = l.attachment {
                    self.emit(Action::Delete { file: a.file });
                }
                self.line_dropped(c, l.id);
            }
        }
        id
    }

    fn notice(&mut self, c: &mut Chat, kind: NoticeKind, args: &[&str]) {
        let notice = Notice {
            kind,
            args: args.iter().map(|s| s.to_string()).collect(),
        };
        self.say(
            c,
            Line {
                notice: Some(notice),
                ..Line::default()
            },
        );
    }

    /// Queue `outgoing`, each written after the one before; `line` shows the one carrying
    /// `content`, into which the bytes of a file it carries, `payload`, are put. A message too
    /// long for a box goes to a substream, written before the I box naming it.
    fn enqueue(
        &mut self,
        c: &mut Chat,
        outgoing: Vec<Outgoing>,
        content: Option<&[u8]>,
        line: Option<usize>,
        payload: Option<&[u8]>,
    ) {
        let max = self.max;
        for o in outgoing {
            if c.group.is_none() {
                continue;
            }
            let mine = content.is_some() && o.message.content.as_deref() == content;
            let mut b = box_of(&o);
            if let (Some(bx), Some(p), true) = (&b, payload, mine) {
                b = wire::put_payload(&bx[1..], p).map(|full| wire::frame(&full));
            }
            if let Some(bx) = b {
                let l = if mine { line } else { None };
                if bx.len() <= max {
                    let id = c.fresh();
                    c.jobs.push(Job {
                        id,
                        token: Some(o.token),
                        index: None,
                        box_: bx,
                        line: l,
                        upload: None,
                    });
                    self.dirty(c);
                    continue;
                }
                let blob = bx[1..].to_vec();
                if blob.len() <= MAX_FILE + max {
                    let id = c.fresh();
                    let file = format!("spool/{}-{}-{id}.cbor", slug(&c.name), self.now);
                    self.keep(file.clone(), blob.clone());
                    let total = wire::chunk_count(blob.len(), max);
                    self.flight.blobs.insert((c.id.clone(), id), blob);
                    let u = Upload {
                        file,
                        box_size: max,
                        total,
                        write_cap: Secret::default(),
                        sent: 0,
                        next: Vec::new(),
                    };
                    c.jobs.push(Job {
                        id,
                        token: Some(o.token),
                        index: None,
                        box_: Vec::new(),
                        line: l,
                        upload: Some(u),
                    });
                    self.dirty(c);
                    continue;
                }
            }
            if let Some(g) = &mut c.group {
                g.abandoned(o.token);
            }
            self.notice(
                c,
                if mine {
                    NoticeKind::TooLong
                } else {
                    NoticeKind::NotWritten
                },
                &[],
            );
        }
    }

    /// Queue a box the member asks to write again, or to tombstone.
    fn rewrite(&mut self, c: &mut Chat, index: Index, b: Vec<u8>) {
        let id = c.fresh();
        c.jobs.push(Job {
            id,
            token: None,
            index: Some(index),
            box_: b,
            line: None,
            upload: None,
        });
        self.dirty(c);
    }

    /// A line for `content` from `sender`, and the file it carries kept.
    fn deliver(&mut self, c: &mut Chat, sender: Key, index: Index, content: &[u8]) {
        let f = wire::Gcm::from_bytes(content).and_then(|g| wire::file_of(&g));
        let Some(mut f) = f else {
            self.say(
                c,
                Line {
                    sender,
                    index,
                    text: wire::text_of(content),
                    ..Line::default()
                },
            );
            return;
        };
        if let Some(p) = self.flight.arriving.get(&(sender.clone(), index.clone())) {
            f.payload = p.clone();
        }
        let name = wire::safe_name(&f.basename);
        let a = Attachment {
            name: name.clone(),
            filetype: f.filetype,
            size: f.payload.len(),
            file: attachment_file(c, c.next_id, self.now, &name),
        };
        if f.payload.len() > MAX_FILE {
            let text = format!("[file {name}, {}, too large to keep]", size_text(a.size));
            self.say(
                c,
                Line {
                    sender,
                    index,
                    text,
                    ..Line::default()
                },
            );
            return;
        }
        self.keep(a.file.clone(), f.payload);
        self.say(
            c,
            Line {
                sender,
                index,
                text: file_text(&a),
                attachment: Some(a),
                ..Line::default()
            },
        );
    }

    /// Keep the lines `keep` holds of, and delete the files the others carry.
    fn drop_lines(&mut self, c: &mut Chat, keep: impl Fn(&Line) -> bool) {
        let before = c.log.len();
        let log = std::mem::take(&mut c.log);
        for l in log {
            if keep(&l) {
                c.log.push(l);
                continue;
            }
            if let Some(a) = &l.attachment {
                self.emit(Action::Delete {
                    file: a.file.clone(),
                });
            }
            self.line_dropped(c, l.id);
        }
        if c.log.len() != before {
            self.dirty(c);
        }
    }

    /// Do what the member asks.
    fn effects(&mut self, c: &mut Chat, es: Vec<Effect>) {
        for e in es {
            match e {
                Effect::WriteBox { index, payload } => {
                    let b = match payload {
                        Payload::Bytes(b) => Some(b),
                        Payload::Message(m) => wire::box_of(&m),
                    };
                    if let Some(b) = b {
                        self.rewrite(c, index, b);
                    }
                }
                Effect::WriteTombstone { index } => self.rewrite(c, index, Vec::new()),
                Effect::ReadBox {
                    stream,
                    read_cap,
                    index,
                    ..
                } => self.emit(Action::ScanRead {
                    chat: c.id.clone(),
                    stream,
                    read_cap,
                    index,
                }),
                Effect::DeriveIndexes {
                    stream,
                    start,
                    count,
                } => self.emit(Action::Derive {
                    chat: c.id.clone(),
                    stream,
                    start,
                    count,
                }),
                Effect::Walk {
                    stream,
                    start,
                    targets,
                    keep,
                } => self.emit(Action::Walk {
                    chat: c.id.clone(),
                    stream,
                    start,
                    targets,
                    keep,
                }),
                Effect::Deliver {
                    sender,
                    index,
                    content,
                } => self.deliver(c, sender, index, &content),
                Effect::Expire { sender, index } => {
                    self.drop_lines(c, |l| !(l.sender == sender && l.index == index))
                }
                Effect::SendJoinReply { .. } => {}
            }
        }
    }

    /// Notes for the conversation about a box: who an Introduction introduced, or a message this
    /// client cannot show.
    fn remark(&mut self, c: &mut Chat, stream: &Key, plaintext: &[u8]) {
        match wire::unframe(plaintext) {
            Chunk::Final(cbor) => {
                let Some(i) = wire::message_from_cbor(&cbor).and_then(|m| m.introduction) else {
                    return;
                };
                let k = wire::key_of(&i.read_cap).to_vec();
                if !c.names.contains_key(&k) {
                    c.names.insert(k.clone(), i.name.clone());
                    self.dirty(c);
                }
                if c.group.as_ref().is_some_and(|g| g.me() == k) {
                    return;
                }
                let l = label(c, stream);
                self.notice(c, NoticeKind::MemberAdded, &[&l, &i.name]);
            }
            Chunk::Continued(_) => {
                let l = label(c, stream);
                self.notice(c, NoticeKind::Unreadable, &[&l]);
            }
            _ => {}
        }
    }

    fn start_reads(&mut self, c: &mut Chat) {
        let Some(g) = &c.group else { return };
        let readers: Vec<(Key, Secret, Index)> = g
            .readers
            .values()
            .map(|r| (r.stream.clone(), r.read_cap.clone(), r.next.clone()))
            .collect();
        for (stream, read_cap, next) in readers {
            let k = (c.id.clone(), stream.clone());
            if self.flight.reading.contains(&k) || c.downloads.iter().any(|d| d.stream == stream) {
                continue;
            }
            let at = match c.cursors.get(&stream) {
                Some(at) => at.clone(),
                None => {
                    c.cursors.insert(stream.clone(), next.clone());
                    self.dirty(c);
                    next
                }
            };
            self.flight.reading.insert(k);
            self.emit(Action::Read {
                chat: c.id.clone(),
                stream,
                read_cap,
                index: at,
            });
        }
    }

    fn start_write(&mut self, c: &mut Chat) {
        if self.flight.writing.contains(&c.id) || c.write_cap.is_empty() || c.jobs.is_empty() {
            return;
        }
        // While a reply is sealing, nothing takes the next index: the reply names it as where
        // the new member starts reading, and the Introduction, queued first once the reply is
        // sealed, must be the box there.
        if c.inducting.as_ref().is_some_and(|i| i.sealing) {
            return;
        }
        if c.jobs[0].upload.as_ref().is_some_and(|u| u.sent < u.total) {
            return;
        }
        if c.jobs[0].index.is_none() {
            c.jobs[0].index = Some(c.next_write.clone());
            self.dirty(c);
        }
        self.flight.writing.insert(c.id.clone());
        let j = &c.jobs[0];
        self.emit(Action::Write {
            chat: c.id.clone(),
            job: j.id,
            write_cap: c.write_cap.clone(),
            index: j.index.clone().unwrap(),
            box_: j.box_.clone(),
        });
    }

    /// Seal the new member's reply, once everything owed is written.
    fn start_induction(&mut self, c: &mut Chat) {
        let (Some(i), Some(g)) = (&c.inducting, &c.group) else {
            return;
        };
        if i.payload.is_none()
            || i.sealing
            || i.sealed.is_some()
            || c.jobs.iter().any(|j| j.token.is_some())
        {
            return;
        }
        let me = g.me();
        let who = wire::ReplyWho::from_join_reply(&g.reply(&c.next_write), |key| {
            if key == me.as_slice() {
                Some(self.me.to_string())
            } else {
                c.names.get(key).cloned()
            }
        });
        self.emit(Action::Seal {
            chat: c.id.clone(),
            voucher: i.voucher.clone(),
            payload: i.payload.clone().unwrap(),
            who_reply: who.to_bytes().into(),
        });
        c.inducting.as_mut().unwrap().sealing = true;
        self.dirty(c);
    }

    /// Write the next boxes of each upload, making its substream, reading its message back and
    /// deriving their indexes first.
    fn start_uploads(&mut self, c: &mut Chat) {
        for j in &c.jobs {
            let Some(u) = &j.upload else { continue };
            let key = (c.id.clone(), j.id);
            if u.sent >= u.total || self.flight.uploading.contains(&key) {
                continue;
            }
            if u.write_cap.is_empty() {
                self.flight.uploading.insert(key);
                self.emit(Action::Substream {
                    chat: c.id.clone(),
                    job: j.id,
                });
                continue;
            }
            let Some(blob) = self.flight.blobs.get(&key).cloned() else {
                if self.flight.loading.insert(key) {
                    self.emit(Action::Load {
                        chat: c.id.clone(),
                        job: j.id,
                        file: u.file.clone(),
                    });
                }
                continue;
            };
            let want = WINDOW.min(u.total - u.sent);
            let ahead = self.flight.ahead.get(&key).cloned().unwrap_or_default();
            if ahead.len() < want {
                self.flight.uploading.insert(key);
                self.emit(Action::ChunkIndexes {
                    chat: c.id.clone(),
                    job: j.id,
                    start: u.next.clone(),
                    count: (2 * WINDOW).min(u.total - u.sent) - 1,
                });
                continue;
            }
            for (i, index) in ahead[..want].iter().enumerate() {
                let n = u.sent + i;
                if self
                    .flight
                    .chunks_out
                    .get(&key)
                    .is_some_and(|s| s.contains(&n))
                    || self
                        .flight
                        .landed
                        .get(&key)
                        .is_some_and(|l| l.iter().any(|x| x.0 == n))
                {
                    continue;
                }
                self.flight
                    .chunks_out
                    .entry(key.clone())
                    .or_default()
                    .insert(n);
                self.emit(Action::WriteChunk {
                    chat: c.id.clone(),
                    job: j.id,
                    n,
                    write_cap: u.write_cap.clone(),
                    index: index.clone(),
                    box_: wire::substream_box(&blob, u.box_size, n),
                });
            }
        }
    }

    /// Read the next box of each download.
    fn start_downloads(&mut self, c: &mut Chat) {
        for d in &c.downloads {
            let k = (c.id.clone(), d.stream.clone());
            if self.flight.reading.contains(&k) {
                continue;
            }
            let at = self
                .flight
                .fetched
                .get(&k)
                .map_or_else(|| wire::start_of(&d.read_cap).to_vec(), |f| f.0.clone());
            self.flight.reading.insert(k);
            self.emit(Action::ReadChunk {
                chat: c.id.clone(),
                stream: d.stream.clone(),
                read_cap: d.read_cap.clone(),
                index: at,
            });
        }
    }

    fn stop_reading(&mut self, c: &Chat, stream: &Key) {
        self.flight.reading.remove(&(c.id.clone(), stream.clone()));
    }

    fn missed(&mut self, c: &Chat, stream: &Key) -> usize {
        let n = self
            .flight
            .misses
            .entry((c.id.clone(), stream.clone()))
            .or_default();
        *n += 1;
        *n - 1
    }

    fn hit(&mut self, c: &Chat, stream: &Key) {
        self.flight.misses.remove(&(c.id.clone(), stream.clone()));
    }

    /// Move a cursor that a scan has carried past it.
    fn follow_reader(&mut self, c: &mut Chat, stream: &Key) {
        let Some(r) = c.group.as_ref().and_then(|g| g.readers.get(stream)) else {
            return;
        };
        let Some(at) = c.cursors.get(stream) else {
            return;
        };
        if wire::counter(at) < wire::counter(&r.next) {
            let n = r.next.clone();
            c.cursors.insert(stream.clone(), n);
            self.dirty(c);
        }
    }

    /// A download is over: tell the member what came of it, in its place in the stream.
    fn finish(&mut self, c: &mut Chat, d: Download, blob: Option<Vec<u8>>) {
        self.flight
            .fetched
            .remove(&(c.id.clone(), d.stream.clone()));
        c.downloads.retain(|x| x.stream != d.stream);
        self.dirty(c);
        let without = blob.map(|b| match wire::take_payload(&b) {
            Some((w, p)) => {
                self.flight.arriving = HashMap::from([((d.stream.clone(), d.index.clone()), p)]);
                w
            }
            None => b,
        });
        let m = without.as_deref().and_then(wire::message_from_cbor);
        match (&without, &m) {
            (Some(w), Some(_)) => self.remark(c, &d.stream, &wire::frame(w)),
            _ => {
                let l = label(c, &d.stream);
                self.notice(c, NoticeKind::NotFetched, &[&l]);
            }
        }
        if let Some(g) = &mut c.group {
            let es = g.observe(&d.stream, &d.index, m, &d.next);
            self.effects(c, es);
        }
        self.flight.arriving.clear();
    }

    fn cancel_held(&mut self, c: &mut Chat) {
        if let Some(g) = &mut c.group
            && g.ledger.induction == crate::protocols::katzenqt1::member::Induction::Inducting
        {
            g.cancel_induction();
        }
    }

    fn wrote_chunk(&mut self, c: &mut Chat, job: usize, n: usize, next: Index) {
        let key = (c.id.clone(), job);
        if let Some(s) = self.flight.chunks_out.get_mut(&key) {
            s.remove(&n);
        }
        let Some(j) = c.job_mut(job) else { return };
        let Some(u) = &mut j.upload else { return };
        if n < u.sent {
            return;
        }
        let landed = self.flight.landed.entry(key.clone()).or_default();
        landed.push((n, next));
        // Count the boxes written in a row from the first not yet counted.
        while let Some(i) = landed.iter().position(|l| l.0 == u.sent) {
            let (_, after) = landed.remove(i);
            if let Some(a) = self.flight.ahead.get_mut(&key)
                && !a.is_empty()
            {
                a.remove(0);
            }
            u.sent += 1;
            u.next = after;
        }
        let done = u.sent >= u.total;
        let (file, total, cap) = (u.file.clone(), u.total, u.write_cap.clone());
        if done {
            j.box_ = wire::indirection(total, &cap[wire::KEY_SIZE..]);
        }
        self.dirty(c);
        if done {
            self.flight.blobs.remove(&key);
            self.flight.ahead.remove(&key);
            self.flight.landed.remove(&key);
            self.emit(Action::Delete { file });
        }
    }

    fn read_chunk(&mut self, c: &mut Chat, stream: Key, index: Index, outcome: Outcome) {
        self.stop_reading(c, &stream);
        let Some(d) = c.downloads.iter().find(|d| d.stream == stream).cloned() else {
            return;
        };
        let k = (c.id.clone(), stream.clone());
        let (at, parts) = self
            .flight
            .fetched
            .get(&k)
            .cloned()
            .unwrap_or_else(|| (wire::start_of(&d.read_cap).to_vec(), Vec::new()));
        if at != index {
            return;
        }
        let max = self.max;
        match outcome {
            Outcome::NotFound => {
                self.flight.reading.insert(k);
                let ms = backoff(self.missed(c, &stream));
                self.emit(Action::Wake {
                    chat: c.id.clone(),
                    stream,
                    ms,
                });
            }
            Outcome::Tombstone { .. } => self.finish(c, d, None),
            Outcome::Data { plaintext, next } => {
                self.hit(c, &stream);
                let tag = plaintext.first().copied();
                let mut parts = parts;
                parts.push(plaintext);
                match tag {
                    Some(b'F') => {
                        let blob = wire::assemble(&parts);
                        self.finish(c, d, blob);
                    }
                    Some(b'C')
                        if parts.len() < wire::max_chunks(max)
                            && d.total.is_none_or(|t| parts.len() < t) =>
                    {
                        self.flight.fetched.insert(k, (next, parts));
                    }
                    _ => self.finish(c, d, None),
                }
            }
        }
    }

    fn read(&mut self, c: &mut Chat, stream: Key, index: Index, outcome: Outcome) {
        self.stop_reading(c, &stream);
        if c.cursors.get(&stream) != Some(&index) {
            return;
        }
        let (plaintext, next) = match outcome {
            Outcome::NotFound => {
                self.flight.reading.insert((c.id.clone(), stream.clone()));
                let ms = backoff(self.missed(c, &stream));
                self.emit(Action::Wake {
                    chat: c.id.clone(),
                    stream,
                    ms,
                });
                return;
            }
            Outcome::Tombstone { next } => {
                self.hit(c, &stream);
                c.cursors.insert(stream, next);
                self.dirty(c);
                return;
            }
            Outcome::Data { plaintext, next } => (plaintext, next),
        };
        self.hit(c, &stream);
        self.dirty(c);
        if let Chunk::Indirection { total, read_cap } = wire::unframe(&plaintext) {
            let t = total.map(|t| t as usize);
            if t.unwrap_or(0) <= wire::max_chunks(self.max) {
                c.downloads.push(Download {
                    stream: stream.clone(),
                    index,
                    next: next.clone(),
                    read_cap: read_cap.into(),
                    total: t,
                });
                c.cursors.insert(stream, next);
                return;
            }
            let l = label(c, &stream);
            self.notice(c, NoticeKind::FileTooLargeToFetch, &[&l]);
            if let Some(g) = &mut c.group {
                let es = g.observe(&stream, &index, None, &next);
                self.effects(c, es);
            }
            c.cursors.insert(stream, next);
            return;
        }
        self.remark(c, &stream, &plaintext);
        if let Some(g) = &mut c.group {
            let es = g.observe(&stream, &index, message_of(&plaintext), &next);
            self.effects(c, es);
        }
        c.cursors.insert(stream, next);
    }
}

/// The group a reply to our voucher puts us in.
fn joined_from(o: &crate::transport::Opened) -> Option<(Group, wire::ReplyWho)> {
    let who = wire::ReplyWho::from_bytes(&o.who_reply)?;
    if o.mutated_write_cap.len() < wire::KEY_SIZE {
        return None;
    }
    let reply = who.to_join_reply().or_else(|| who.without_rosters())?;
    let own = &o.mutated_write_cap[wire::KEY_SIZE..];
    if reply
        .members
        .iter()
        .flatten()
        .any(|m| wire::key_of(&m.read_cap) == wire::key_of(own))
    {
        return None;
    }
    Some((Group::joined(own, &reply, Retention::default(), 256), who))
}

fn chat_of(i: &Input) -> Option<&ChatId> {
    use Input::*;
    match i {
        Create { .. } | Join { .. } | Epoch { .. } => None,
        Induct { chat, .. }
        | Send { chat, .. }
        | SendFile { chat, .. }
        | Scan { chat }
        | Leave { chat }
        | RemoveMember { chat, .. }
        | Clear { chat }
        | Rename { chat, .. }
        | Created { chat, .. }
        | Wrote { chat, .. }
        | Refused { chat, .. }
        | Read { chat, .. }
        | Wake { chat, .. }
        | ScanRead { chat, .. }
        | Walked { chat, .. }
        | Derived { chat, .. }
        | Minted { chat, .. }
        | Opened { chat, .. }
        | JoinerPayload { chat, .. }
        | SealedReply { chat, .. }
        | Published { chat }
        | Failed { chat, .. }
        | Loaded { chat, .. }
        | Substream { chat, .. }
        | WroteChunk { chat, .. }
        | ChunkIndexes { chat, .. }
        | ReadChunk { chat, .. } => Some(chat),
    }
}

impl Engine {
    pub fn new(state: State, max_plaintext: usize) -> Engine {
        Engine {
            state,
            max_plaintext,
            epoch: 0,
            flight: Flight::default(),
        }
    }

    fn pump(&mut self, out: &mut StepResult, now: i64) {
        let me = self.state.me.clone();
        let mut cx = Cx {
            out,
            flight: &mut self.flight,
            now,
            max: self.max_plaintext,
            me: &me,
        };
        for c in &mut self.state.chats {
            cx.start_write(c);
            cx.start_reads(c);
            cx.start_induction(c);
            cx.start_uploads(c);
            cx.start_downloads(c);
        }
    }

    /// Take one input at time `now`, in milliseconds since the Unix epoch.
    pub fn step(&mut self, now: i64, input: Input) -> StepResult {
        let mut out = StepResult::default();
        self.handle(&mut out, now, input);
        self.pump(&mut out, now);
        out
    }

    /// Begin again after a restart: whatever was under way is started afresh.
    pub fn resume(&mut self, now: i64) -> StepResult {
        let mut out = StepResult::default();
        for c in &mut self.state.chats {
            let id = c.id.clone();
            if c.write_cap.is_empty() {
                out.actions.push(Action::Create {
                    chat: id,
                    joining: c.joining.is_some(),
                });
                continue;
            }
            if let Some(j) = &c.joining {
                out.actions.push(if j.code.is_empty() {
                    Action::Mint {
                        chat: id.clone(),
                        write_cap: c.write_cap.clone(),
                        name: self.state.me.clone(),
                    }
                } else {
                    Action::AwaitReply {
                        chat: id.clone(),
                        secret_key: j.secret_key.clone(),
                        voucher_read_cap: j.voucher_read_cap.clone(),
                        box1: j.box1.clone(),
                        write_cap: c.write_cap.clone(),
                    }
                });
            }
            if let Some(i) = &mut c.inducting {
                if i.payload.is_none() {
                    out.actions.push(Action::ReadVoucher {
                        chat: id,
                        voucher: i.voucher.clone(),
                    });
                } else if let Some(s) = &i.sealed {
                    out.actions.push(Action::Publish {
                        chat: id,
                        voucher_write_cap: i.voucher_write_cap.clone(),
                        box1: i.box1.clone(),
                        reply: s.reply.clone(),
                    });
                } else if i.sealing {
                    // The sealed reply was never kept, so it was never published: seal it again.
                    i.sealing = false;
                    out.changes.chats.insert(id);
                }
            }
        }
        self.pump(&mut out, now);
        out
    }

    fn handle(&mut self, out: &mut StepResult, now: i64, input: Input) {
        let me = self.state.me.clone();
        // Commands that make or unmake conversations, or look at more than one.
        match &input {
            Input::Create { chat, name } | Input::Join { chat, name } => {
                let joining = matches!(input, Input::Join { .. });
                let mut cx = Cx {
                    out,
                    flight: &mut self.flight,
                    now,
                    max: self.max_plaintext,
                    me: &me,
                };
                if let Some(c) = self.state.chats.iter_mut().find(|c| &c.name == name) {
                    let kind = if joining {
                        NoticeKind::NameTakenJoining
                    } else {
                        NoticeKind::NameTaken
                    };
                    cx.notice(c, kind, &[name]);
                    return;
                }
                let c = Chat {
                    id: chat.clone(),
                    name: name.clone(),
                    joining: joining.then(Joining::default),
                    ..Chat::default()
                };
                cx.dirty(&c);
                cx.emit(Action::Create {
                    chat: chat.clone(),
                    joining,
                });
                self.state.chats.push(c);
                return;
            }
            Input::Leave { chat } => {
                let Some(i) = self.state.chats.iter().position(|c| &c.id == chat) else {
                    return;
                };
                let c = self.state.chats.remove(i);
                for f in c.files() {
                    out.actions.push(Action::Delete { file: f });
                }
                self.flight.forget(chat);
                out.changes.chats.remove(chat);
                out.changes.lines.remove(chat);
                out.changes.dropped.remove(chat);
                out.changes.removed.insert(chat.clone());
                return;
            }
            Input::Rename { chat, to } => {
                let taken = self
                    .state
                    .chats
                    .iter()
                    .any(|c| &c.name == to && &c.id != chat);
                let mut cx = Cx {
                    out,
                    flight: &mut self.flight,
                    now,
                    max: self.max_plaintext,
                    me: &me,
                };
                let Some(c) = self.state.chats.iter_mut().find(|c| &c.id == chat) else {
                    return;
                };
                if to.is_empty() || to == &c.name {
                    return;
                }
                cx.dirty(c);
                if taken {
                    cx.notice(c, NoticeKind::NameTaken, &[to]);
                    return;
                }
                let old = std::mem::replace(&mut c.name, to.clone());
                cx.notice(c, NoticeKind::Renamed, &[&old]);
                return;
            }
            Input::Epoch { n } => {
                self.epoch = self.epoch.max(*n);
                let mut cx = Cx {
                    out,
                    flight: &mut self.flight,
                    now,
                    max: self.max_plaintext,
                    me: &me,
                };
                for c in &mut self.state.chats {
                    let Some(g) = &mut c.group else { continue };
                    if g.epoch >= *n {
                        continue;
                    }
                    let es = g.handle(Event::EpochChanged { epoch: *n });
                    cx.dirty(c);
                    cx.effects(c, es);
                }
                return;
            }
            _ => {}
        }
        let Some(id) = chat_of(&input).cloned() else {
            return;
        };
        let epoch = self.epoch;
        // Inputs that only tell what is under way.
        match &input {
            Input::Loaded { job, .. } => {
                self.flight.loading.remove(&(id.clone(), *job));
            }
            Input::Substream { job, .. } | Input::ChunkIndexes { job, .. } => {
                self.flight.uploading.remove(&(id.clone(), *job));
            }
            Input::Wrote { .. } => {
                self.flight.writing.remove(&id);
            }
            Input::Wake { stream, .. } => {
                self.flight.reading.remove(&(id.clone(), stream.clone()));
                return;
            }
            _ => {}
        }
        let mut cx = Cx {
            out,
            flight: &mut self.flight,
            now,
            max: self.max_plaintext,
            me: &me,
        };
        let Some(c) = self.state.chats.iter_mut().find(|c| c.id == id) else {
            return;
        };
        let quiet = matches!(
            input,
            Input::Read { .. }
                | Input::ReadChunk { .. }
                | Input::ChunkIndexes { .. }
                | Input::WroteChunk { .. }
        );
        if !quiet {
            cx.dirty(c);
        }
        match input {
            Input::Created {
                joining, keypair, ..
            } => {
                c.write_cap = keypair.write_cap;
                c.next_write = keypair.first;
                if joining {
                    cx.emit(Action::Mint {
                        chat: id,
                        write_cap: c.write_cap.clone(),
                        name: me.clone(),
                    });
                    cx.notice(c, NoticeKind::Minting, &[]);
                    return;
                }
                let mut g = Group::found(
                    &keypair.read_cap,
                    &[&keypair.read_cap],
                    Retention::default(),
                    256,
                );
                let es = g.handle(Event::EpochChanged { epoch });
                c.group = Some(g);
                cx.effects(c, es);
                cx.notice(c, NoticeKind::NewGroup, &[]);
            }
            Input::Minted { minted, box1, .. } => {
                let code = voucher_code(&minted.voucher);
                cx.emit(Action::AwaitReply {
                    chat: id,
                    secret_key: minted.secret_key.clone(),
                    voucher_read_cap: minted.read_cap.clone(),
                    box1: box1.clone(),
                    write_cap: c.write_cap.clone(),
                });
                c.joining = Some(Joining {
                    code: code.clone(),
                    secret_key: minted.secret_key,
                    voucher_read_cap: minted.read_cap,
                    box1,
                });
                let file = voucher_file(&c.name);
                cx.keep(file.clone(), format!("{code}\n").into_bytes());
                let name = c.name.clone();
                cx.notice(c, NoticeKind::VoucherMinted, &[&code, &name, &file]);
            }
            Input::Opened { opened, .. } => {
                if c.group.is_some() || c.joining.as_ref().is_none_or(|j| j.code.is_empty()) {
                    return;
                }
                let Some((g, who)) = joined_from(&opened) else {
                    c.joining = None;
                    cx.notice(c, NoticeKind::ReplyUnreadable, &[]);
                    return;
                };
                for p in who.please_adds.iter().flatten() {
                    c.names
                        .insert(wire::key_of(&p.read_cap).to_vec(), sanitize(&p.name));
                }
                let wc = opened.mutated_write_cap;
                c.next_write = wc[wc.len() - wire::INDEX_SIZE..].to_vec();
                c.write_cap = wc;
                let mut g = g;
                let es = g.handle(Event::EpochChanged { epoch });
                c.group = Some(g);
                c.joining = None;
                c.cursors.clear();
                cx.effects(c, es);
                cx.notice(c, NoticeKind::Joined, &[]);
            }
            Input::Induct { code, .. } => {
                let voucher = STANDARD.decode(&code);
                if c.group.is_none() {
                    cx.notice(c, NoticeKind::NotJoinedYet, &[]);
                } else if c.inducting.as_ref().is_some_and(|i| i.payload.is_some()) {
                    cx.notice(c, NoticeKind::AlreadyAdding, &[]);
                } else if let Ok(voucher) = voucher.map(Secret::from) {
                    c.inducting = Some(Inducting {
                        voucher: voucher.clone(),
                        ..Inducting::default()
                    });
                    cx.emit(Action::ReadVoucher { chat: id, voucher });
                    cx.notice(c, NoticeKind::ReadingVoucher, &[]);
                } else {
                    cx.notice(c, NoticeKind::NotAVoucher, &[]);
                }
            }
            Input::JoinerPayload {
                voucher,
                voucher_write_cap,
                payload,
                box1,
                ..
            } => {
                if c.inducting
                    .as_ref()
                    .is_none_or(|i| i.payload.is_some() || i.voucher != voucher)
                {
                    return;
                }
                if let Some(g) = &mut c.group {
                    let out = g.begin_induction();
                    cx.enqueue(c, out, None, None, None);
                }
                c.inducting = Some(Inducting {
                    voucher,
                    payload: Some(payload),
                    voucher_write_cap,
                    box1,
                    sealing: false,
                    sealed: None,
                });
            }
            Input::SealedReply { inducted, .. } => {
                let Some(i) = &mut c.inducting else { return };
                i.sealing = false;
                i.sealed = Some(Sealed {
                    name: inducted.name.clone(),
                    mutated_read_cap: inducted.mutated_read_cap.clone(),
                    reply: inducted.sealed_reply.clone(),
                });
                let publish = Action::Publish {
                    chat: id,
                    voucher_write_cap: i.voucher_write_cap.clone(),
                    box1: i.box1.clone(),
                    reply: inducted.sealed_reply,
                };
                // The Introduction goes ahead of anything queued while the reply was sealing,
                // so it is the box at the index the reply names.
                if let Some(g) = &mut c.group {
                    let o = g.introduce_now(&sanitize(&inducted.name), &inducted.mutated_read_cap);
                    let waiting = std::mem::take(&mut c.jobs);
                    cx.enqueue(c, vec![o], None, None, None);
                    c.jobs.extend(waiting);
                    cx.dirty(c);
                }
                cx.emit(publish);
            }
            Input::Published { .. } => {
                let Some(sealed) = c.inducting.as_ref().and_then(|i| i.sealed.clone()) else {
                    return;
                };
                let who = sanitize(&sealed.name);
                c.inducting = None;
                c.names
                    .insert(wire::key_of(&sealed.mutated_read_cap).to_vec(), who.clone());
                cx.notice(c, NoticeKind::Added, &[&who]);
            }
            Input::Send { text, .. } => {
                let Some(g) = &mut c.group else {
                    cx.notice(c, NoticeKind::NotJoined, &[]);
                    return;
                };
                let content = wire::text_content(&g.membership(None), &text);
                let me_key = g.me();
                let line = cx.say(
                    c,
                    Line {
                        sender: me_key,
                        text,
                        status: Status::Pending,
                        ..Line::default()
                    },
                );
                let out = c.group.as_mut().unwrap().compose(Some(content.clone()));
                cx.enqueue(c, out, Some(&content), Some(line), None);
            }
            Input::SendFile { name, bytes, .. } => {
                let Some(g) = &c.group else {
                    cx.notice(c, NoticeKind::NotJoined, &[]);
                    return;
                };
                if bytes.len() > MAX_FILE {
                    cx.notice(c, NoticeKind::FileTooLarge, &[&size_text(MAX_FILE)]);
                    return;
                }
                let safe = wire::safe_name(&name);
                let f = FileUpload {
                    payload: Vec::new(),
                    filetype: wire::filetype_of(&safe).into(),
                    basename: safe.clone(),
                };
                let content = wire::file_content(&g.membership(None), &f);
                let me_key = g.me();
                let a = Attachment {
                    name: safe.clone(),
                    filetype: f.filetype,
                    size: bytes.len(),
                    file: attachment_file(c, c.next_id, now, &safe),
                };
                cx.keep(a.file.clone(), bytes.clone());
                let line = cx.say(
                    c,
                    Line {
                        sender: me_key,
                        text: file_text(&a),
                        status: Status::Pending,
                        attachment: Some(a),
                        ..Line::default()
                    },
                );
                let out = c.group.as_mut().unwrap().compose(Some(content.clone()));
                cx.enqueue(c, out, Some(&content), Some(line), Some(&bytes));
            }
            Input::Loaded { job, bytes, .. } => {
                let Some(j) = c.jobs.iter().find(|j| j.id == job) else {
                    return;
                };
                match bytes {
                    Some(b) => {
                        cx.flight.blobs.insert((id, job), b);
                    }
                    None => {
                        if let (Some(t), Some(g)) = (j.token, &mut c.group) {
                            g.abandoned(t);
                        }
                        c.jobs.retain(|j| j.id != job);
                        cx.notice(c, NoticeKind::SendLost, &[]);
                    }
                }
            }
            Input::Substream { job, keypair, .. } => {
                if let Some(u) = c.job_mut(job).and_then(|j| j.upload.as_mut()) {
                    u.write_cap = keypair.write_cap;
                    u.next = keypair.first;
                }
            }
            Input::ChunkIndexes {
                job,
                start,
                indexes,
                ..
            } => {
                if c.jobs
                    .iter()
                    .any(|j| j.id == job && j.upload.as_ref().is_some_and(|u| u.next == start))
                {
                    let mut a = vec![start];
                    a.extend(indexes);
                    cx.flight.ahead.insert((id, job), a);
                }
            }
            Input::WroteChunk { job, n, next, .. } => cx.wrote_chunk(c, job, n, next),
            Input::ReadChunk {
                stream,
                index,
                outcome,
                ..
            } => cx.read_chunk(c, stream, index, outcome),
            Input::Wrote {
                job, index, next, ..
            } => {
                let Some(pos) = c.jobs.iter().position(|j| j.id == job) else {
                    return;
                };
                let j = c.jobs.remove(pos);
                if let (Some(t), Some(g)) = (j.token, &mut c.group) {
                    g.written(t, &index, Some(Payload::Bytes(j.box_.clone())));
                    c.next_write = next;
                }
                if let Some(l) = j.line {
                    let n = wire::counter(&index);
                    if let Some(line) = c.log.iter_mut().find(|x| x.id == l) {
                        line.status = Status::Sent;
                        line.idx64 = Some(n);
                        cx.line_changed(c, l);
                    }
                }
            }
            // The chat's writes stop here: the job stays first, and nothing writes after it.
            Input::Refused { .. } => cx.notice(c, NoticeKind::Desync, &[]),
            Input::Read {
                stream,
                index,
                outcome,
                ..
            } => cx.read(c, stream, index, outcome),
            Input::Scan { .. } => {
                let Some(g) = &mut c.group else { return };
                for stream in g.readers.keys().cloned().collect::<Vec<_>>() {
                    let es = c.group.as_mut().unwrap().handle(Event::Scan { stream });
                    cx.effects(c, es);
                }
                cx.notice(c, NoticeKind::Scanning, &[]);
            }
            Input::RemoveMember { who, .. } => {
                if !c
                    .group
                    .as_ref()
                    .is_some_and(|g| g.readers.contains_key(&who))
                {
                    cx.notice(c, NoticeKind::NoLongerMember, &[]);
                    return;
                }
                let l = label(c, &who);
                c.group.as_mut().unwrap().remove(&who);
                cx.stop_reading(c, &who);
                cx.hit(c, &who);
                cx.flight.fetched.remove(&(id.clone(), who.clone()));
                cx.drop_lines(c, |x| x.sender != who);
                c.cursors.shift_remove(&who);
                c.downloads.retain(|d| d.stream != who);
                cx.notice(c, NoticeKind::StoppedReading, &[&l]);
            }
            Input::Clear { .. } => cx.drop_lines(c, |_| false),
            Input::ScanRead {
                stream,
                index,
                outcome,
                ..
            } => {
                let Some(g) = &mut c.group else { return };
                let (result, next) = read_result(&outcome);
                let es = g.handle(Event::BoxRead {
                    stream: stream.clone(),
                    index,
                    result,
                    next,
                });
                cx.effects(c, es);
                cx.follow_reader(c, &stream);
            }
            Input::Walked {
                stream,
                target,
                skipped,
                steps,
                ..
            } => {
                let Some(g) = &mut c.group else { return };
                let es = g.handle(Event::Walked {
                    stream: stream.clone(),
                    target,
                    skipped,
                    steps,
                });
                cx.effects(c, es);
                cx.follow_reader(c, &stream);
            }
            Input::Derived {
                stream, indexes, ..
            } => {
                let Some(g) = &mut c.group else { return };
                let es = g.handle(Event::IndexesDerived { stream, indexes });
                cx.effects(c, es);
            }
            Input::Failed { what, .. } => {
                // A chat still joining stays so, and joins on when resumed.
                cx.cancel_held(c);
                c.inducting = None;
                cx.notice(c, NoticeKind::ActionFailed, &[&what]);
            }
            Input::Create { .. }
            | Input::Join { .. }
            | Input::Leave { .. }
            | Input::Rename { .. }
            | Input::Epoch { .. }
            | Input::Wake { .. } => {}
        }
    }
}
