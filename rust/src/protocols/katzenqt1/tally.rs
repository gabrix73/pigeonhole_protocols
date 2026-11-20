//! Polls: katzenqt's tally protocol over the group chat, without IO. A poll is a Yjs document,
//! written with yrs in the Yjs v1 update encoding pycrdt 0.13.1 writes:
//!
//! - `meta`, a map: `survey_id` (hex), `topic`, `mode` (`approval` or `availability`), `n_slots`,
//!   `status` (`open` or `closed`) and `creator`, the voter id of whoever made it (hex);
//! - `slots`, an array of maps `{id, text}`, the options, with ids `s0`, `s1`, …;
//! - `votes`, a map from a voter id (hex) to a map of slot id to availability (`yes`, `no`, and
//!   in availability mode `maybe`), plus `_version`.
//!
//! Its creator sends the whole document in a create ([`MSG_TALLY_CREATE`]). A vote
//! ([`MSG_TALLY_VOTE`]) is the availabilities chosen and a version; every reader writes it into
//! its copy under the sender's voter id, never one the vote names, unless that voter's recorded
//! version is newer, so the newest wins whatever order votes come in; an equal version replaces.
//! A close ([`MSG_TALLY_CLOSE`]) counts only from the creator. A sync request
//! ([`MSG_TALLY_SYNC_REQ`]) carries the asker's state vector, and a member holding the poll
//! answers with a sync response ([`MSG_TALLY_SYNC_RESP`]), the update the asker lacks, which is
//! merged like a create. The counts are read from the votes; a voter who left an option out
//! counts as no for it. A vote or close read before its poll waits for it.
//!
//! [`Polls`] rebuilds a group's polls from its lines, so a client keeps nothing but the lines.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use blake2::digest::consts::U16;
use blake2::{Blake2b, Digest};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{Any, Array, ArrayRef, Doc, Map, MapPrelim, MapRef, Out, ReadTxn, StateVector, Transact, Update};

use crate::protocols::katzenqt1::engine::Line;
use crate::protocols::katzenqt1::wire::{
    MSG_TALLY_CLOSE, MSG_TALLY_CREATE, MSG_TALLY_SYNC_REQ, MSG_TALLY_SYNC_RESP, MSG_TALLY_VOTE, Tally,
};

/// The longest survey id katzenqt reads.
pub const MAX_SURVEY_ID: usize = 64;
/// The largest update or state vector katzenqt reads.
pub const MAX_CRDT: usize = 512 * 1024;
const VERSION_KEY: &str = "_version";

/// A voter's id: the BLAKE2b-128 of the member's key, the 32 bytes their read cap starts with.
pub fn voter_id(key: &[u8]) -> [u8; 16] {
    Blake2b::<U16>::digest(key).into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Yes or no for each option.
    Approval,
    /// Yes, maybe or no for each option.
    Availability,
}

impl Mode {
    pub fn name(self) -> &'static str {
        match self {
            Mode::Approval => "approval",
            Mode::Availability => "availability",
        }
    }

    fn of(s: &str) -> Option<Mode> {
        match s {
            "approval" => Some(Mode::Approval),
            "availability" => Some(Mode::Availability),
            _ => None,
        }
    }

    /// The availabilities a vote may give, in the order a tap cycles through them after none.
    pub fn domain(self) -> &'static [&'static str] {
        match self {
            Mode::Approval => &["yes", "no"],
            Mode::Availability => &["yes", "maybe", "no"],
        }
    }
}

/// A new poll's document, as the update a create carries; `creator` is the maker's member key.
pub fn new_poll(survey_id: &[u8], topic: &str, mode: Mode, options: &[String], creator: &[u8]) -> Vec<u8> {
    let doc = Doc::new();
    let meta = doc.get_or_insert_map("meta");
    let slots = doc.get_or_insert_array("slots");
    doc.get_or_insert_map("votes");
    let mut txn = doc.transact_mut();
    meta.insert(&mut txn, "survey_id", hex::encode(survey_id));
    meta.insert(&mut txn, "topic", topic);
    meta.insert(&mut txn, "mode", mode.name());
    meta.insert(&mut txn, "n_slots", options.len() as f64);
    meta.insert(&mut txn, "status", "open");
    meta.insert(&mut txn, "creator", hex::encode(voter_id(creator)));
    for (i, text) in options.iter().enumerate() {
        slots.push_back(&mut txn, MapPrelim::from_iter([("id", format!("s{i}")), ("text", text.clone())]));
    }
    txn.encode_state_as_update_v1(&StateVector::default())
}

/// The create for a new poll, `survey_id` fresh and random, katzenqt's 16 bytes.
pub fn create(survey_id: &[u8], topic: &str, mode: Mode, options: &[String], me: &[u8]) -> Tally {
    Tally {
        kind: MSG_TALLY_CREATE,
        survey_id: survey_id.to_vec(),
        crdt: Some(new_poll(survey_id, topic, mode, options, me)),
        ..Tally::default()
    }
}

/// One option of a poll, counted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Count {
    pub id: String,
    pub text: String,
    pub yes: usize,
    pub maybe: usize,
    pub no: usize,
}

/// One voter's recorded vote: the availability for each option they marked, in option order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ballot {
    pub voter: [u8; 16],
    pub version: u64,
    pub choice: Vec<(String, String)>,
}

/// Which options lead: the one with the most yes, several tied, or none with a yes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Winner(String),
    Tie(Vec<String>),
    NoWinner,
}

/// A poll as it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollView {
    pub survey_id: Vec<u8>,
    pub topic: String,
    pub mode: Mode,
    pub closed: bool,
    /// The maker's voter id; none for a poll made before katzenqt kept it.
    pub creator: Option<[u8; 16]>,
    pub options: Vec<Count>,
    /// By voter id, in order.
    pub ballots: Vec<Ballot>,
}

impl PollView {
    /// By yes votes alone, as katzenqt declares it.
    pub fn outcome(&self) -> Outcome {
        let top = self.options.iter().map(|o| o.yes).max().unwrap_or(0);
        let leaders: Vec<String> = self.options.iter().filter(|o| o.yes == top).map(|o| o.text.clone()).collect();
        match (top, leaders.len()) {
            (0, _) => Outcome::NoWinner,
            (_, 1) => Outcome::Winner(leaders[0].clone()),
            _ => Outcome::Tie(leaders),
        }
    }

    /// Whether `voter` may close it: its creator, or anyone when it names none.
    pub fn may_close(&self, voter: &[u8; 16]) -> bool {
        self.creator.is_none_or(|c| &c == voter)
    }
}

/// A poll's document.
pub struct Poll {
    doc: Doc,
}

impl Poll {
    /// The poll an update makes, if it reads as one.
    pub fn load(update: &[u8]) -> Option<Poll> {
        let p = Poll { doc: Doc::new() };
        (p.merge(update) && p.view().is_some()).then_some(p)
    }

    /// Merge an update into the document; false if it can't be read.
    pub fn merge(&self, update: &[u8]) -> bool {
        if update.len() > MAX_CRDT {
            return false;
        }
        // An update from another member is untrusted: one that makes yrs panic is refused.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(u) = Update::decode_v1(update) else { return false };
            self.doc.transact_mut().apply_update(u).is_ok()
        }))
        .unwrap_or(false)
    }

    /// The whole document as one update.
    pub fn update(&self) -> Vec<u8> {
        self.doc.transact().encode_state_as_update_v1(&StateVector::default())
    }

    /// What the document holds, as a state vector, for a sync request.
    pub fn state_vector(&self) -> Vec<u8> {
        self.doc.transact().state_vector().encode_v1()
    }

    /// The update a holder of the state vector `sv` lacks; none if `sv` can't be read.
    pub fn diff(&self, sv: &[u8]) -> Option<Vec<u8>> {
        if sv.len() > MAX_CRDT {
            return None;
        }
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let sv = StateVector::decode_v1(sv).ok()?;
            Some(self.doc.transact().encode_state_as_update_v1(&sv))
        }))
        .ok()
        .flatten()
    }

    fn roots(&self) -> (MapRef, ArrayRef, MapRef) {
        (self.doc.get_or_insert_map("meta"), self.doc.get_or_insert_array("slots"), self.doc.get_or_insert_map("votes"))
    }

    /// The version of the vote recorded for `voter`, if any.
    pub fn version(&self, voter: &[u8; 16]) -> Option<u64> {
        let (_, _, votes) = self.roots();
        let txn = self.doc.transact();
        let Some(Out::YMap(v)) = votes.get(&txn, &hex::encode(voter)) else { return None };
        Some(version_of(v.get(&txn, VERSION_KEY)))
    }

    /// Record `voter`'s choice unless a newer version of theirs is recorded; false, recording
    /// nothing, if the choice names an option the poll lacks or an availability its mode does not
    /// allow.
    pub fn vote(&self, voter: &[u8; 16], choice: &[(String, String)], version: u64) -> bool {
        let Some(view) = self.view() else { return false };
        let ok = |s: &String, a: &String| view.options.iter().any(|o| &o.id == s) && view.mode.domain().contains(&a.as_str());
        if !choice.iter().all(|(s, a)| ok(s, a)) {
            return false;
        }
        if self.version(voter).is_some_and(|v| version < v) {
            return true;
        }
        let (_, _, votes) = self.roots();
        let mut m: HashMap<String, Any> = choice.iter().map(|(s, a)| (s.clone(), Any::from(a.as_str()))).collect();
        m.insert(VERSION_KEY.into(), Any::Number(version as f64));
        votes.insert(&mut self.doc.transact_mut(), hex::encode(voter), MapPrelim::from_iter(m));
        true
    }

    /// Close the poll if `voter` may; false if not.
    pub fn close(&self, voter: &[u8; 16]) -> bool {
        if !self.view().is_some_and(|v| v.may_close(voter)) {
            return false;
        }
        let (meta, _, _) = self.roots();
        meta.insert(&mut self.doc.transact_mut(), "status", "closed");
        true
    }

    /// The poll, counted; none if the document is not a poll.
    pub fn view(&self) -> Option<PollView> {
        let (meta, slots, votes) = self.roots();
        let txn = self.doc.transact();
        let survey_id = hex::decode(text_of(meta.get(&txn, "survey_id"))?).ok()?;
        let mode = Mode::of(&text_of(meta.get(&txn, "mode"))?)?;
        let mut options = Vec::new();
        for s in slots.iter(&txn) {
            let Out::YMap(s) = s else { return None };
            options.push(Count { id: text_of(s.get(&txn, "id"))?, text: text_of(s.get(&txn, "text"))?, yes: 0, maybe: 0, no: 0 });
        }
        let mut ballots = Vec::new();
        for (k, v) in votes.iter(&txn) {
            let (Out::YMap(v), Ok(voter)) = (v, hex::decode(k)) else { continue };
            let Ok(voter) = <[u8; 16]>::try_from(voter) else { continue };
            let mut choice: Vec<(String, String)> =
                v.iter(&txn).filter(|(k, _)| *k != VERSION_KEY).filter_map(|(k, a)| Some((k.to_string(), text_of(Some(a))?))).collect();
            choice.sort_by_key(|(k, _)| slot_number(k));
            for o in &mut options {
                match choice.iter().find(|(s, _)| s == &o.id).map(|(_, a)| a.as_str()) {
                    Some("yes") => o.yes += 1,
                    Some("maybe") => o.maybe += 1,
                    _ => o.no += 1,
                }
            }
            ballots.push(Ballot { voter, version: version_of(v.get(&txn, VERSION_KEY)), choice });
        }
        ballots.sort_by_key(|b| b.voter);
        let creator = text_of(meta.get(&txn, "creator")).and_then(|c| <[u8; 16]>::try_from(hex::decode(c).ok()?).ok());
        Some(PollView {
            survey_id,
            topic: text_of(meta.get(&txn, "topic"))?,
            mode,
            closed: text_of(meta.get(&txn, "status")).as_deref() == Some("closed"),
            creator,
            options,
            ballots,
        })
    }
}

fn text_of(o: Option<Out>) -> Option<String> {
    match o? {
        Out::Any(Any::String(s)) => Some(s.to_string()),
        _ => None,
    }
}

/// A recorded `_version`, as katzenqt reads one: 0 when absent, negative or not a finite number.
fn version_of(o: Option<Out>) -> u64 {
    match o {
        Some(Out::Any(Any::Number(n))) if n.is_finite() && n >= 0.0 => n as u64,
        Some(Out::Any(Any::BigInt(n))) if n >= 0 => n as u64,
        _ => 0,
    }
}

fn slot_number(id: &str) -> usize {
    id.strip_prefix('s').and_then(|n| n.parse().ok()).unwrap_or(usize::MAX)
}

/// The polls of a group, rebuilt from its lines: each shown at the line that brought it.
#[derive(Default)]
pub struct Polls {
    polls: BTreeMap<Vec<u8>, Poll>,
    /// The line each poll is shown at.
    at: BTreeMap<usize, Vec<u8>>,
    me: [u8; 16],
}

impl Polls {
    /// The polls `lines` hold, read by the member whose key is `me`: every create and sync
    /// response first, then the votes and closes in the order read, as katzenqt holds back a vote
    /// read before its poll until the poll comes.
    pub fn from_lines<L: Borrow<Line>>(lines: &[L], me: &[u8]) -> Polls {
        let mut p = Polls { me: voter_id(me), ..Polls::default() };
        for (l, t) in tallies(lines).filter(|(_, t)| matches!(t.kind, MSG_TALLY_CREATE | MSG_TALLY_SYNC_RESP)) {
            let Some(crdt) = &t.crdt else { continue };
            match p.polls.get(&t.survey_id) {
                Some(poll) => {
                    poll.merge(crdt);
                }
                // A poll's document names the poll it is.
                None => {
                    if let Some(poll) = Poll::load(crdt).filter(|q| q.view().is_some_and(|v| v.survey_id == t.survey_id)) {
                        p.polls.insert(t.survey_id.clone(), poll);
                        p.at.insert(l.id, t.survey_id.clone());
                    }
                }
            }
        }
        for (l, t) in tallies(lines) {
            let Some(poll) = p.polls.get(&t.survey_id) else { continue };
            let voter = voter_id(&l.sender);
            match t.kind {
                MSG_TALLY_VOTE => {
                    poll.vote(&voter, t.choice.as_deref().unwrap_or_default(), t.version);
                }
                MSG_TALLY_CLOSE => {
                    poll.close(&voter);
                }
                _ => {}
            }
        }
        p
    }

    /// Whether a line is shown: any but a tally's, and a poll's at the line that brought it.
    pub fn shows(&self, l: &Line) -> bool {
        l.tally.is_none() || self.at.contains_key(&l.id)
    }

    /// The poll shown at line `id`.
    pub fn at(&self, id: usize) -> Option<&Poll> {
        self.polls.get(self.at.get(&id)?)
    }

    /// Our own vote in the poll at line `id`.
    pub fn mine(&self, id: usize) -> Vec<(String, String)> {
        let Some(v) = self.at(id).and_then(Poll::view) else { return Vec::new() };
        v.ballots.into_iter().find(|b| b.voter == self.me).map(|b| b.choice).unwrap_or_default()
    }

    /// Our vote setting option `index` of the open poll at line `line` to `availability`, or
    /// leaving it unmarked for `None`; the rest of our vote stays.
    pub fn vote(&self, line: usize, index: usize, availability: Option<&str>) -> Option<Tally> {
        let poll = self.at(line)?;
        let view = poll.view().filter(|v| !v.closed)?;
        let slot = view.options.get(index)?.id.clone();
        if availability.is_some_and(|a| !view.mode.domain().contains(&a)) {
            return None;
        }
        let mut choice = self.mine(line);
        choice.retain(|(s, _)| *s != slot);
        if let Some(a) = availability {
            choice.push((slot, a.into()));
            choice.sort_by_key(|(k, _)| slot_number(k));
        }
        Some(Tally {
            kind: MSG_TALLY_VOTE,
            survey_id: view.survey_id,
            version: poll.version(&self.me).map_or(0, |v| v + 1),
            choice: Some(choice),
            crdt: None,
        })
    }

    /// Our vote moving option `index` of the poll at line `line` to the next availability of its
    /// mode, katzenqt's click to cycle: unmarked, then yes, (maybe,) no, and unmarked again.
    pub fn cycle(&self, line: usize, index: usize) -> Option<Tally> {
        let view = self.at(line)?.view()?;
        let slot = &view.options.get(index)?.id;
        let mine = self.mine(line);
        let now = mine.iter().find(|(s, _)| s == slot).map(|(_, a)| a.as_str());
        let domain = view.mode.domain();
        let next = match now.and_then(|a| domain.iter().position(|d| *d == a)) {
            None => domain.first().copied(),
            Some(i) => domain.get(i + 1).copied(),
        };
        self.vote(line, index, next)
    }

    /// Our close of the poll at line `line`, if it is open and ours to close.
    pub fn close(&self, line: usize) -> Option<Tally> {
        let view = self.at(line)?.view().filter(|v| !v.closed && v.may_close(&self.me))?;
        Some(Tally { kind: MSG_TALLY_CLOSE, survey_id: view.survey_id, ..Tally::default() })
    }

    /// The sync responses we owe: one for each other member's sync request for a poll we hold
    /// that we have not answered since it came.
    pub fn answers<L: Borrow<Line>>(&self, lines: &[L]) -> Vec<Tally> {
        let mut out = Vec::new();
        for (i, (l, t)) in tallies(lines).enumerate() {
            if t.kind != MSG_TALLY_SYNC_REQ || voter_id(&l.sender) == self.me {
                continue;
            }
            let answered = tallies(lines)
                .skip(i + 1)
                .any(|(m, a)| a.kind == MSG_TALLY_SYNC_RESP && a.survey_id == t.survey_id && voter_id(&m.sender) == self.me);
            let Some(poll) = self.polls.get(&t.survey_id) else { continue };
            if answered {
                continue;
            }
            if let Some(diff) = poll.diff(t.crdt.as_deref().unwrap_or_default()) {
                out.push(Tally { kind: MSG_TALLY_SYNC_RESP, survey_id: t.survey_id.clone(), crdt: Some(diff), ..Tally::default() });
            }
        }
        out
    }

    /// The sync requests to send: one for each poll other members vote in or close that we do
    /// not hold, as a member who joined after it was made, unless we asked already.
    pub fn requests<L: Borrow<Line>>(&self, lines: &[L]) -> Vec<Tally> {
        let asked: BTreeSet<&Vec<u8>> =
            tallies(lines).filter(|(l, t)| t.kind == MSG_TALLY_SYNC_REQ && voter_id(&l.sender) == self.me).map(|(_, t)| &t.survey_id).collect();
        let unknown: BTreeSet<&Vec<u8>> = tallies(lines)
            .filter(|(l, t)| matches!(t.kind, MSG_TALLY_VOTE | MSG_TALLY_CLOSE) && voter_id(&l.sender) != self.me)
            .map(|(_, t)| &t.survey_id)
            .filter(|s| !self.polls.contains_key(*s) && !asked.contains(s))
            .collect();
        let empty = Doc::new().transact().state_vector().encode_v1();
        unknown
            .into_iter()
            .map(|s| Tally { kind: MSG_TALLY_SYNC_REQ, survey_id: s.clone(), crdt: Some(empty.clone()), ..Tally::default() })
            .collect()
    }
}

/// The lines carrying tally messages katzenqt would read, with them.
fn tallies<L: Borrow<Line>>(lines: &[L]) -> impl Iterator<Item = (&Line, &Tally)> {
    lines.iter().map(Borrow::borrow).filter_map(|l: &Line| Some((l, l.tally.as_ref()?))).filter(|(_, t)| t.survey_id.len() <= MAX_SURVEY_ID)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: [u8; 32] = [1; 32];
    const BOB: [u8; 32] = [2; 32];
    const CAROL: [u8; 32] = [3; 32];

    fn line(id: usize, sender: &[u8], t: Tally) -> Line {
        Line { id, sender: sender.to_vec(), tally: Some(t), ..Line::default() }
    }

    fn vote(survey: &[u8], version: u64, choice: &[(&str, &str)]) -> Tally {
        Tally {
            kind: MSG_TALLY_VOTE,
            survey_id: survey.to_vec(),
            version,
            choice: Some(choice.iter().map(|(s, a)| (s.to_string(), a.to_string())).collect()),
            crdt: None,
        }
    }

    fn opts(o: &[&str]) -> Vec<String> {
        o.iter().map(|s| s.to_string()).collect()
    }

    fn counts(p: &Polls, line: usize) -> Vec<(usize, usize, usize)> {
        p.at(line).unwrap().view().unwrap().options.iter().map(|o| (o.yes, o.maybe, o.no)).collect()
    }

    fn poll(mode: Mode) -> (Tally, Vec<u8>) {
        let c = create(&[7; 16], "Lunch?", mode, &opts(&["Mon", "Tue", "Wed"]), &ALICE);
        let s = c.survey_id.clone();
        (c, s)
    }

    /// Several members' votes, read in any order, come to the same count; a member's newer vote
    /// replaces their older one whichever comes first.
    #[test]
    fn votes_in_any_order_come_to_the_same_count() {
        for mode in [Mode::Approval, Mode::Availability] {
            let (c, s) = poll(mode);
            let maybe = if mode == Mode::Availability { "maybe" } else { "no" };
            let lines = vec![
                line(1, &BOB, vote(&s, 0, &[("s0", "yes")])),
                line(2, &ALICE, c),
                line(3, &CAROL, vote(&s, 0, &[("s0", "yes"), ("s2", "yes")])),
                line(4, &BOB, vote(&s, 2, &[("s1", maybe), ("s2", "yes")])),
                line(5, &ALICE, vote(&s, 0, &[("s2", "yes")])),
                line(6, &BOB, vote(&s, 1, &[("s0", "yes")])),
            ];
            let want = match mode {
                Mode::Approval => vec![(1, 0, 2), (0, 0, 3), (3, 0, 0)],
                Mode::Availability => vec![(1, 0, 2), (0, 1, 2), (3, 0, 0)],
            };
            let mut orders = vec![lines.clone(), lines.iter().rev().cloned().collect()];
            orders.push([3, 0, 5, 1, 4, 2].iter().map(|&i| lines[i].clone()).collect());
            for order in orders {
                let p = Polls::from_lines(&order, &ALICE);
                assert_eq!(counts(&p, 2), want, "{mode:?}");
                assert_eq!(p.at(2).unwrap().view().unwrap().ballots.len(), 3);
                assert_eq!(p.at(2).unwrap().view().unwrap().outcome(), Outcome::Winner("Wed".into()));
            }
            let p = Polls::from_lines(&lines, &ALICE);
            assert_eq!(lines.iter().filter(|l| p.shows(l)).map(|l| l.id).collect::<Vec<_>>(), vec![2]);
        }
    }

    /// Documents that recorded different members' votes merge, as updates, to the same count.
    #[test]
    fn documents_merge_to_the_same_count() {
        let (c, _) = poll(Mode::Approval);
        let crdt = c.crdt.unwrap();
        let (a, b) = (Poll::load(&crdt).unwrap(), Poll::load(&crdt).unwrap());
        assert!(a.vote(&voter_id(&ALICE), &[("s0".into(), "yes".into())], 0));
        assert!(b.vote(&voter_id(&BOB), &[("s0".into(), "yes".into()), ("s1".into(), "yes".into())], 0));
        assert!(a.merge(&b.update()) && b.merge(&a.update()));
        assert_eq!(a.view(), b.view());
        assert_eq!(a.view().unwrap().options.iter().map(|o| o.yes).collect::<Vec<_>>(), vec![2, 1, 0]);
    }

    /// A vote or a poll read twice, and the poll's whole document sent again, change nothing.
    #[test]
    fn duplicates_change_nothing() {
        let (c, s) = poll(Mode::Approval);
        let again = Tally { kind: MSG_TALLY_SYNC_RESP, ..c.clone() };
        let once = vec![line(1, &ALICE, c.clone()), line(2, &BOB, vote(&s, 0, &[("s1", "yes")]))];
        let mut twice = once.clone();
        twice.extend([line(3, &BOB, vote(&s, 0, &[("s1", "yes")])), line(4, &ALICE, c), line(5, &ALICE, again)]);
        let (p, q) = (Polls::from_lines(&once, &ALICE), Polls::from_lines(&twice, &ALICE));
        assert_eq!(p.at(1).unwrap().view(), q.at(1).unwrap().view());
        assert_eq!(twice.iter().filter(|l| q.shows(l)).count(), 1);
    }

    /// Cycling through an option: unmarked, yes, (maybe,) no, unmarked; each a newer version.
    #[test]
    fn cycling_a_vote() {
        for (mode, want) in [(Mode::Approval, vec!["yes", "no", ""]), (Mode::Availability, vec!["yes", "maybe", "no", ""])] {
            let (c, _) = poll(mode);
            let mut lines = vec![line(1, &ALICE, c)];
            for (n, a) in want.iter().enumerate() {
                let v = Polls::from_lines(&lines, &BOB).cycle(1, 1).unwrap();
                assert_eq!(v.version, n as u64);
                lines.push(line(lines.len() + 1, &BOB, v));
                let mine = Polls::from_lines(&lines, &BOB).mine(1);
                assert_eq!(mine.iter().find(|(s, _)| s == "s1").map_or("", |(_, a)| a.as_str()), *a, "{mode:?}");
            }
        }
        // Setting one option keeps the others.
        let (c, s) = poll(Mode::Availability);
        let lines = vec![line(1, &ALICE, c), line(2, &BOB, vote(&s, 4, &[("s0", "maybe")]))];
        let v = Polls::from_lines(&lines, &BOB).vote(1, 2, Some("yes")).unwrap();
        assert_eq!((v.version, v.choice), (5, Some(vec![("s0".into(), "maybe".into()), ("s2".into(), "yes".into())])));
        assert_eq!(Polls::from_lines(&lines, &BOB).vote(1, 0, Some("perhaps")), None);
    }

    /// Only its creator closes a poll; then no one votes in it, and it declares its outcome.
    #[test]
    fn closing() {
        let (c, s) = poll(Mode::Approval);
        let mut lines = vec![line(1, &ALICE, c), line(2, &BOB, vote(&s, 0, &[("s0", "yes"), ("s1", "yes")]))];
        assert_eq!(Polls::from_lines(&lines, &BOB).close(1), None, "not bob's to close");
        lines.push(line(3, &BOB, Tally { kind: MSG_TALLY_CLOSE, survey_id: s.clone(), ..Tally::default() }));
        let p = Polls::from_lines(&lines, &ALICE);
        assert!(!p.at(1).unwrap().view().unwrap().closed, "a close from bob counts for nothing");
        assert_eq!(p.at(1).unwrap().view().unwrap().outcome(), Outcome::Tie(opts(&["Mon", "Tue"])));
        lines.push(line(4, &ALICE, p.close(1).unwrap()));
        let p = Polls::from_lines(&lines, &BOB);
        assert!(p.at(1).unwrap().view().unwrap().closed);
        assert_eq!(p.vote(1, 0, Some("yes")), None);
        assert_eq!(Polls::from_lines(&lines, &ALICE).close(1), None, "closed already");
    }

    /// A member who joined after a poll was made asks for it, from the votes they see, once; a
    /// member holding it answers, once; the answer makes the poll, its votes in it.
    #[test]
    fn sync_request_and_response() {
        let (c, s) = poll(Mode::Approval);
        let alice_lines = vec![line(1, &ALICE, c), line(2, &ALICE, vote(&s, 0, &[("s2", "yes")]))];
        // Carol sees only alice's vote.
        let mut carol = vec![line(10, &ALICE, vote(&s, 0, &[("s2", "yes")]))];
        let p = Polls::from_lines(&carol, &CAROL);
        assert!(p.answers(&carol).is_empty());
        let req = p.requests(&carol);
        assert_eq!(req.len(), 1);
        assert_eq!((req[0].kind, &req[0].survey_id), (MSG_TALLY_SYNC_REQ, &s));
        carol.push(line(11, &CAROL, req[0].clone()));
        assert!(Polls::from_lines(&carol, &CAROL).requests(&carol).is_empty(), "asked once");
        // Alice answers it, once.
        let mut alice = alice_lines.clone();
        alice.push(line(3, &CAROL, req[0].clone()));
        let resp = Polls::from_lines(&alice, &ALICE).answers(&alice);
        assert_eq!(resp.len(), 1);
        assert_eq!(resp[0].kind, MSG_TALLY_SYNC_RESP);
        alice.push(line(4, &ALICE, resp[0].clone()));
        assert!(Polls::from_lines(&alice, &ALICE).answers(&alice).is_empty(), "answered once");
        // Carol has the poll, shown at the response, with alice's vote.
        carol.push(line(12, &ALICE, resp[0].clone()));
        let p = Polls::from_lines(&carol, &CAROL);
        assert_eq!(counts(&p, 12), vec![(0, 0, 1), (0, 0, 1), (1, 0, 0)]);
        assert!(p.requests(&carol).is_empty());
        // A request from ourselves, or for a poll we lack, is not ours to answer.
        let lone = vec![line(1, &CAROL, req[0].clone())];
        assert!(Polls::from_lines(&lone, &CAROL).answers(&lone).is_empty());
    }

    /// What katzenqt refuses is refused here, and garbage does not panic.
    #[test]
    fn refusals() {
        let (c, s) = poll(Mode::Approval);
        // A create whose document names another poll.
        let other = Tally { survey_id: vec![9; 16], ..c.clone() };
        assert!(Polls::from_lines(&[line(1, &ALICE, other)], &ALICE).at(1).is_none());
        // A survey id longer than katzenqt reads.
        let long = Tally { survey_id: vec![9; MAX_SURVEY_ID + 1], ..c.clone() };
        assert!(Polls::from_lines(&[line(1, &ALICE, long)], &ALICE).at(1).is_none());
        // A create without its document; a document too large; garbage.
        assert!(Polls::from_lines(&[line(1, &ALICE, Tally { crdt: None, ..c.clone() })], &ALICE).at(1).is_none());
        let poll = Poll::load(c.crdt.as_ref().unwrap()).unwrap();
        assert!(!poll.merge(&vec![0; MAX_CRDT + 1]));
        assert!(Poll::load(&[0xff; 40]).is_none() && Poll::load(&[]).is_none());
        assert_eq!(poll.diff(&[0xff; 9]), None);
        // A vote for an option the poll lacks, or a maybe in an approval poll, counts for
        // nothing; a vote with no choice is a vote for nothing.
        let lines = vec![
            line(1, &ALICE, c),
            line(2, &BOB, vote(&s, 0, &[("s7", "yes")])),
            line(3, &BOB, vote(&s, 0, &[("s0", "maybe")])),
            line(4, &CAROL, Tally { choice: None, ..vote(&s, 0, &[]) }),
        ];
        let p = Polls::from_lines(&lines, &ALICE);
        assert_eq!(counts(&p, 1), vec![(0, 0, 1); 3]);
        assert_eq!(p.at(1).unwrap().view().unwrap().ballots.len(), 1);
        // A document that is no poll.
        let d = Doc::new();
        d.get_or_insert_map("meta").insert(&mut d.transact_mut(), "topic", "no id");
        assert!(Poll::load(&d.transact().encode_state_as_update_v1(&StateVector::default())).is_none());
    }
}
