//! A reader reads one member's stream in order, one box at a time. A scan rechecks boxes
//! previously stepped past and may jump ahead to a box another member acknowledged, keeping the
//! boxes it skips. A reader acknowledges the end of the unbroken run it has read ([`Reader::run`]).

use crate::protocols::katzenqt1::member::Secret;
use crate::protocols::katzenqt1::member::{Effect, Index, Key, Message, ReadResult, counter};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Idle,
    Reading,
    Scanning,
}

/// A box a scan stepped past without reading: with the count it was passed at and the box before
/// it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    pub index: Index,
    pub passed: usize,
    pub before: Option<Index>,
}

/// The first box passed unread and no longer kept; acknowledgements stop before it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lost {
    pub passed: usize,
    pub before: Option<Index>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reader {
    pub stream: Key,
    pub read_cap: Secret,
    /// The index of the next box to read.
    pub next: Index,
    /// The last box read in order, data or tombstone.
    pub last: Option<Index>,
    /// How many boxes this reader has passed.
    pub passed: usize,
    /// Boxes a scan stepped past, oldest first.
    pub kept: Vec<Kept>,
    pub lost: Option<Lost>,
    pub mode: Mode,
    /// The Idx64 of each acknowledged box ahead that a scan has already looked for, while it is
    /// still heard: no more than there are members.
    pub tried: Vec<u64>,
}

impl Reader {
    pub(crate) fn new(read_cap: Vec<u8>, next: Index) -> Reader {
        Reader {
            stream: crate::protocols::katzenqt1::member::key_of(&read_cap),
            read_cap: read_cap.into(),
            next,
            last: None,
            passed: 0,
            kept: Vec::new(),
            lost: None,
            mode: Mode::Idle,
            tried: Vec::new(),
        }
    }

    fn read_box(&self, index: &Index, recheck: bool) -> Effect {
        Effect::ReadBox {
            stream: self.stream.clone(),
            read_cap: self.read_cap.clone(),
            index: index.clone(),
            recheck,
        }
    }

    pub(crate) fn read(&mut self) -> Vec<Effect> {
        if self.mode != Mode::Idle {
            return Vec::new();
        }
        self.mode = Mode::Reading;
        vec![self.read_box(&self.next, false)]
    }

    /// Acknowledged boxes ahead of here a scan has not looked for yet, each once. A walk only goes
    /// forward, so one behind is never found.
    fn ahead(&self, heard: &[u64]) -> Vec<u64> {
        let here = counter(&self.next);
        let mut out = Vec::new();
        for &h in heard {
            if h > here && !self.tried.contains(&h) && !out.contains(&h) {
                out.push(h);
            }
        }
        out
    }

    /// Recheck what was kept, then look for acknowledged boxes ahead, or probe forward from here.
    pub(crate) fn scan(&mut self, heard: &[u64], window: usize) -> Vec<Effect> {
        let here = counter(&self.next);
        self.tried.retain(|t| *t > here && heard.contains(t));
        let ahead = self.ahead(heard);
        let mut es: Vec<Effect> = self
            .kept
            .iter()
            .map(|k| self.read_box(&k.index, true))
            .collect();
        self.mode = Mode::Scanning;
        if ahead.is_empty() {
            es.push(self.read_box(&self.next, false));
            return es;
        }
        self.tried.extend(&ahead);
        es.push(Effect::Walk {
            stream: self.stream.clone(),
            start: self.next.clone(),
            targets: ahead,
            keep: window,
        });
        es
    }

    /// The end of the unbroken run read: how far this stream may be acknowledged.
    pub fn run(&self) -> Option<&Index> {
        let gaps = self
            .kept
            .iter()
            .map(|k| (k.passed, &k.before))
            .chain(self.lost.iter().map(|l| (l.passed, &l.before)));
        let mut min: Option<(usize, &Option<Index>)> = None;
        for g in gaps {
            if min.is_none_or(|m| g.0 < m.0) {
                min = Some(g);
            }
        }
        match min {
            None => self.last.as_ref(),
            Some((_, before)) => before.as_ref(),
        }
    }

    fn lose(&mut self, at: usize, before: Option<Index>) {
        if self.lost.as_ref().is_none_or(|l| at < l.passed) {
            self.lost = Some(Lost { passed: at, before });
        }
    }

    /// Drop kept boxes more than `window` behind, as lost.
    fn forget(&mut self, window: usize) {
        let (dropped, kept): (Vec<Kept>, Vec<Kept>) = std::mem::take(&mut self.kept)
            .into_iter()
            .partition(|k| k.passed + window < self.passed);
        for k in dropped {
            self.lose(k.passed, k.before);
        }
        self.kept = kept;
    }

    /// Jump to `t` past `steps` boxes, keeping the last `skipped` of them; any before those are
    /// given up on.
    fn jump(&mut self, t: Index, skipped: &[Index], steps: usize) {
        let start = self.passed + steps - skipped.len();
        if start > self.passed {
            self.lose(self.passed, self.last.clone());
        }
        let mut before = self.last.clone();
        for (n, i) in skipped.iter().enumerate() {
            self.kept.push(Kept {
                index: i.clone(),
                passed: start + n,
                before: before.clone(),
            });
            before = Some(i.clone());
        }
        self.passed += steps;
        self.next = t;
    }

    /// Take the result of a walk: jump to `target`, keeping the boxes passed.
    pub(crate) fn walked(
        &mut self,
        target: Option<Index>,
        skipped: &[Index],
        steps: usize,
        window: usize,
    ) -> Vec<Effect> {
        let Some(t) = target else {
            return vec![self.read_box(&self.next, false)];
        };
        self.jump(t.clone(), skipped, steps);
        self.forget(window);
        vec![self.read_box(&t, false)]
    }

    /// Take one box read: its message if it is new data to ingest, and what to read next.
    pub(crate) fn found(
        &mut self,
        index: &Index,
        result: ReadResult,
        next: Option<Index>,
        window: usize,
    ) -> (Option<Message>, Vec<Effect>) {
        let message_of = |r: ReadResult| match r {
            ReadResult::Data(m) => m,
            _ => None,
        };
        if let Some(n) = self.kept.iter().position(|k| &k.index == index) {
            if result == ReadResult::NotFound {
                return (None, Vec::new());
            }
            self.kept.remove(n);
            return (message_of(result), Vec::new());
        }
        if index != &self.next || self.mode == Mode::Idle {
            return (None, Vec::new());
        }
        let Some(next) = next.filter(|_| result != ReadResult::NotFound) else {
            self.mode = Mode::Idle;
            return (None, Vec::new());
        };
        self.last = Some(index.clone());
        self.next = next.clone();
        self.passed += 1;
        self.forget(window);
        (message_of(result), vec![self.read_box(&next, false)])
    }
}
