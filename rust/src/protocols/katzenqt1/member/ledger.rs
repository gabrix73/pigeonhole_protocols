//! What this member has acknowledged, and what others have acknowledged of each stream. An
//! induction holds publishing back.

use indexmap::IndexMap;

use crate::protocols::katzenqt1::member::Secret;
use crate::protocols::katzenqt1::member::{Index, Key};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Induction {
    #[default]
    Idle,
    CatchingUp,
    Inducting,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invitee {
    pub name: String,
    pub read_cap: Secret,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ledger {
    /// The last index acknowledged of each stream.
    pub published: IndexMap<Key, Index>,
    /// The Idx64 of the last box of our stream each member has acknowledged, after the Sent-box
    /// check.
    pub acked_by: IndexMap<Key, u64>,
    /// For each stream, the Idx64 of the last box each other member acknowledged of it.
    pub heard: IndexMap<Key, IndexMap<Key, u64>>,
    pub induction: Induction,
    /// The member being inducted.
    pub invitee: Option<Invitee>,
    /// Commit the induction as soon as catching up is done.
    pub commit: bool,
    /// Where each stream had been read when the invitation began.
    pub starts: IndexMap<Key, Index>,
}

impl Ledger {
    pub(crate) fn holding(&self) -> bool {
        self.induction == Induction::Inducting
    }

    /// The index to acknowledge of `stream`, the end of the unbroken run read, if anything new.
    pub(crate) fn owed(&self, stream: &Key, run: Option<&Index>) -> Option<Index> {
        let run = run?;
        if self.holding() || self.published.get(stream) == Some(run) {
            return None;
        }
        Some(run.clone())
    }

    pub(crate) fn hear(&mut self, stream: &Key, idx64: u64, by: &Key) {
        self.heard
            .entry(stream.clone())
            .or_default()
            .insert(by.clone(), idx64);
    }

    pub(crate) fn acked(&mut self, member: &Key, idx64: u64) {
        let v = self.acked_by.entry(member.clone()).or_insert(idx64);
        *v = (*v).max(idx64);
    }

    pub(crate) fn forget(&mut self, member: &Key) {
        self.acked_by.shift_remove(member);
        self.heard.shift_remove(member);
        for h in self.heard.values_mut() {
            h.shift_remove(member);
        }
    }
}
