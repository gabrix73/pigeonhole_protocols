//! The boxes a member wrote to its own stream: what it may still rewrite, and what retention lets
//! it forget.

use indexmap::IndexMap;

use crate::protocols::katzenqt1::member::{Effect, Index, Payload, counter};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retention {
    /// The epochs a Sent-box record is kept and backfilled; `None` keeps it for good.
    pub window: Option<usize>,
    /// Drop plaintext every member still read has acknowledged.
    pub discard_acked: bool,
    /// The epochs the policy keeps sent content.
    pub keep_sent: Option<usize>,
    /// The epochs the policy keeps received content.
    pub keep_received: Option<usize>,
}

impl Default for Retention {
    fn default() -> Self {
        Retention {
            window: Some(3),
            discard_acked: true,
            keep_sent: None,
            keep_received: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The box's whole MessageBoxIndex.
    pub index: Index,
    /// `None` once the plaintext is gone, or if it was never handed over.
    pub plaintext: Option<Payload>,
    pub control: bool,
    pub written: usize,
    /// Written as a tombstone once every member acknowledged it.
    pub settled: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SentBox {
    /// By the box's Idx64, which orders the boxes of the member's stream as it wrote them.
    pub records: IndexMap<u64, Record>,
    /// The epoch last backfilled.
    pub backfilled: Option<usize>,
}

impl SentBox {
    pub(crate) fn record(
        &mut self,
        index: Index,
        plaintext: Option<Payload>,
        control: bool,
        epoch: usize,
    ) {
        self.records.insert(
            counter(&index),
            Record {
                index,
                plaintext,
                control,
                written: epoch,
                settled: false,
            },
        );
    }

    /// The Sent-box check for an acknowledgement, which names the box by its Idx64.
    pub(crate) fn check_at(&self, idx64: u64) -> bool {
        self.records.contains_key(&idx64)
    }

    pub(crate) fn retain(
        &mut self,
        epoch: usize,
        policy: &Retention,
        everyone_acked: impl Fn(u64) -> bool,
    ) {
        if let Some(w) = policy.window {
            self.records.retain(|_, r| epoch <= r.written + w);
        }
        for (&k, r) in self.records.iter_mut() {
            let expired = policy
                .keep_sent
                .is_some_and(|keep| !r.control && r.written + keep <= epoch);
            if expired || policy.discard_acked && everyone_acked(k) {
                r.plaintext = None;
            }
        }
    }

    /// Rewrite every record a member has yet to acknowledge, at most once per epoch, and write a
    /// record every member has acknowledged as a tombstone once its plaintext is gone.
    pub(crate) fn backfill(
        &mut self,
        epoch: usize,
        everyone_acked: impl Fn(u64) -> bool,
    ) -> Vec<Effect> {
        if self.backfilled == Some(epoch) {
            return Vec::new();
        }
        let mut keys: Vec<u64> = self.records.keys().copied().collect();
        keys.sort();
        let mut es = Vec::new();
        for k in keys {
            let r = &self.records[&k];
            let acked = everyone_acked(k);
            match (&r.plaintext, acked) {
                (Some(p), false) => es.push(Effect::WriteBox {
                    index: r.index.clone(),
                    payload: p.clone(),
                }),
                (None, false) => es.push(Effect::WriteTombstone {
                    index: r.index.clone(),
                }),
                (None, true) if !r.settled => es.push(Effect::WriteTombstone {
                    index: r.index.clone(),
                }),
                _ => {}
            }
        }
        for (&k, r) in self.records.iter_mut() {
            if r.plaintext.is_none() && everyone_acked(k) {
                r.settled = true;
            }
        }
        self.backfilled = Some(epoch);
        es
    }
}
