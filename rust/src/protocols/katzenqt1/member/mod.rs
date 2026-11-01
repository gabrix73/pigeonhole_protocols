//! One member of one katzenqt1 group chat: a state machine over [`Group`], driven either by
//! events ([`Group::handle`], returning effects) or by a client that reads and writes itself
//! ([`Group::observe`], [`Group::compose`], [`Group::written`]). A member never derives a BACAP
//! index, encrypts, or touches the network itself.

mod bacap;
mod group;
mod ledger;
mod reader;
mod rosters;
mod sent_box;
pub mod sim;
pub mod trace;
mod walk;

pub use bacap::{hkdf, next_index};
pub use group::{AckedRun, Group, NumberAt, Outgoing, POOL_SIZE, Pending, ReceivedAt};
pub use ledger::{Induction, Invitee, Ledger};
pub use crate::secret::Secret;
pub use reader::{Kept, Lost, Mode, Reader};
pub use rosters::{Entry, KnownEntry, Roster, Rosters, Started};
pub use sent_box::{Record, Retention, SentBox};
pub use walk::{WALK_LIMIT, derive_with, walk_with};

pub use crate::protocols::katzenqt1::wire::{JoinReply, Message};

/// A member's identity: the public key its read cap begins with.
pub type Key = Vec<u8>;
/// A box: its 104-byte MessageBoxIndex.
pub type Index = Vec<u8>;

pub(crate) fn key_of(read_cap: &[u8]) -> Key {
    crate::protocols::katzenqt1::wire::key_of(read_cap).to_vec()
}

pub(crate) fn start_of(read_cap: &[u8]) -> Index {
    crate::protocols::katzenqt1::wire::start_of(read_cap).to_vec()
}

pub(crate) use crate::protocols::katzenqt1::wire::counter;

/// An Introduction: its introducer and its box.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct At {
    pub introducer: Key,
    pub index: Index,
}

/// What reading a box found: a message, `None` for one that holds nothing a member can decode,
/// or why there is none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadResult {
    Data(Option<Message>),
    Tombstone,
    NotFound,
}

/// What a box of the member's own stream holds, as its Sent box keeps it: a message the member
/// composed, which its client encodes, or the bytes a client that writes for itself handed over,
/// which the member never looks into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    Message(Message),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Send {
        content: Vec<u8>,
    },
    Read {
        stream: Key,
    },
    Scan {
        stream: Key,
    },
    /// The result of [`Effect::ReadBox`], with the index after it.
    BoxRead {
        stream: Key,
        index: Index,
        result: ReadResult,
        next: Option<Index>,
    },
    IndexesDerived {
        stream: Key,
        indexes: Vec<Index>,
    },
    /// The result of [`Effect::Walk`]: the box at the furthest target Idx64 within reach, the
    /// indexes before it (the last `keep` of them), and how many steps ahead it is.
    Walked {
        stream: Key,
        target: Option<Index>,
        skipped: Vec<Index>,
        steps: usize,
    },
    Invite {
        name: String,
        read_cap: Secret,
    },
    Introduce {
        name: String,
        read_cap: Secret,
    },
    Remove {
        member: Key,
    },
    EpochChanged {
        epoch: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    WriteBox {
        index: Index,
        payload: Payload,
    },
    WriteTombstone {
        index: Index,
    },
    ReadBox {
        stream: Key,
        read_cap: Secret,
        index: Index,
        recheck: bool,
    },
    DeriveIndexes {
        stream: Key,
        start: Index,
        count: usize,
    },
    Walk {
        stream: Key,
        start: Index,
        targets: Vec<u64>,
        keep: usize,
    },
    Deliver {
        sender: Key,
        index: Index,
        content: Vec<u8>,
    },
    Expire {
        sender: Key,
        index: Index,
    },
    SendJoinReply {
        to: Secret,
        reply: JoinReply,
    },
}
