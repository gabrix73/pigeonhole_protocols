use std::collections::{BTreeMap, BTreeSet};

use crate::protocols::katzenqt1::member::{Index, Key};
use crate::transport::{Inducted, Keypair, Minted, Opened, Secret};

use crate::protocols::katzenqt1::engine::ChatId;

/// What reading a box found, with the index after it for data or a tombstone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Data { plaintext: Vec<u8>, next: Index },
    Tombstone { next: Index },
    NotFound,
}

/// One thing that happened: a user's command, or what came of an [`Action`].
#[derive(Clone, Debug)]
pub enum Input {
    // What a user asks.
    Create {
        chat: ChatId,
        name: String,
    },
    /// Mint a voucher to join a group we will call `name`.
    Join {
        chat: ChatId,
        name: String,
    },
    /// Add the member whose voucher code is `code`.
    Induct {
        chat: ChatId,
        code: String,
    },
    Send {
        chat: ChatId,
        text: String,
    },
    SendFile {
        chat: ChatId,
        name: String,
        bytes: Vec<u8>,
    },
    Scan {
        chat: ChatId,
    },
    /// Forget a group: stop reading and writing it, and delete it.
    Leave {
        chat: ChatId,
    },
    /// Stop reading a member.
    RemoveMember {
        chat: ChatId,
        who: Key,
    },
    /// Delete a conversation's lines here.
    Clear {
        chat: ChatId,
    },
    Rename {
        chat: ChatId,
        to: String,
    },
    // What came of an action.
    Created {
        chat: ChatId,
        joining: bool,
        keypair: Keypair,
    },
    Wrote {
        chat: ChatId,
        job: usize,
        index: Index,
        next: Index,
    },
    /// A write found its box holding other bytes.
    Refused {
        chat: ChatId,
        job: usize,
    },
    Read {
        chat: ChatId,
        stream: Key,
        index: Index,
        outcome: Outcome,
    },
    Wake {
        chat: ChatId,
        stream: Key,
    },
    ScanRead {
        chat: ChatId,
        stream: Key,
        index: Index,
        outcome: Outcome,
    },
    Walked {
        chat: ChatId,
        stream: Key,
        target: Option<Index>,
        skipped: Vec<Index>,
        steps: usize,
    },
    Derived {
        chat: ChatId,
        stream: Key,
        indexes: Vec<Index>,
    },
    Minted {
        chat: ChatId,
        minted: Minted,
        box1: Index,
    },
    Opened {
        chat: ChatId,
        opened: Opened,
    },
    JoinerPayload {
        chat: ChatId,
        voucher: Secret,
        voucher_write_cap: Secret,
        payload: Secret,
        box1: Index,
    },
    SealedReply {
        chat: ChatId,
        inducted: Inducted,
    },
    /// The sealed reply is in box 1.
    Published {
        chat: ChatId,
    },
    Epoch {
        n: usize,
    },
    Failed {
        chat: ChatId,
        what: String,
    },
    /// An upload's message read back from its file, or `None` when it is lost.
    Loaded {
        chat: ChatId,
        job: usize,
        bytes: Option<Vec<u8>>,
    },
    Substream {
        chat: ChatId,
        job: usize,
        keypair: Keypair,
    },
    WroteChunk {
        chat: ChatId,
        job: usize,
        n: usize,
        next: Index,
    },
    ChunkIndexes {
        chat: ChatId,
        job: usize,
        start: Index,
        indexes: Vec<Index>,
    },
    ReadChunk {
        chat: ChatId,
        stream: Key,
        index: Index,
        outcome: Outcome,
    },
}

/// Network or disk work. Each comes back as the [`Input`] named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// A new stream: Created.
    Create { chat: ChatId, joining: bool },
    /// Write a box, retrying until it is written: Wrote, or Refused.
    Write {
        chat: ChatId,
        job: usize,
        write_cap: Secret,
        index: Index,
        box_: Vec<u8>,
    },
    /// Read a box once: Read.
    Read {
        chat: ChatId,
        stream: Key,
        read_cap: Secret,
        index: Index,
    },
    /// Send Wake after `ms` milliseconds.
    Wake { chat: ChatId, stream: Key, ms: u64 },
    /// Read a box once for a scan: ScanRead.
    ScanRead {
        chat: ChatId,
        stream: Key,
        read_cap: Secret,
        index: Index,
    },
    /// Walked.
    Walk {
        chat: ChatId,
        stream: Key,
        start: Index,
        targets: Vec<u64>,
        keep: usize,
    },
    /// Derived.
    Derive {
        chat: ChatId,
        stream: Key,
        start: Index,
        count: usize,
    },
    /// Mint a voucher and publish its box 0: Minted.
    Mint {
        chat: ChatId,
        write_cap: Secret,
        name: String,
    },
    /// Wait for the reply in box 1 and open it: Opened.
    AwaitReply {
        chat: ChatId,
        secret_key: Secret,
        voucher_read_cap: Secret,
        box1: Index,
        write_cap: Secret,
    },
    /// Read a voucher's box 0: JoinerPayload.
    ReadVoucher { chat: ChatId, voucher: Secret },
    /// Seal the reply to a voucher: SealedReply.
    Seal {
        chat: ChatId,
        voucher: Secret,
        payload: Secret,
        who_reply: Secret,
    },
    /// Write the sealed reply to box 1, retrying until it is written: Published.
    Publish {
        chat: ChatId,
        voucher_write_cap: Secret,
        box1: Index,
        reply: Vec<u8>,
    },
    /// Delete a file under the state directory.
    Delete { file: String },
    /// Read back the file holding an upload's message: Loaded.
    Load {
        chat: ChatId,
        job: usize,
        file: String,
    },
    /// A new stream for an upload: Substream.
    Substream { chat: ChatId, job: usize },
    /// Write the `n`th box of an upload, retrying until it is written: WroteChunk.
    WriteChunk {
        chat: ChatId,
        job: usize,
        n: usize,
        write_cap: Secret,
        index: Index,
        box_: Vec<u8>,
    },
    /// The indexes of `count` boxes after `start` of an upload's substream: ChunkIndexes.
    ChunkIndexes {
        chat: ChatId,
        job: usize,
        start: Index,
        count: usize,
    },
    /// Read a box of the substream an I box named: ReadChunk.
    ReadChunk {
        chat: ChatId,
        stream: Key,
        read_cap: Secret,
        index: Index,
    },
}

/// A file to keep under the state directory. It must be on disk before the state that names it
/// is saved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileWrite {
    pub file: String,
    pub bytes: Vec<u8>,
}

/// What a step changed, so that only that is saved.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changes {
    /// The conversations whose record changed, apart from their lines.
    pub chats: BTreeSet<ChatId>,
    /// The lines added or changed, by conversation.
    pub lines: BTreeMap<ChatId, BTreeSet<usize>>,
    /// The lines deleted, by conversation.
    pub dropped: BTreeMap<ChatId, BTreeSet<usize>>,
    /// The conversations deleted.
    pub removed: BTreeSet<ChatId>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        self.chats.is_empty()
            && self.lines.is_empty()
            && self.dropped.is_empty()
            && self.removed.is_empty()
    }
}

/// What a step asks for: files to keep, then the state to save, then work to start.
#[derive(Clone, Debug, Default)]
pub struct StepResult {
    pub files: Vec<FileWrite>,
    pub changes: Changes,
    pub actions: Vec<Action>,
}
