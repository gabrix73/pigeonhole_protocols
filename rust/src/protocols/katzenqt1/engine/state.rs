use indexmap::IndexMap;
use crate::protocols::katzenqt1::member::{Group, Index, Key};
use crate::transport::Secret;

use crate::protocols::katzenqt1::engine::Action;
use crate::protocols::katzenqt1::engine::notice::Notice;

/// Names a conversation for good; its name may change.
pub type ChatId = String;

/// A message too long for a box, being written to a substream of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Upload {
    /// The file under the state directory that holds the message, until it is written.
    pub file: String,
    /// The most plaintext a box holds, which its boxes were cut to.
    pub box_size: usize,
    pub total: usize,
    /// The substream's, once made.
    pub write_cap: Secret,
    /// The boxes written so far, and the index of the next.
    pub sent: usize,
    pub next: Index,
}

/// A box to write to our own stream, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub id: usize,
    /// The message's token, to tell the member when it is written; `None` for a rewrite.
    pub token: Option<usize>,
    /// The box: chosen when the job is first sent, given for a rewrite.
    pub index: Option<Index>,
    /// What the box holds; empty for a tombstone.
    pub box_: Vec<u8>,
    /// The conversation line it shows as.
    pub line: Option<usize>,
    /// For a message too long for a box: its substream, written first; `box_` is then the I box
    /// naming it.
    pub upload: Option<Upload>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Status {
    #[default]
    Sent,
    Pending,
}

/// A file a line carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub filetype: String,
    pub size: usize,
    /// The file under the state directory that holds it.
    pub file: String,
}

/// A line of a conversation: a message, or a notice of our own.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Line {
    pub id: usize,
    pub sender: Key,
    /// The box it came in, so that it can expire.
    pub index: Index,
    pub text: String,
    pub notice: Option<Notice>,
    pub status: Status,
    /// The Idx64 of our own message's box, once written.
    pub idx64: Option<u64>,
    /// When it was said here, or read, in milliseconds since the Unix epoch.
    pub time: i64,
    pub attachment: Option<Attachment>,
}

/// Joining a group through a contact voucher we minted: minting until `code` is set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Joining {
    pub code: String,
    pub secret_key: Secret,
    pub voucher_read_cap: Secret,
    pub box1: Index,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub name: String,
    pub mutated_read_cap: Secret,
    pub reply: Vec<u8>,
}

/// Inducting a member whose voucher we were given: reading the voucher until `payload` is set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Inducting {
    pub voucher: Secret,
    pub payload: Option<Secret>,
    pub voucher_write_cap: Secret,
    pub box1: Index,
    /// The reply is being sealed.
    pub sealing: bool,
    /// The reply once sealed, kept until it is in box 1, with whom it adds.
    pub sealed: Option<Sealed>,
}

/// A message a member's I box announced, being read from its substream. Their stream is read no
/// further until it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Download {
    pub stream: Key,
    /// The I box, and the one after it.
    pub index: Index,
    pub next: Index,
    pub read_cap: Secret,
    /// How many boxes the substream holds, when the writer said.
    pub total: Option<usize>,
}

#[derive(Clone, Debug, Default)]
pub struct Chat {
    pub id: ChatId,
    pub name: String,
    pub write_cap: Secret,
    pub next_write: Index,
    pub group: Option<Group>,
    /// Where we read each member's stream next.
    pub cursors: IndexMap<Key, Index>,
    pub names: IndexMap<Key, String>,
    pub jobs: Vec<Job>,
    pub log: Vec<Line>,
    pub joining: Option<Joining>,
    pub inducting: Option<Inducting>,
    pub next_id: usize,
    pub downloads: Vec<Download>,
}

#[derive(Clone, Debug, Default)]
pub struct State {
    /// Our display name.
    pub me: String,
    pub chats: Vec<Chat>,
}

/// The lines a conversation keeps; older ones are dropped.
pub const MAX_LOG: usize = 10000;

impl State {
    pub fn chat(&self, id: &str) -> Option<&Chat> {
        self.chats.iter().find(|c| c.id == id)
    }

    pub fn chat_mut(&mut self, id: &str) -> Option<&mut Chat> {
        self.chats.iter_mut().find(|c| c.id == id)
    }

    pub fn chat_named(&self, name: &str) -> Option<&Chat> {
        self.chats.iter().find(|c| c.name == name)
    }

    /// Whether an action tried again is still of use: its chat is still here and, for a
    /// voucher's box, still waiting for it.
    pub fn wanted(&self, a: &Action) -> bool {
        let chat = match a {
            Action::AwaitReply {
                chat, secret_key, ..
            } => {
                return self
                    .chat(chat)
                    .and_then(|c| c.joining.as_ref())
                    .is_some_and(|j| &j.secret_key == secret_key);
            }
            Action::ReadVoucher { chat, voucher } => {
                return self
                    .chat(chat)
                    .and_then(|c| c.inducting.as_ref())
                    .is_some_and(|i| i.payload.is_none() && &i.voucher == voucher);
            }
            Action::Write { chat, .. }
            | Action::Read { chat, .. }
            | Action::ScanRead { chat, .. }
            | Action::Walk { chat, .. }
            | Action::Derive { chat, .. }
            | Action::Substream { chat, .. }
            | Action::WriteChunk { chat, .. }
            | Action::ChunkIndexes { chat, .. }
            | Action::ReadChunk { chat, .. } => chat,
            _ => return true,
        };
        self.chat(chat).is_some()
    }
}

impl Chat {
    pub(crate) fn fresh(&mut self) -> usize {
        self.next_id += 1;
        self.next_id - 1
    }

    /// The files a conversation's lines and jobs hold.
    pub fn files(&self) -> Vec<String> {
        let mut fs: Vec<String> = self
            .log
            .iter()
            .filter_map(|l| l.attachment.as_ref().map(|a| a.file.clone()))
            .collect();
        fs.extend(
            self.jobs
                .iter()
                .filter_map(|j| j.upload.as_ref().map(|u| u.file.clone())),
        );
        fs
    }

    pub(crate) fn job_mut(&mut self, id: usize) -> Option<&mut Job> {
        self.jobs.iter_mut().find(|j| j.id == id)
    }

    /// Whether any member has acknowledged our line `l`.
    pub fn acknowledged(&self, l: &Line) -> bool {
        match (&self.group, l.idx64) {
            (Some(g), Some(n)) => g.ledger.acked_by.values().any(|&s| n <= s),
            _ => false,
        }
    }
}

pub(crate) fn slug(group: &str) -> String {
    group
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
