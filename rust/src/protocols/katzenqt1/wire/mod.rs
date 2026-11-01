//! katzenqt1's wire formats: the fields of a group chat message, the GroupChatMessage CBOR and
//! its box framing, the reply to a new member and the membership hash.

mod acks;
mod cbor;
mod files;
mod gcm;
mod membership;
mod reply_who;
mod term;

pub use acks::{AcksError, acks_from_bytes, acks_to_bytes};
pub use files::{
    FileUpload, MAX_FILE, assemble, chunk_count, file_content, file_of, filetype_of, indirection,
    max_chunks, put_payload, safe_name, substream_box, take_payload, text_of,
};
pub use gcm::{
    CURRENT_VERSION, Chunk, Gcm, MSG_CONTROL, MSG_FILE_UPLOAD, MSG_INTRODUCTION, MSG_REPLY_WHO,
    MSG_TEXT, MSG_WHO, OTHER_KEYS, RawField, SENTINEL, box_of, frame, message_from_cbor,
    message_to_gcm, text_content, unframe,
};
pub use membership::membership_hash;
pub use reply_who::{IntroAt, JoinReply, Member, PleaseAdd, ReplyWho, Roster, RosterEntry};

pub const KEY_SIZE: usize = 32;
pub const INDEX_SIZE: usize = 104;
pub const READ_CAP_SIZE: usize = 136;
pub const HASH_SIZE: usize = 32;
/// The most entries a roster holds: roster indexes are one byte.
pub const ROSTER_MAX: usize = 256;
/// How much of a member's key a Numbers field names it by.
pub const PREFIX_SIZE: usize = 8;

/// A member's identity: the public key its read cap begins with.
pub fn key_of(read_cap: &[u8]) -> &[u8] {
    &read_cap[..KEY_SIZE.min(read_cap.len())]
}

pub fn prefix_of(key: &[u8]) -> &[u8] {
    &key[..PREFIX_SIZE.min(key.len())]
}

/// The index a read cap starts at.
pub fn start_of(read_cap: &[u8]) -> &[u8] {
    &read_cap[KEY_SIZE.min(read_cap.len())..]
}

/// The BACAP Idx64 of an index: its first 8 bytes, little-endian.
pub fn counter(index: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    let n = index.len().min(8);
    b[..n].copy_from_slice(&index[..n]);
    u64::from_le_bytes(b)
}

/// An Introduction as named by its introducer's roster index in the sender's roster, and its box.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IntroRef {
    pub introducer: usize,
    pub index: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Introduction {
    pub name: String,
    pub read_cap: Vec<u8>,
}

/// A roster index assigned to the member whose key starts with `prefix`; `None` for the member
/// the message's own Introduction introduces.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Number {
    pub index: usize,
    pub prefix: Option<Vec<u8>>,
}

/// An acknowledgement of the box with `idx64` of the member at roster index `member`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ack {
    pub member: usize,
    pub idx64: u64,
}

/// What a member reads of a message. It carries content or control, never both; `acks` are in
/// ascending order of roster index. A message the member makes itself carries the membership
/// hash it was composed with, so that a rewrite writes the same box; content carries its own.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Message {
    pub content: Option<Vec<u8>>,
    pub introduction: Option<Introduction>,
    pub numbers: Vec<Number>,
    pub introduced_at: Option<IntroRef>,
    pub acks: Vec<Ack>,
    pub membership_hash: Option<Vec<u8>>,
}

/// The first index assigned, then the key prefix of each member, one per consecutive index; a
/// lone byte for the member an Introduction introduces.
pub fn numbers_to_bytes(numbers: &[Number]) -> Vec<u8> {
    match numbers {
        [] => Vec::new(),
        [
            Number {
                index,
                prefix: None,
            },
        ] => vec![*index as u8],
        [first, ..] => {
            let mut out = vec![first.index as u8];
            for n in numbers {
                if let Some(p) = &n.prefix {
                    out.extend_from_slice(p);
                }
            }
            out
        }
    }
}

/// Empty when the field is malformed.
pub fn numbers_from_bytes(field: &[u8]) -> Vec<Number> {
    match field {
        [] => Vec::new(),
        [k] => vec![Number {
            index: *k as usize,
            prefix: None,
        }],
        [first, rest @ ..] => {
            if rest.len() % PREFIX_SIZE != 0 {
                return Vec::new();
            }
            let n = rest.len() / PREFIX_SIZE;
            let first = *first as usize;
            if first + n > ROSTER_MAX {
                return Vec::new();
            }
            let prefixes: Vec<&[u8]> = rest.chunks(PREFIX_SIZE).collect();
            for (i, p) in prefixes.iter().enumerate() {
                if prefixes[..i].contains(p) {
                    return Vec::new();
                }
            }
            prefixes
                .into_iter()
                .enumerate()
                .map(|(i, p)| Number {
                    index: first + i,
                    prefix: Some(p.to_vec()),
                })
                .collect()
        }
    }
}

pub fn introduced_at_to_bytes(r: &IntroRef) -> Vec<u8> {
    let mut out = vec![r.introducer as u8];
    out.extend_from_slice(&r.index);
    out
}

pub fn introduced_at_from_bytes(field: &[u8]) -> Option<IntroRef> {
    if field.len() != 1 + INDEX_SIZE {
        return None;
    }
    Some(IntroRef {
        introducer: field[0] as usize,
        index: field[1..].to_vec(),
    })
}
