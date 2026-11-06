//! A box of a member's stream holds `F` followed by the CBOR of one GroupChatMessage: from
//! version 4 the array [version, membership_hash, msg_type, body, acks, numbers, introduced_at]
//! with trailing nulls left out; up to version 3 the map katzenqt's models.py writes, its fields
//! in declaration order, absent ones left out. The first byte's major type tells the forms apart.
//! A ping, msg_type 11, is content with a null body: `[4, membership_hash, 11, null]` and, as for
//! any message, acks and the rest after it. Its readers play their ping sound. A reader refuses
//! a type it does not know; the engine then tells the user who sent it, its type and version.
//! A message too long for a box goes to a substream of `C` chunks ending in an `F` chunk,
//! announced in the member's stream by an `I` chunk carrying the substream's read cap.
//!
//! [`Gcm`] holds what this client reads of a message. The bodies it does not read (file_upload,
//! who, reply_who, tally) are kept as their CBOR under the map form's key, a file_upload as its
//! map; keys katzenqt does not know are dropped, as its decoder drops them.

use crate::protocols::katzenqt1::wire::cbor::*;
use crate::protocols::katzenqt1::wire::files::{upload_array, upload_map};
use crate::protocols::katzenqt1::wire::{
    HASH_SIZE, Introduction, Message, READ_CAP_SIZE, acks_from_bytes, acks_to_bytes,
    introduced_at_from_bytes, introduced_at_to_bytes, numbers_from_bytes, numbers_to_bytes,
};

/// The version written: the array form. The map form, up to [`MAP_VERSION`], is read as well.
pub const CURRENT_VERSION: u64 = 4;
/// The last version written as a CBOR map.
pub const MAP_VERSION: u64 = 3;
const MAX_NAME_CHARS: usize = 30;

pub const MSG_TEXT: u64 = 0;
pub const MSG_INTRODUCTION: u64 = 1;
pub const MSG_FILE_UPLOAD: u64 = 2;
pub const MSG_WHO: u64 = 3;
pub const MSG_REPLY_WHO: u64 = 4;
pub const MSG_CONTROL: u64 = 10;
/// Asks its readers to play their ping sound: content with a null body.
pub const MSG_PING: u64 = 11;

/// The fields this client keeps without reading, in the order they are written.
pub const OTHER_KEYS: [&str; 4] = ["file_upload", "who", "reply_who", "tally"];

/// The field a message type's body is, in the map form and in `other`.
fn body_key(msg_type: u64) -> Option<&'static str> {
    match msg_type {
        MSG_FILE_UPLOAD => Some("file_upload"),
        MSG_WHO => Some("who"),
        MSG_REPLY_WHO => Some("reply_who"),
        5..=9 => Some("tally"),
        _ => None,
    }
}

/// A field kept as its CBOR.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawField {
    pub key: String,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Gcm {
    pub version: u64,
    pub membership_hash: Vec<u8>,
    pub msg_type: u64,
    pub text: Option<String>,
    pub introduction: Option<Introduction>,
    pub other: Vec<RawField>,
    pub acks: Option<Vec<u8>>,
    pub numbers: Option<Vec<u8>>,
    pub introduced_at: Option<Vec<u8>>,
}

impl Gcm {
    /// The array form from version 4, the map form below it.
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.version < CURRENT_VERSION {
            return self.to_map_bytes();
        }
        let tail = [&self.acks, &self.numbers, &self.introduced_at];
        let n = tail.iter().rposition(|f| f.is_some()).map_or(0, |i| i + 1);
        let mut out = Vec::new();
        push_header(&mut out, 4, 4 + n as u64);
        push_uint(&mut out, self.version);
        push_bytes(&mut out, &self.membership_hash);
        push_uint(&mut out, self.msg_type);
        self.push_body(&mut out);
        for f in &tail[..n] {
            match f {
                Some(b) => push_bytes(&mut out, b),
                None => push_null(&mut out),
            }
        }
        out
    }

    /// The type's payload: the text, [name, read_cap], [payload, filetype, basename], an app's
    /// value as it came, or null.
    fn push_body(&self, out: &mut Vec<u8>) {
        let raw = body_key(self.msg_type).and_then(|k| self.other.iter().find(|o| o.key == k));
        match (self.msg_type, raw) {
            (MSG_TEXT, _) => push_text(out, self.text.as_deref().unwrap_or_default()),
            (MSG_INTRODUCTION, _) => match &self.introduction {
                Some(i) => {
                    push_header(out, 4, 2);
                    push_text(out, &i.name);
                    push_bytes(out, &i.read_cap);
                }
                None => push_null(out),
            },
            (MSG_FILE_UPLOAD, Some(o)) => {
                out.extend(upload_array(&o.raw).unwrap_or_else(|| o.raw.clone()))
            }
            (_, Some(o)) => out.extend_from_slice(&o.raw),
            _ => push_null(out),
        }
    }

    /// The map form, version 3.
    pub fn to_map_bytes(&self) -> Vec<u8> {
        let n = 3
            + self.other.len()
            + [
                self.text.is_some(),
                self.introduction.is_some(),
                self.acks.is_some(),
                self.numbers.is_some(),
                self.introduced_at.is_some(),
            ]
            .iter()
            .filter(|&&b| b)
            .count();
        let mut out = Vec::new();
        push_header(&mut out, 5, n as u64);
        push_text(&mut out, "version");
        push_uint(&mut out, self.version);
        push_text(&mut out, "membership_hash");
        push_bytes(&mut out, &self.membership_hash);
        push_text(&mut out, "msg_type");
        push_uint(&mut out, self.msg_type);
        if let Some(t) = &self.text {
            push_text(&mut out, "text");
            push_text(&mut out, t);
        }
        if let Some(i) = &self.introduction {
            push_text(&mut out, "introduction");
            push_header(&mut out, 5, 2);
            push_text(&mut out, "display_name");
            push_text(&mut out, &i.name);
            push_text(&mut out, "read_cap");
            push_bytes(&mut out, &i.read_cap);
        }
        for o in &self.other {
            push_text(&mut out, &o.key);
            out.extend_from_slice(&o.raw);
        }
        for (k, v) in [
            ("acks", &self.acks),
            ("numbers", &self.numbers),
            ("introduced_at", &self.introduced_at),
        ] {
            if let Some(v) = v {
                push_text(&mut out, k);
                push_bytes(&mut out, v);
            }
        }
        out
    }

    /// The message a box's CBOR holds, in either form, or `None` when it is refused. What
    /// follows the item is ignored, as cbor2.loads ignores it.
    pub fn from_bytes(b: &[u8]) -> Option<Gcm> {
        match b.first()? >> 5 {
            4 => Gcm::from_array(b),
            5 => Gcm::from_map(b),
            _ => None,
        }
    }

    fn from_array(b: &[u8]) -> Option<Gcm> {
        let (n, l) = read_array(b)?;
        if !(4..=7).contains(&n) {
            return None;
        }
        let (version, l) = read_uint(l)?;
        let (membership_hash, l) = read_bytes(l)?;
        let (msg_type, mut l) = read_uint(l)?;
        if version < CURRENT_VERSION || membership_hash.len() != HASH_SIZE || msg_type > MSG_PING {
            return None;
        }
        let mut g = Gcm {
            version,
            membership_hash,
            msg_type,
            ..Gcm::default()
        };
        l = match msg_type {
            MSG_TEXT => {
                let (s, l) = read_text(l)?;
                g.text = Some(s);
                l
            }
            MSG_INTRODUCTION => {
                let (n, l) = read_array(l)?;
                if n != 2 {
                    return None;
                }
                let (name, l) = read_text(l)?;
                let (read_cap, l) = read_bytes(l)?;
                g.introduction = Some(intro_of(name, read_cap)?);
                l
            }
            MSG_FILE_UPLOAD => {
                let (raw, l) = upload_map(l)?;
                g.other.push(RawField {
                    key: "file_upload".into(),
                    raw,
                });
                l
            }
            MSG_CONTROL | MSG_PING => {
                if !is_null(l) {
                    return None;
                }
                &l[1..]
            }
            _ if is_null(l) => &l[1..],
            _ => {
                let (raw, l) = read_raw(l)?;
                g.other.push(RawField {
                    key: body_key(msg_type)?.into(),
                    raw,
                });
                l
            }
        };
        for (i, slot) in [&mut g.acks, &mut g.numbers, &mut g.introduced_at]
            .into_iter()
            .enumerate()
        {
            if 4 + i as u64 >= n {
                break;
            }
            if is_null(l) {
                l = &l[1..];
            } else {
                let (b, rest) = read_bytes(l)?;
                *slot = Some(b);
                l = rest;
            }
        }
        Some(g)
    }

    fn from_map(b: &[u8]) -> Option<Gcm> {
        let (_, n, mut l) = read_header(b)?;
        let mut a = Acc::default();
        for _ in 0..n {
            l = a.read_field(l)?;
        }
        let msg_type = a.msg_type.unwrap_or_else(|| a.infer_type());
        let (Some(version), Some(membership_hash)) = (a.version, a.hash) else {
            return None;
        };
        if version > MAP_VERSION || membership_hash.len() != HASH_SIZE || msg_type > MSG_PING {
            return None;
        }
        let other = OTHER_KEYS
            .iter()
            .filter_map(|k| a.g.other.iter().find(|o| o.key == *k).cloned())
            .collect();
        Some(Gcm {
            version,
            membership_hash,
            msg_type,
            other,
            ..a.g
        })
    }

    fn is_control(&self) -> bool {
        self.msg_type == MSG_CONTROL || self.msg_type == MSG_INTRODUCTION
    }
}

/// An introduction katzenqt accepts: a name of 1 to 30 characters and a whole read cap.
fn read_intro(l: &[u8]) -> Option<(Introduction, &[u8])> {
    let (major, n, mut l) = read_header(l)?;
    if major != 5 {
        return None;
    }
    let (mut name, mut read_cap) = (None, None);
    for _ in 0..n {
        let (k, rest) = read_text(l)?;
        l = match k.as_str() {
            "display_name" => {
                let (s, rest) = read_text(rest)?;
                name = Some(s);
                rest
            }
            "read_cap" => {
                let (b, rest) = read_bytes(rest)?;
                read_cap = Some(b);
                rest
            }
            _ => skip_items(rest.len() + 1, 1, rest)?,
        };
    }
    Some((intro_of(name?, read_cap?)?, l))
}

fn intro_of(name: String, read_cap: Vec<u8>) -> Option<Introduction> {
    let chars = name.chars().count();
    if !(1..=MAX_NAME_CHARS).contains(&chars) || read_cap.len() != READ_CAP_SIZE {
        return None;
    }
    Some(Introduction { name, read_cap })
}

#[derive(Default)]
struct Acc {
    version: Option<u64>,
    hash: Option<Vec<u8>>,
    msg_type: Option<u64>,
    g: Gcm,
}

impl Acc {
    fn has_other(&self, k: &str) -> bool {
        self.g.other.iter().any(|o| o.key == k)
    }

    /// Take in one map entry; a repeated key keeps its last value, as a Python dict does, and
    /// null counts as absent.
    fn read_field<'a>(&mut self, l: &'a [u8]) -> Option<&'a [u8]> {
        let (k, l) = read_text(l)?;
        match k.as_str() {
            "version" => {
                let (n, l) = read_uint(l)?;
                self.version = Some(n);
                return Some(l);
            }
            "membership_hash" => {
                let (b, l) = read_bytes(l)?;
                self.hash = Some(b);
                return Some(l);
            }
            _ => {}
        }
        let nullable = matches!(
            k.as_str(),
            "msg_type" | "text" | "introduction" | "acks" | "numbers" | "introduced_at"
        ) || OTHER_KEYS.contains(&k.as_str());
        if nullable && is_null(l) {
            return Some(&l[1..]);
        }
        Some(match k.as_str() {
            "msg_type" => {
                let (n, l) = read_uint(l)?;
                self.msg_type = Some(n);
                l
            }
            "text" => {
                let (s, l) = read_text(l)?;
                self.g.text = Some(s);
                l
            }
            "introduction" => {
                let (i, l) = read_intro(l)?;
                self.g.introduction = Some(i);
                l
            }
            "acks" | "numbers" | "introduced_at" => {
                let (b, l) = read_bytes(l)?;
                let slot = match k.as_str() {
                    "acks" => &mut self.g.acks,
                    "numbers" => &mut self.g.numbers,
                    _ => &mut self.g.introduced_at,
                };
                *slot = Some(b);
                l
            }
            _ if OTHER_KEYS.contains(&k.as_str()) => {
                let (raw, l) = read_raw(l)?;
                self.g.other.retain(|o| o.key != k);
                self.g.other.push(RawField { key: k, raw });
                l
            }
            _ => skip_items(l.len() + 1, 1, l)?,
        })
    }

    /// The type of a message written before msg_type was, from the field it carries.
    fn infer_type(&self) -> u64 {
        if self.g.introduction.is_some() {
            MSG_INTRODUCTION
        } else if self.has_other("file_upload") {
            MSG_FILE_UPLOAD
        } else if self.has_other("who") {
            MSG_WHO
        } else if self.has_other("reply_who") {
            MSG_REPLY_WHO
        } else {
            MSG_TEXT
        }
    }
}

/// What a box of a stream holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Chunk {
    /// The last or only chunk of a message: its CBOR.
    Final(Vec<u8>),
    /// A chunk of a message that continues in the next box.
    Continued(Vec<u8>),
    /// Where a long message is: how many chunks its substream holds when the writer said, and
    /// the substream's read cap.
    Indirection {
        total: Option<u32>,
        read_cap: Vec<u8>,
    },
    Unknown,
}

pub fn frame(cbor: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(cbor.len() + 1);
    out.push(b'F');
    out.extend_from_slice(cbor);
    out
}

pub fn unframe(b: &[u8]) -> Chunk {
    let Some((&tag, rest)) = b.split_first() else {
        return Chunk::Unknown;
    };
    match tag {
        b'F' => Chunk::Final(rest.to_vec()),
        b'C' => Chunk::Continued(rest.to_vec()),
        b'I' if rest.len() == 4 + READ_CAP_SIZE => Chunk::Indirection {
            total: Some(u32::from_be_bytes(rest[..4].try_into().unwrap())),
            read_cap: rest[4..].to_vec(),
        },
        b'I' if rest.len() == READ_CAP_SIZE => Chunk::Indirection {
            total: None,
            read_cap: rest.to_vec(),
        },
        _ => Chunk::Unknown,
    }
}

/// The hash a control message or an introduction carries in place of the membership hash.
pub const SENTINEL: [u8; HASH_SIZE] = [0; HASH_SIZE];

/// The sentinel older clients send.
const OLD_SENTINEL: &[u8; HASH_SIZE] = b"TODOTODOTODOTODOTODOTODOTODOTODO";

/// Whether `h` says no membership hash.
pub fn is_sentinel(h: &[u8]) -> bool {
    h == SENTINEL || h == OLD_SENTINEL
}

/// What a member reads of a message's CBOR, or `None` when it is not a message. As katzenqt's
/// GcmCodec, a content message's whole CBOR travels as its content.
pub fn message_from_cbor(cbor: &[u8]) -> Option<Message> {
    let g = Gcm::from_bytes(cbor)?;
    Some(Message {
        content: (!g.is_control()).then(|| cbor.to_vec()),
        introduction: if g.msg_type == MSG_INTRODUCTION {
            g.introduction.clone()
        } else {
            None
        },
        numbers: numbers_from_bytes(g.numbers.as_deref().unwrap_or_default()),
        introduced_at: g
            .introduced_at
            .as_deref()
            .and_then(introduced_at_from_bytes),
        acks: acks_from_bytes(g.acks.as_deref().unwrap_or_default()).unwrap_or_default(),
        membership_hash: (g.is_control() && !is_sentinel(&g.membership_hash))
            .then(|| g.membership_hash.clone()),
    })
}

fn non_empty(b: Vec<u8>) -> Option<Vec<u8>> {
    (!b.is_empty()).then_some(b)
}

/// The message whose CBOR a member's `m` is written as; `None` when its content is not a
/// message. Control messages and introductions are written afresh, in `version`; content keeps
/// the version it carries.
pub fn message_to_gcm(m: &Message, version: u64) -> Option<Gcm> {
    let g = match (&m.content, &m.introduction) {
        (Some(c), _) => Gcm::from_bytes(c)?,
        (None, Some(i)) => Gcm {
            version,
            membership_hash: stamped(m),
            msg_type: MSG_INTRODUCTION,
            introduction: Some(i.clone()),
            ..Gcm::default()
        },
        (None, None) => Gcm {
            version,
            membership_hash: stamped(m),
            msg_type: MSG_CONTROL,
            ..Gcm::default()
        },
    };
    Some(Gcm {
        acks: non_empty(acks_to_bytes(&m.acks)),
        numbers: non_empty(numbers_to_bytes(&m.numbers)),
        introduced_at: m.introduced_at.as_ref().map(introduced_at_to_bytes),
        ..g
    })
}

fn stamped(m: &Message) -> Vec<u8> {
    m.membership_hash
        .clone()
        .unwrap_or_else(|| SENTINEL.to_vec())
}

/// The box for a member's `m`, a message made afresh in `version`.
pub fn box_of(m: &Message, version: u64) -> Option<Vec<u8>> {
    message_to_gcm(m, version).map(|g| frame(&g.to_bytes()))
}

/// A text message in `version`, as a member's content.
pub fn text_content(membership_hash: &[u8], s: &str, version: u64) -> Vec<u8> {
    Gcm {
        version,
        membership_hash: membership_hash.to_vec(),
        msg_type: MSG_TEXT,
        text: Some(s.to_owned()),
        ..Gcm::default()
    }
    .to_bytes()
}

/// A ping in `version`, as a member's content.
pub fn ping_content(membership_hash: &[u8], version: u64) -> Vec<u8> {
    Gcm {
        version,
        membership_hash: membership_hash.to_vec(),
        msg_type: MSG_PING,
        ..Gcm::default()
    }
    .to_bytes()
}

/// `(version, msg_type)` of the array form `cbor`, which [`Gcm::from_bytes`] refuses, when it is
/// a message of a newer version or of a type this client does not know.
pub fn unsupported(cbor: &[u8]) -> Option<(u64, u64)> {
    let (n, l) = read_array(cbor)?;
    if n < 3 {
        return None;
    }
    let (version, l) = read_uint(l)?;
    let (_, l) = read_bytes(l)?;
    let (msg_type, _) = read_uint(l)?;
    (version > CURRENT_VERSION || msg_type > MSG_PING).then_some((version, msg_type))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key repeated in a map keeps its last value, as a Python dict does.
    #[test]
    fn repeated_keys() {
        let mut m = Vec::new();
        push_header(&mut m, 5, 5);
        push_text(&mut m, "version");
        push_uint(&mut m, 3);
        push_text(&mut m, "membership_hash");
        push_bytes(&mut m, &[0; 32]);
        push_text(&mut m, "msg_type");
        push_uint(&mut m, MSG_FILE_UPLOAD);
        push_text(&mut m, "file_upload");
        push_uint(&mut m, 1);
        push_text(&mut m, "file_upload");
        push_uint(&mut m, 2);
        let g = Gcm::from_bytes(&m).unwrap();
        assert_eq!(
            g.other,
            vec![RawField {
                key: "file_upload".into(),
                raw: vec![2]
            }]
        );
        let mut r = Vec::new();
        push_header(&mut r, 5, 3);
        push_text(&mut r, "please_adds");
        push_header(&mut r, 4, 0);
        push_text(&mut r, "introducer");
        push_uint(&mut r, 1);
        push_text(&mut r, "introducer");
        push_uint(&mut r, 2);
        assert_eq!(crate::protocols::katzenqt1::wire::ReplyWho::from_bytes(&r).unwrap().introducer, Some(2));
    }
}
