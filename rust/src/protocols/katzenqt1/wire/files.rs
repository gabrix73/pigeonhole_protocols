//! A file travels as katzenqt's file_upload: a map of its bytes, its type and its name. A message
//! too long for one box is written to a substream of its own, `C` chunks then an `F` chunk, and
//! the member's stream gets an `I` box: the number of chunks, four bytes big-endian, then the
//! substream's read cap.

use crate::protocols::katzenqt1::wire::cbor::*;
use crate::protocols::katzenqt1::wire::{CURRENT_VERSION, Gcm, MSG_FILE_UPLOAD, MSG_TEXT, RawField};

/// The largest file sent or fetched.
pub const MAX_FILE: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileUpload {
    pub payload: Vec<u8>,
    /// image/png, audio/opus or arbitrary, as katzenqt tags it.
    pub filetype: String,
    pub basename: String,
}

impl FileUpload {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_header(&mut out, 5, 3);
        push_text(&mut out, "payload");
        push_bytes(&mut out, &self.payload);
        push_text(&mut out, "filetype");
        push_text(&mut out, &self.filetype);
        push_text(&mut out, "basename");
        push_text(&mut out, &self.basename);
        out
    }

    fn from_bytes(raw: &[u8]) -> Option<FileUpload> {
        let (major, n, mut l) = read_header(raw)?;
        if major != 5 {
            return None;
        }
        let (mut p, mut t, mut b) = (None, None, None);
        for _ in 0..n {
            let (k, rest) = read_text(l)?;
            l = match k.as_str() {
                "payload" => {
                    let (v, rest) = read_bytes(rest)?;
                    p = Some(v);
                    rest
                }
                "filetype" | "basename" => {
                    let (v, rest) = read_text(rest)?;
                    if k == "filetype" {
                        t = Some(v)
                    } else {
                        b = Some(v)
                    }
                    rest
                }
                _ => skip_items(rest.len() + 1, 1, rest)?,
            };
        }
        Some(FileUpload {
            payload: p?,
            filetype: t?,
            basename: b?,
        })
    }
}

/// The file a message carries.
pub fn file_of(g: &Gcm) -> Option<FileUpload> {
    if g.msg_type != MSG_FILE_UPLOAD {
        return None;
    }
    FileUpload::from_bytes(&g.other.iter().find(|o| o.key == "file_upload")?.raw)
}

/// A file, as a member's content.
pub fn file_content(membership_hash: &[u8], f: &FileUpload) -> Vec<u8> {
    Gcm {
        version: CURRENT_VERSION,
        membership_hash: membership_hash.to_vec(),
        msg_type: MSG_FILE_UPLOAD,
        other: vec![RawField {
            key: "file_upload".into(),
            raw: f.to_bytes(),
        }],
        ..Gcm::default()
    }
    .to_bytes()
}

/// A name from elsewhere as a file may be called here: printable ASCII from katzenqt's list, no
/// leading dots, at most 200 characters.
pub fn safe_name(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || " ._-+()[]".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let s = s.trim_start_matches('.');
    if s.is_empty() {
        return "unnamed".into();
    }
    s.chars().take(200).collect()
}

/// The type katzenqt tags a file with, from its name.
pub fn filetype_of(name: &str) -> &'static str {
    let parts: Vec<&str> = name.split('.').collect();
    let ext = if parts.len() < 2 {
        String::new()
    } else {
        parts[parts.len() - 1].to_lowercase()
    };
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "opus" => "audio/opus",
        _ => "arbitrary",
    }
}

// A file's bytes are kept out of a message as it is read and written: the message carries an
// empty payload, and the bytes are spliced in as it is written and out as it is read.

/// An item's major type, its argument, and where what follows its header begins.
fn header_at(b: &[u8], pos: usize) -> Option<(u8, u64, usize)> {
    let (major, n, rest) = read_header(b.get(pos..)?)?;
    Some((major, n, b.len() - rest.len()))
}

/// Where the item at `pos` ends.
fn skip_at(b: &[u8], fuel: usize, pos: usize) -> Option<usize> {
    let rest = skip_items(fuel, 1, b.get(pos..)?)?;
    Some(b.len() - rest.len())
}

/// Where the value of the entry under `key` of the map at `pos` begins.
fn lookup_at(b: &[u8], pos: usize, key: &str) -> Option<usize> {
    let (major, n, mut at) = header_at(b, pos)?;
    if major != 5 {
        return None;
    }
    for _ in 0..n {
        let (name, rest) = read_text(&b[at..])?;
        let value = b.len() - rest.len();
        if name == key {
            return Some(value);
        }
        at = skip_at(b, b.len() + 1, value)?;
    }
    None
}

/// Where the file's bytes are in a message: the payload item's start and end.
fn payload_span(cbor: &[u8]) -> Option<(usize, usize)> {
    let upload = lookup_at(cbor, 0, "file_upload")?;
    let start = lookup_at(cbor, upload, "payload")?;
    if header_at(cbor, start)?.0 != 2 {
        return None;
    }
    Some((start, skip_at(cbor, 1, start)?))
}

/// A message with the file's bytes taken out, and the bytes.
pub fn take_payload(cbor: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (start, stop) = payload_span(cbor)?;
    let (_, _, data) = header_at(cbor, start)?;
    let without = [&cbor[..start], &[0x40], &cbor[stop..]].concat();
    Some((without, cbor[data..stop].to_vec()))
}

/// A message with `payload` put in place of the file's bytes.
pub fn put_payload(cbor: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    let (start, stop) = payload_span(cbor)?;
    let mut out = cbor[..start].to_vec();
    push_bytes(&mut out, payload);
    out.extend_from_slice(&cbor[stop..]);
    Some(out)
}

/// How many boxes of `max` bytes a message of `n` bytes takes in a substream.
pub fn chunk_count(n: usize, max: usize) -> usize {
    (n + (max - 2)) / (max - 1)
}

/// The most boxes of `max` bytes a substream is sent or fetched in: a message of `MAX_FILE + max`
/// bytes, the most a sender cuts.
pub fn max_chunks(max: usize) -> usize {
    chunk_count(MAX_FILE + max, max)
}

/// The `i`th box of `blob`'s substream.
pub fn substream_box(blob: &[u8], max: usize, i: usize) -> Vec<u8> {
    let size = max - 1;
    let tag = if i + 1 < chunk_count(blob.len(), max) {
        b'C'
    } else {
        b'F'
    };
    let (lo, hi) = ((i * size).min(blob.len()), ((i + 1) * size).min(blob.len()));
    [&[tag], &blob[lo..hi]].concat()
}

/// The `I` box naming a substream of `total` boxes.
pub fn indirection(total: usize, read_cap: &[u8]) -> Vec<u8> {
    let mut out = b"I".to_vec();
    out.extend((total as u32).to_be_bytes());
    out.extend_from_slice(read_cap);
    out
}

/// The message a substream's boxes hold, once its `F` box is among them.
pub fn assemble(boxes: &[Vec<u8>]) -> Option<Vec<u8>> {
    let (last, rest) = boxes.split_last()?;
    if last.first() != Some(&b'F') || rest.iter().any(|b| b.first() != Some(&b'C')) {
        return None;
    }
    Some(boxes.iter().flat_map(|b| b[1..].iter().copied()).collect())
}

/// How a message's content reads.
pub fn text_of(content: &[u8]) -> String {
    match Gcm::from_bytes(content) {
        None => "[a message that cannot be read]".into(),
        Some(g) if g.msg_type == MSG_TEXT => g.text.unwrap_or_default(),
        Some(g) if g.msg_type == MSG_FILE_UPLOAD => "[a file that cannot be read]".into(),
        Some(_) => "[a message that cannot be shown]".into(),
    }
}
