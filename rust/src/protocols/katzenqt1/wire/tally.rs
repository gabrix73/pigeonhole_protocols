//! A tally message's body, msg_type 5 to 9: the map katzenqt's GroupChatTally writes,
//! `{survey_id, version, choice, crdt}` in that order, absent fields left out. A create or a
//! sync response carries a CRDT update in `crdt`, a sync request a state vector there; a vote
//! carries the sender's `choice`, slot id to availability; a close neither. What the CRDT holds
//! is the app's: this client only carries it.

use crate::prelude::*;
use crate::protocols::katzenqt1::wire::cbor::*;
use crate::protocols::katzenqt1::wire::gcm::{Gcm, RawField};

pub const MSG_TALLY_CREATE: u64 = 5;
pub const MSG_TALLY_VOTE: u64 = 6;
pub const MSG_TALLY_CLOSE: u64 = 7;
pub const MSG_TALLY_SYNC_REQ: u64 = 8;
pub const MSG_TALLY_SYNC_RESP: u64 = 9;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// The message's type, [`MSG_TALLY_CREATE`] to [`MSG_TALLY_SYNC_RESP`].
    pub kind: u64,
    pub survey_id: Vec<u8>,
    pub version: u64,
    /// A vote's slot ids and availabilities, in the order sent.
    pub choice: Option<Vec<(String, String)>>,
    pub crdt: Option<Vec<u8>>,
}

impl Tally {
    /// The body's CBOR.
    pub fn to_body(&self) -> Vec<u8> {
        let n = 2 + self.choice.is_some() as u64 + self.crdt.is_some() as u64;
        let mut out = Vec::new();
        push_header(&mut out, 5, n);
        push_text(&mut out, "survey_id");
        push_bytes(&mut out, &self.survey_id);
        push_text(&mut out, "version");
        push_uint(&mut out, self.version);
        if let Some(c) = &self.choice {
            push_text(&mut out, "choice");
            push_header(&mut out, 5, c.len() as u64);
            for (k, v) in c {
                push_text(&mut out, k);
                push_text(&mut out, v);
            }
        }
        if let Some(c) = &self.crdt {
            push_text(&mut out, "crdt");
            push_bytes(&mut out, c);
        }
        out
    }

    /// A body of type `kind`, which must have a survey id; keys katzenqt does not write are
    /// passed over.
    pub fn from_body(kind: u64, b: &[u8]) -> Option<Tally> {
        if !(MSG_TALLY_CREATE..=MSG_TALLY_SYNC_RESP).contains(&kind) {
            return None;
        }
        let (5, n, mut l) = read_header(b)? else {
            return None;
        };
        let mut t = Tally {
            kind,
            ..Tally::default()
        };
        for _ in 0..n {
            let (key, rest) = read_text(l)?;
            l = match key.as_str() {
                "survey_id" => {
                    let (v, rest) = read_bytes(rest)?;
                    t.survey_id = v;
                    rest
                }
                "version" => {
                    let (v, rest) = read_uint(rest)?;
                    t.version = v;
                    rest
                }
                "crdt" if is_null(rest) => &rest[1..],
                "crdt" => {
                    let (v, rest) = read_bytes(rest)?;
                    t.crdt = Some(v);
                    rest
                }
                "choice" if is_null(rest) => &rest[1..],
                "choice" => {
                    let (5, m, mut l) = read_header(rest)? else {
                        return None;
                    };
                    if m > l.len() as u64 {
                        return None;
                    }
                    let mut c = Vec::new();
                    for _ in 0..m {
                        let (k, rest) = read_text(l)?;
                        let (v, rest) = read_text(rest)?;
                        c.push((k, v));
                        l = rest;
                    }
                    t.choice = Some(c);
                    l
                }
                _ => skip_items(rest.len() + 1, 1, rest)?,
            };
        }
        (!t.survey_id.is_empty()).then_some(t)
    }

    /// The tally a message carries, if it is one.
    pub fn of(g: &Gcm) -> Option<Tally> {
        let raw = g.other.iter().find(|o| o.key == "tally")?;
        Tally::from_body(g.msg_type, &raw.raw)
    }
}

/// `t` in `version`, as a member's content.
pub fn tally_content(membership_hash: &[u8], t: &Tally, version: u64) -> Vec<u8> {
    Gcm {
        version,
        membership_hash: membership_hash.to_vec(),
        msg_type: t.kind,
        other: vec![RawField {
            key: "tally".into(),
            raw: t.to_body(),
        }],
        ..Gcm::default()
    }
    .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vote as katzenqt's cbor2 writes it: `cbor2.dumps([4, bytes(32), 6, {"survey_id":
    /// b"\x01\x02", "version": 3, "choice": {"s0": "yes"}}])`.
    #[test]
    fn katzenqt_vote() {
        let mut want = vec![0x84, 0x04, 0x58, 0x20];
        want.extend([0u8; 32]);
        want.extend([0x06, 0xa3]);
        want.extend(b"\x69survey_id\x42\x01\x02\x67version\x03\x66choice\xa1\x62s0\x63yes");
        let t = Tally {
            kind: MSG_TALLY_VOTE,
            survey_id: vec![1, 2],
            version: 3,
            choice: Some(vec![("s0".into(), "yes".into())]),
            crdt: None,
        };
        assert_eq!(tally_content(&[0; 32], &t, 4), want);
        assert_eq!(Tally::of(&Gcm::from_bytes(&want).unwrap()), Some(t));
    }

    #[test]
    fn round_trip_and_refusals() {
        let t = Tally {
            kind: MSG_TALLY_CREATE,
            survey_id: vec![9; 16],
            version: 0,
            choice: None,
            crdt: Some(vec![1, 2, 3]),
        };
        for v in [3, 4, 5] {
            let g = Gcm::from_bytes(&tally_content(&[0; 32], &t, v)).unwrap();
            assert_eq!(Tally::of(&g), Some(t.clone()), "version {v}");
        }
        assert_eq!(Tally::from_body(MSG_TALLY_CREATE, &[0xa0]), None, "no survey id");
        assert_eq!(Tally::from_body(4, &t.to_body()), None, "not a tally type");
        assert_eq!(Tally::from_body(MSG_TALLY_CREATE, &t.to_body()[..5]), None, "cut short");
    }
}
