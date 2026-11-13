//! The reply to a new member: what an introducer seals into a contact voucher's reply. Its
//! roster in order, each member as a display name and a read cap starting where the new member
//! is to start reading, then the rest of a JoinReply, each member written as its place in that
//! list. Written as the array [please_adds, rosters, introductions, introducer, newcomer] with
//! trailing nulls left out; katzenqt's GroupChatReplyWho map, version 3, is read as well.

use crate::prelude::*;
use crate::protocols::katzenqt1::wire::term::Term;
use crate::protocols::katzenqt1::wire::{INDEX_SIZE, READ_CAP_SIZE, ROSTER_MAX, key_of, start_of};

const MAX_NAME_CHARS: usize = 30;
const KEYS: [&str; 5] = ["please_adds", "rosters", "introductions", "introducer", "newcomer"];

/// A member's read cap and the index the new member starts reading it at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub read_cap: Vec<u8>,
    pub start: Vec<u8>,
}

/// A roster index and the place of the member at it, `None` when unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RosterEntry {
    pub index: usize,
    pub place: Option<usize>,
}

pub type Roster = Vec<RosterEntry>;

/// An Introduction a new member is told of: the introducer's place, its box and the introduced
/// member's place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntroAt {
    pub by: usize,
    pub index: Vec<u8>,
    pub member: usize,
}

/// What an introducer hands a new member. Members are named by their place in `members`, the
/// introducer's roster; the new member takes place `newcomer`. A `None` member is a slot not
/// filled, a `None` roster one unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinReply {
    pub members: Vec<Option<Member>>,
    pub rosters: Vec<Option<Roster>>,
    pub introductions: Vec<IntroAt>,
    pub introducer: usize,
    pub newcomer: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PleaseAdd {
    pub name: String,
    pub read_cap: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplyWho {
    pub please_adds: Vec<Option<PleaseAdd>>,
    pub rosters: Option<Vec<Option<Roster>>>,
    pub introductions: Option<Vec<IntroAt>>,
    pub introducer: Option<usize>,
    pub newcomer: Option<usize>,
}

impl ReplyWho {
    /// The reply for `r`, naming each member by `name`; a member with no name takes no place, as
    /// katzenqt leaves out a member it does not know.
    pub fn from_join_reply(r: &JoinReply, name: impl Fn(&[u8]) -> Option<String>) -> ReplyWho {
        ReplyWho {
            please_adds: r
                .members
                .iter()
                .map(|m| {
                    let m = m.as_ref()?;
                    let key = key_of(&m.read_cap);
                    let n = name(key)?;
                    Some(PleaseAdd {
                        name: n,
                        read_cap: [key, &m.start].concat(),
                    })
                })
                .collect(),
            rosters: Some(r.rosters.clone()),
            introductions: Some(r.introductions.clone()),
            introducer: Some(r.introducer),
            newcomer: Some(r.newcomer),
        }
    }

    /// The JoinReply a reply carries, or `None` when it carries no rosters or cannot be read.
    pub fn to_join_reply(&self) -> Option<JoinReply> {
        let places = self.please_adds.len();
        let rosters = self.rosters.as_ref()?;
        let (introducer, newcomer) = (self.introducer?, self.newcomer?);
        if newcomer != places || !(introducer < places && places < ROSTER_MAX) {
            return None;
        }
        if self.please_adds[introducer].is_none() || rosters.len() != places {
            return None;
        }
        let keys: Vec<&[u8]> = self
            .please_adds
            .iter()
            .flatten()
            .map(|p| key_of(&p.read_cap))
            .collect();
        for (i, k) in keys.iter().enumerate() {
            if keys[..i].contains(k) {
                return None;
            }
        }
        let ok = rosters
            .iter()
            .flatten()
            .flatten()
            .all(|e| e.index < ROSTER_MAX && e.place.is_none_or(|p| p < places));
        if !ok {
            return None;
        }
        Some(JoinReply {
            members: self
                .please_adds
                .iter()
                .map(|p| {
                    p.as_ref().map(|p| Member {
                        read_cap: p.read_cap.clone(),
                        start: start_of(&p.read_cap).to_vec(),
                    })
                })
                .collect(),
            rosters: rosters.clone(),
            introductions: self
                .introductions
                .iter()
                .flatten()
                .filter(|i| i.by < places && i.member < places && i.index.len() == INDEX_SIZE)
                .cloned()
                .collect(),
            introducer,
            newcomer,
        })
    }

    /// The JoinReply of a reply that carries no rosters, as katzenqt sends for a conversation
    /// that keeps none: the members it names, the introducer first, with every roster unknown.
    /// `None` when the reply carries rosters or cannot be read.
    pub fn without_rosters(&self) -> Option<JoinReply> {
        if self.rosters.is_some() {
            return None;
        }
        let members: Vec<&PleaseAdd> = self.please_adds.iter().flatten().collect();
        let places = members.len();
        if !(1..ROSTER_MAX).contains(&places) {
            return None;
        }
        let keys: Vec<&[u8]> = members.iter().map(|p| key_of(&p.read_cap)).collect();
        for (i, k) in keys.iter().enumerate() {
            if keys[..i].contains(k) {
                return None;
            }
        }
        Some(JoinReply {
            members: members
                .iter()
                .map(|p| {
                    Some(Member {
                        read_cap: p.read_cap.clone(),
                        start: start_of(&p.read_cap).to_vec(),
                    })
                })
                .collect(),
            rosters: vec![None; places],
            introductions: Vec::new(),
            introducer: 0,
            newcomer: places,
        })
    }

    /// The five elements, null where absent; a please_add as a map in the map form.
    fn parts(&self, map: bool) -> Vec<Term> {
        let text = |s: &str| Term::Text(s.to_owned());
        let please_add = |p: &PleaseAdd| {
            if map {
                Term::Map(vec![
                    (text("display_name"), text(&p.name)),
                    (text("read_cap"), Term::Bytes(p.read_cap.clone())),
                ])
            } else {
                Term::List(vec![text(&p.name), Term::Bytes(p.read_cap.clone())])
            }
        };
        let roster = |r: &Roster| {
            Term::List(
                r.iter()
                    .map(|e| {
                        Term::List(vec![
                            Term::nat(e.index),
                            e.place.map_or(Term::Null, Term::nat),
                        ])
                    })
                    .collect(),
            )
        };
        let intro = |i: &IntroAt| {
            Term::List(vec![
                Term::nat(i.by),
                Term::Bytes(i.index.clone()),
                Term::nat(i.member),
            ])
        };
        let list = |items: Vec<Term>| Term::List(items);
        vec![
            list(
                self.please_adds
                    .iter()
                    .map(|p| p.as_ref().map_or(Term::Null, please_add))
                    .collect(),
            ),
            self.rosters.as_ref().map_or(Term::Null, |rs| {
                list(
                    rs.iter()
                        .map(|r| r.as_ref().map_or(Term::Null, roster))
                        .collect(),
                )
            }),
            self.introductions
                .as_ref()
                .map_or(Term::Null, |is| list(is.iter().map(intro).collect())),
            self.introducer.map_or(Term::Null, Term::nat),
            self.newcomer.map_or(Term::Null, Term::nat),
        ]
    }

    /// The array form.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut a = self.parts(false);
        while a.len() > 1 && a.last().is_some_and(Term::is_null) {
            a.pop();
        }
        let mut out = Vec::new();
        Term::List(a).write(&mut out);
        out
    }

    /// The map form, version 3.
    pub fn to_map_bytes(&self) -> Vec<u8> {
        let kvs = KEYS
            .iter()
            .zip(self.parts(true))
            .filter(|(_, v)| !v.is_null())
            .map(|(k, v)| (Term::Text((*k).to_owned()), v))
            .collect();
        let mut out = Vec::new();
        Term::Map(kvs).write(&mut out);
        out
    }

    /// A reply in either form, or `None` when it cannot be read.
    pub fn from_bytes(b: &[u8]) -> Option<ReplyWho> {
        let t = Term::read(b)?;
        let (map, parts): (bool, Vec<Option<&Term>>) = match &t {
            Term::List(a) if (1..=5).contains(&a.len()) => {
                (false, (0..5).map(|i| a.get(i)).collect())
            }
            Term::Map(_) => (true, KEYS.iter().map(|k| t.field(k)).collect()),
            _ => return None,
        };
        let part = |i: usize| parts[i].filter(|v| !v.is_null());
        let Some(Term::List(pas)) = part(0) else {
            return None;
        };
        let please_adds = pas
            .iter()
            .map(|e| {
                if e.is_null() {
                    Some(None)
                } else {
                    read_please_add(e, map).map(Some)
                }
            })
            .collect::<Option<Vec<_>>>()?;
        let rosters = match part(1) {
            None => None,
            Some(Term::List(rs)) => Some(
                rs.iter()
                    .map(|r| {
                        if r.is_null() {
                            Some(None)
                        } else {
                            read_roster(r).map(Some)
                        }
                    })
                    .collect::<Option<Vec<_>>>()?,
            ),
            Some(_) => return None,
        };
        let introductions = match part(2) {
            None => None,
            Some(Term::List(is)) => Some(is.iter().map(read_intro_at).collect::<Option<Vec<_>>>()?),
            Some(_) => return None,
        };
        let opt_nat = |i: usize| match part(i) {
            None => Some(None),
            Some(v) => v.as_nat().map(Some),
        };
        Some(ReplyWho {
            please_adds,
            rosters,
            introductions,
            introducer: opt_nat(3)?,
            newcomer: opt_nat(4)?,
        })
    }
}

fn read_please_add(t: &Term, map: bool) -> Option<PleaseAdd> {
    let (name, read_cap) = match (map, t) {
        (true, _) => (t.field("display_name")?, t.field("read_cap")?),
        (false, Term::List(p)) if p.len() == 2 => (&p[0], &p[1]),
        _ => return None,
    };
    let (Term::Text(name), Term::Bytes(read_cap)) = (name, read_cap) else {
        return None;
    };
    let chars = name.chars().count();
    if !(1..=MAX_NAME_CHARS).contains(&chars) || read_cap.len() != READ_CAP_SIZE {
        return None;
    }
    Some(PleaseAdd {
        name: name.clone(),
        read_cap: read_cap.clone(),
    })
}

fn read_roster(t: &Term) -> Option<Roster> {
    let Term::List(es) = t else { return None };
    es.iter()
        .map(|e| match e {
            Term::List(p) if p.len() == 2 => Some(RosterEntry {
                index: p[0].as_nat()?,
                place: if p[1].is_null() {
                    None
                } else {
                    Some(p[1].as_nat()?)
                },
            }),
            _ => None,
        })
        .collect()
}

fn read_intro_at(t: &Term) -> Option<IntroAt> {
    match t {
        Term::List(p) if p.len() == 3 => match &p[1] {
            Term::Bytes(index) => Some(IntroAt {
                by: p[0].as_nat()?,
                index: index.clone(),
                member: p[2].as_nat()?,
            }),
            _ => None,
        },
        _ => None,
    }
}
