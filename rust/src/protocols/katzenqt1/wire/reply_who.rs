//! The reply to a new member: what an introducer seals into a contact voucher's reply, as
//! katzenqt's GroupChatReplyWho. Its roster in order, each member as a display name and a read
//! cap starting where the new member is to start reading, then the rest of a JoinReply, each
//! member written as its place in that list.

use crate::protocols::katzenqt1::wire::term::Term;
use crate::protocols::katzenqt1::wire::{INDEX_SIZE, READ_CAP_SIZE, ROSTER_MAX, key_of, start_of};

const MAX_NAME_CHARS: usize = 30;

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

    fn term(&self) -> Term {
        let text = |s: &str| Term::Text(s.to_owned());
        let mut kvs = vec![(
            text("please_adds"),
            Term::List(
                self.please_adds
                    .iter()
                    .map(|p| match p {
                        None => Term::Null,
                        Some(p) => Term::Map(vec![
                            (text("display_name"), text(&p.name)),
                            (text("read_cap"), Term::Bytes(p.read_cap.clone())),
                        ]),
                    })
                    .collect(),
            ),
        )];
        if let Some(rs) = &self.rosters {
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
            kvs.push((
                text("rosters"),
                Term::List(
                    rs.iter()
                        .map(|r| r.as_ref().map_or(Term::Null, roster))
                        .collect(),
                ),
            ));
        }
        if let Some(is) = &self.introductions {
            kvs.push((
                text("introductions"),
                Term::List(
                    is.iter()
                        .map(|i| {
                            Term::List(vec![
                                Term::nat(i.by),
                                Term::Bytes(i.index.clone()),
                                Term::nat(i.member),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        if let Some(n) = self.introducer {
            kvs.push((text("introducer"), Term::nat(n)));
        }
        if let Some(n) = self.newcomer {
            kvs.push((text("newcomer"), Term::nat(n)));
        }
        Term::Map(kvs)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.term().write(&mut out);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Option<ReplyWho> {
        let t = Term::read(b)?;
        if !matches!(t, Term::Map(_)) {
            return None;
        }
        let Term::List(pas) = t.field("please_adds")? else {
            return None;
        };
        let please_adds = pas
            .iter()
            .map(|e| {
                if e.is_null() {
                    Some(None)
                } else {
                    read_please_add(e).map(Some)
                }
            })
            .collect::<Option<Vec<_>>>()?;
        let rosters = match t.field("rosters") {
            None | Some(Term::Null) => None,
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
        let introductions = match t.field("introductions") {
            None | Some(Term::Null) => None,
            Some(Term::List(is)) => Some(is.iter().map(read_intro_at).collect::<Option<Vec<_>>>()?),
            Some(_) => return None,
        };
        let opt_nat = |k: &str| match t.field(k) {
            None | Some(Term::Null) => Some(None),
            Some(v) => v.as_nat().map(Some),
        };
        Some(ReplyWho {
            please_adds,
            rosters,
            introductions,
            introducer: opt_nat("introducer")?,
            newcomer: opt_nat("newcomer")?,
        })
    }
}

fn read_please_add(t: &Term) -> Option<PleaseAdd> {
    let (Term::Text(name), Term::Bytes(read_cap)) =
        (t.field("display_name")?, t.field("read_cap")?)
    else {
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
