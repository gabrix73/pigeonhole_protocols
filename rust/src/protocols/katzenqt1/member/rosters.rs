//! Rosters with explicit numbering: every roster index is announced explicitly, so a missed
//! message leaves an index unresolved and never shifts others. A roster that began as its
//! introducer's reads its early entries from that roster.

use std::collections::HashSet;

use indexmap::IndexMap;

use crate::protocols::katzenqt1::member::{At, Key};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub key: Option<Key>,
    /// The start of the member's key, as a Numbers field names it.
    pub prefix: Option<Vec<u8>>,
}

/// A member's roster began as `introducer`'s, through index `top`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Started {
    pub introducer: Key,
    pub top: usize,
}

pub type Roster = IndexMap<usize, Entry>;

/// An index an owner assigned and to whom, if this member can tell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownEntry {
    pub index: usize,
    pub key: Option<Key>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rosters {
    pub entries: IndexMap<Key, Roster>,
    pub started: IndexMap<Key, Started>,
    /// The members introduced, by Introduction.
    pub introductions: IndexMap<At, Key>,
    /// Every member whose key this member knows: whom a prefix can name.
    pub keys: Vec<Key>,
    known: HashSet<Key>,
}

impl Rosters {
    pub(crate) fn learn(&mut self, k: &Key) {
        if self.known.len() != self.keys.len() {
            self.known = self.keys.iter().cloned().collect();
        }
        if self.known.insert(k.clone()) {
            self.keys.push(k.clone());
        }
    }

    /// The one member known whose key starts with `p`.
    fn named(&self, p: &[u8]) -> Option<Key> {
        let mut found = self.keys.iter().filter(|k| k.starts_with(p));
        let k = found.next()?;
        found.next().is_none().then(|| k.clone())
    }

    /// Start a group: every founder's roster is all founders in ascending order of key.
    pub(crate) fn found(&mut self, founders: &[Key]) {
        let mut sorted = founders.to_vec();
        sorted.sort();
        let roster: Roster = sorted
            .into_iter()
            .enumerate()
            .map(|(i, k)| {
                (
                    i,
                    Entry {
                        key: Some(k),
                        prefix: None,
                    },
                )
            })
            .collect();
        for f in founders {
            self.entries.insert(f.clone(), roster.clone());
            self.learn(f);
        }
    }

    /// Who `owner` numbered `index`, following where rosters began, if this member can tell.
    pub(crate) fn resolve<'a>(&'a self, mut owner: &'a Key, index: usize) -> Option<Key> {
        let mut fuel = self.started.len() + 1;
        let mut seen: Vec<&Key> = Vec::new();
        loop {
            if let Some(e) = self.entries.get(owner).and_then(|r| r.get(&index)) {
                return match (&e.key, &e.prefix) {
                    (Some(k), _) => Some(k.clone()),
                    (None, Some(p)) if !p.is_empty() => self.named(p),
                    _ => None,
                };
            }
            if fuel == 0 {
                return None;
            }
            fuel -= 1;
            let s = self.started.get(owner)?;
            if index > s.top || seen.contains(&owner) {
                return None;
            }
            seen.push(owner);
            owner = &s.introducer;
        }
    }

    fn indexes(&self, fuel: usize, seen: &mut Vec<Key>, owner: &Key) -> Vec<usize> {
        let mut own: Vec<usize> = self
            .entries
            .get(owner)
            .map(|r| r.keys().copied().collect())
            .unwrap_or_default();
        let Some(s) = self.started.get(owner) else {
            return own;
        };
        if fuel == 0 || seen.contains(owner) {
            return own;
        }
        seen.push(owner.clone());
        own.extend(
            self.indexes(fuel - 1, seen, &s.introducer)
                .into_iter()
                .filter(|&i| i <= s.top),
        );
        own
    }

    /// Every index `owner` is known to have assigned, in ascending order, and to whom.
    pub fn known(&self, owner: &Key) -> Vec<KnownEntry> {
        let mut is = self.indexes(self.started.len() + 1, &mut Vec::new(), owner);
        is.sort();
        is.dedup();
        is.into_iter()
            .map(|index| KnownEntry {
                index,
                key: self.resolve(owner, index),
            })
            .collect()
    }

    pub(crate) fn size(&self, owner: &Key) -> usize {
        self.known(owner).last().map_or(0, |e| e.index + 1)
    }

    pub(crate) fn index_of(&self, owner: &Key, member: &Key) -> Option<usize> {
        self.known(owner)
            .into_iter()
            .find(|e| e.key.as_ref() == Some(member))
            .map(|e| e.index)
    }

    /// `owner` numbered `index` as `entry` says; an entry already held is kept.
    pub(crate) fn number(&mut self, owner: &Key, index: usize, entry: Entry) {
        self.entries
            .entry(owner.clone())
            .or_default()
            .entry(index)
            .or_insert(entry);
    }

    /// Forget `member`'s key, keeping every place it holds, under `token`. A place named by a
    /// prefix is `member`'s only if the prefix names no other member known. `token` stands in a
    /// place, never among the keys a prefix can name.
    pub(crate) fn retire(&mut self, member: &Key, token: &Key) {
        let renamed = |k: &Key| {
            if k == member {
                token.clone()
            } else {
                k.clone()
            }
        };
        let mut entries: IndexMap<Key, Roster> = self
            .entries
            .iter()
            .map(|(owner, ro)| {
                let nr = ro
                    .iter()
                    .map(|(&i, e)| {
                        let hit = e.key.as_ref() == Some(member)
                            || e.prefix.as_ref().is_some_and(|p| {
                                !p.is_empty() && self.named(p).as_ref() == Some(member)
                            });
                        (
                            i,
                            if hit {
                                Entry {
                                    key: Some(token.clone()),
                                    prefix: None,
                                }
                            } else {
                                e.clone()
                            },
                        )
                    })
                    .collect();
                (owner.clone(), nr)
            })
            .collect();
        if let Some(ro) = entries.shift_remove(member) {
            entries.insert(token.clone(), ro);
        }
        let mut started = IndexMap::new();
        for (o, s) in &self.started {
            started.insert(
                renamed(o),
                Started {
                    introducer: renamed(&s.introducer),
                    top: s.top,
                },
            );
        }
        let mut introductions = IndexMap::new();
        for (a, k) in &self.introductions {
            introductions.insert(
                At {
                    introducer: renamed(&a.introducer),
                    index: a.index.clone(),
                },
                renamed(k),
            );
        }
        let keys = self.keys.iter().filter(|k| *k != member).cloned().collect();
        *self = Rosters {
            entries,
            started,
            introductions,
            keys,
            known: HashSet::new(),
        };
    }
}
