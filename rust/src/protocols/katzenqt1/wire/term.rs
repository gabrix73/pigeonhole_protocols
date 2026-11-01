//! A general CBOR item, as the reply to a new member uses: reading accepts every well-formed item
//! (indefinite lengths, tags, bignums, floats and simple values), and writing gives definite
//! lengths in shortest form.

use crate::protocols::katzenqt1::wire::cbor::{push_bytes, push_header, push_text, push_uint, read_header, read_string};

const MAX_DEPTH: usize = 1000;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Term {
    /// An integer: whether it is negative, and its magnitude (for a negative one, the magnitude
    /// less one), saturated where it does not fit.
    Int {
        negative: bool,
        value: u64,
    },
    Bytes(Vec<u8>),
    Text(String),
    List(Vec<Term>),
    Map(Vec<(Term, Term)>),
    Tag,
    Null,
    Other,
}

impl Term {
    pub(crate) fn nat(n: usize) -> Term {
        Term::Int {
            negative: false,
            value: n as u64,
        }
    }

    /// A natural number; one too large saturates, which every bound it is checked against
    /// refuses.
    pub(crate) fn as_nat(&self) -> Option<usize> {
        match self {
            Term::Int {
                negative: false,
                value,
            } => Some((*value).min(i32::MAX as u64) as usize),
            _ => None,
        }
    }

    pub(crate) fn is_null(&self) -> bool {
        matches!(self, Term::Null)
    }

    /// The value of the last entry under `key`.
    pub(crate) fn field(&self, key: &str) -> Option<&Term> {
        match self {
            Term::Map(kvs) => kvs
                .iter()
                .rev()
                .find(|(k, _)| matches!(k, Term::Text(s) if s == key))
                .map(|(_, v)| v),
            _ => None,
        }
    }

    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        match self {
            Term::Int {
                negative: false,
                value,
            } => push_uint(out, *value),
            Term::Int {
                negative: true,
                value,
            } => push_header(out, 1, *value),
            Term::Bytes(b) => push_bytes(out, b),
            Term::Text(s) => push_text(out, s),
            Term::List(l) => {
                push_header(out, 4, l.len() as u64);
                for t in l {
                    t.write(out);
                }
            }
            Term::Map(kvs) => {
                push_header(out, 5, kvs.len() as u64);
                for (k, v) in kvs {
                    k.write(out);
                    v.write(out);
                }
            }
            _ => out.push(0xf6),
        }
    }

    /// One item; what follows it is ignored.
    pub(crate) fn read(b: &[u8]) -> Option<Term> {
        read_term(b, MAX_DEPTH).map(|(t, _)| t)
    }
}

/// The value bignum bytes spell, saturated.
fn bignum(b: &[u8]) -> u64 {
    let b = &b[b.iter().take_while(|&&c| c == 0).count()..];
    if b.len() > 8 {
        return u64::MAX;
    }
    b.iter().fold(0u64, |n, &c| n << 8 | c as u64)
}

fn read_term(l: &[u8], depth: usize) -> Option<(Term, &[u8])> {
    let &first = l.first()?;
    let (major, ai) = (first >> 5, first & 31);
    let indef = ai == 31;
    if indef && matches!(major, 0 | 1 | 6) || (28..31).contains(&ai) {
        return None;
    }
    if matches!(major, 4..=6) && depth == 0 {
        return None;
    }
    let (n, rest) = if indef {
        (0, &l[1..])
    } else {
        read_header(l).map(|(_, n, r)| (n, r))?
    };
    match major {
        0 => Some((
            Term::Int {
                negative: false,
                value: n,
            },
            rest,
        )),
        1 => Some((
            Term::Int {
                negative: true,
                value: n,
            },
            rest,
        )),
        2 | 3 => {
            let (data, rest) = if indef {
                let mut data = Vec::new();
                let mut rest = rest;
                loop {
                    let (&b, after) = rest.split_first()?;
                    if b == 0xff {
                        rest = after;
                        break;
                    }
                    let (chunk, after) = read_string(major, rest)?;
                    if major == 3 {
                        std::str::from_utf8(chunk).ok()?;
                    }
                    data.extend_from_slice(chunk);
                    rest = after;
                }
                (data, rest)
            } else {
                if n > rest.len() as u64 {
                    return None;
                }
                let (d, r) = rest.split_at(n as usize);
                (d.to_vec(), r)
            };
            if major == 2 {
                Some((Term::Bytes(data), rest))
            } else {
                Some((Term::Text(String::from_utf8(data).ok()?), rest))
            }
        }
        4 | 5 => {
            let mut rest = rest;
            let mut items = Vec::new();
            let mut i = 0;
            loop {
                if indef {
                    if *rest.first()? == 0xff {
                        rest = &rest[1..];
                        break;
                    }
                } else if i == n {
                    break;
                }
                let (a, r) = read_term(rest, depth - 1)?;
                rest = r;
                if major == 5 {
                    let (b, r) = read_term(rest, depth - 1)?;
                    rest = r;
                    items.push((a, b));
                } else {
                    items.push((a, Term::Null));
                }
                i += 1;
            }
            if major == 4 {
                Some((
                    Term::List(items.into_iter().map(|(a, _)| a).collect()),
                    rest,
                ))
            } else {
                Some((Term::Map(items), rest))
            }
        }
        6 => {
            if (n == 2 || n == 3)
                && ai < 24
                && let Some((b, after)) = read_string(2, rest)
            {
                return Some((
                    Term::Int {
                        negative: n == 3,
                        value: bignum(b),
                    },
                    after,
                ));
            }
            let (_, after) = read_term(rest, depth - 1)?;
            Some((Term::Tag, after))
        }
        _ => {
            if indef {
                return None;
            }
            Some((if ai == 22 { Term::Null } else { Term::Other }, rest))
        }
    }
}
