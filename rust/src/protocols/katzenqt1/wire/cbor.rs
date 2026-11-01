//! The CBOR a group chat message uses: definite-length unsigned integers, byte strings, text
//! strings and maps, as Python's cbor2 writes them, each header in its shortest form. Reading
//! also skips any other well-formed item, so that a field this client does not interpret can be
//! passed over or kept as it came.

pub(crate) fn push_header(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n < 1 << 8 {
        out.extend([m | 24, n as u8]);
    } else if n < 1 << 16 {
        out.push(m | 25);
        out.extend((n as u16).to_be_bytes());
    } else if n < 1 << 32 {
        out.push(m | 26);
        out.extend((n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend(n.to_be_bytes());
    }
}

pub(crate) fn push_uint(out: &mut Vec<u8>, n: u64) {
    push_header(out, 0, n);
}

pub(crate) fn push_bytes(out: &mut Vec<u8>, b: &[u8]) {
    push_header(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

pub(crate) fn push_text(out: &mut Vec<u8>, s: &str) {
    push_header(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// An item's major type, its argument, and what follows the header. Indefinite lengths and the
/// reserved additional information values are refused.
pub(crate) fn read_header(l: &[u8]) -> Option<(u8, u64, &[u8])> {
    let (&b, rest) = l.split_first()?;
    let ai = b & 31;
    if ai < 24 {
        return Some((b >> 5, ai as u64, rest));
    }
    if ai >= 28 {
        return None;
    }
    let k = 1usize << (ai - 24);
    if rest.len() < k {
        return None;
    }
    let n = rest[..k].iter().fold(0u64, |n, &c| n << 8 | c as u64);
    Some((b >> 5, n, &rest[k..]))
}

pub(crate) fn read_uint(l: &[u8]) -> Option<(u64, &[u8])> {
    match read_header(l)? {
        (0, n, rest) => Some((n, rest)),
        _ => None,
    }
}

pub(crate) fn read_string(major: u8, l: &[u8]) -> Option<(&[u8], &[u8])> {
    let (m, n, rest) = read_header(l)?;
    if m != major || n > rest.len() as u64 {
        return None;
    }
    Some(rest.split_at(n as usize))
}

pub(crate) fn read_bytes(l: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    read_string(2, l).map(|(b, rest)| (b.to_vec(), rest))
}

pub(crate) fn read_text(l: &[u8]) -> Option<(String, &[u8])> {
    let (b, rest) = read_string(3, l)?;
    Some((std::str::from_utf8(b).ok()?.to_owned(), rest))
}

pub(crate) fn is_null(l: &[u8]) -> bool {
    l.first() == Some(&0xf6)
}

/// Pass over `count` well-formed items. `fuel` bounds the items visited; one per byte of input is
/// always enough, since every item takes at least one byte.
pub(crate) fn skip_items(mut fuel: usize, mut count: u64, mut l: &[u8]) -> Option<&[u8]> {
    while count > 0 {
        if fuel == 0 {
            return None;
        }
        fuel -= 1;
        let (major, n, rest) = read_header(l)?;
        l = match major {
            0 | 1 | 7 => rest,
            2 | 3 => {
                if n > rest.len() as u64 {
                    return None;
                }
                &rest[n as usize..]
            }
            4 => skip_items(fuel, n, rest)?,
            5 => {
                if n > rest.len() as u64 {
                    return None;
                }
                skip_items(fuel, 2 * n, rest)?
            }
            _ => skip_items(fuel, 1, rest)?,
        };
        count -= 1;
    }
    Some(l)
}

/// The next item as it came, and what follows it.
pub(crate) fn read_raw(l: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    let rest = skip_items(l.len() + 1, 1, l)?;
    Some((l[..l.len() - rest.len()].to_vec(), rest))
}
