//! A store sealed with a key: the state file and every file beside it are each one sealed blob,
//! with nothing of what they hold readable without that key.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use pigeonhole_protocols::protocols::katzenqt1::client::Files;
use pigeonhole_protocols::protocols::katzenqt1::client::sealed_file::MAGIC;
use pigeonhole_protocols::protocols::katzenqt1::client::store::{Options, Store, StoreError};
use pigeonhole_protocols::protocols::katzenqt1::engine::{
    Changes, Chat, FileWrite, Line, State, StepResult,
};
use pigeonhole_protocols::secret::Secret;

const WORDS: &[u8] = b"meet me by the old mill";
const FILE: &[u8] = b"the contents of an attachment";
const CAP: &[u8] = b"a write cap of the group";
const ATTACHMENT: &str = "attachments/g/a.bin";

fn tmp() -> tempfile::TempDir {
    tempfile::TempDir::new_in(
        std::env::var("TMPDIR")
            .unwrap_or_else(|_| format!("{}/scratch/tmp", std::env::var("HOME").unwrap())),
    )
    .unwrap()
}

fn key(b: u8) -> Option<Secret> {
    Some(Secret::new(&[b; 32]))
}

fn opts(key: Option<Secret>) -> Options {
    Options { no_sync: true, key }
}

fn chat(id: &str) -> Chat {
    Chat {
        id: id.into(),
        name: format!("{id} group"),
        write_cap: Secret::new(CAP),
        log: vec![Line {
            id: 0,
            text: String::from_utf8(WORDS.to_vec()).unwrap(),
            ..Line::default()
        }],
        ..Chat::default()
    }
}

/// Saves chats `ids`, each with one line, and a file.
fn fill(st: &mut Store, ids: &[&str]) -> State {
    let state = State {
        me: "alice".into(),
        chats: ids.iter().map(|i| chat(i)).collect(),
    };
    let r = StepResult {
        files: vec![FileWrite {
            file: ATTACHMENT.into(),
            bytes: FILE.to_vec(),
        }],
        changes: Changes {
            chats: ids.iter().map(|i| i.to_string()).collect(),
            lines: ids
                .iter()
                .map(|i| (i.to_string(), BTreeSet::from([0])))
                .collect::<BTreeMap<_, _>>(),
            ..Changes::default()
        },
        ..StepResult::default()
    };
    st.commit(&state, &r).unwrap();
    state
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

fn holds(dir: &Path, needle: &[u8]) -> bool {
    walk(dir).iter().any(|f| {
        std::fs::read(f)
            .unwrap()
            .windows(needle.len())
            .any(|w| w == needle)
    })
}

/// Nothing anywhere under `dir` can be read: no message, file, name, cap, group id, or even the
/// names of the store's tables; and every file is a sealed blob.
fn all_sealed(dir: &Path) {
    for needle in [WORDS, FILE, CAP, b"alice", b"friends-chat", b"records", b"lines", b"meta"] {
        assert!(
            !holds(dir, needle),
            "{:?} can be read",
            String::from_utf8_lossy(needle)
        );
    }
    for f in walk(dir) {
        assert!(
            std::fs::read(&f).unwrap().starts_with(MAGIC),
            "{} is not sealed",
            f.display()
        );
    }
}

fn locked<T>(r: Result<T, StoreError>) -> bool {
    matches!(r, Err(StoreError::Locked))
}

fn unsealed<T>(r: Result<T, StoreError>) -> bool {
    matches!(r, Err(StoreError::Unsealed))
}

#[test]
fn sealed_round_trip() {
    let dir = tmp();
    {
        let mut st = Store::open(dir.path(), opts(key(1))).unwrap();
        fill(&mut st, &["friends-chat"]);
    }
    assert!(dir.path().join("state.sealed").exists());
    assert!(!dir.path().join("state.redb").exists());
    all_sealed(dir.path());
    let mut st = Store::open(dir.path(), opts(key(1))).unwrap();
    let state = st.load("bob").unwrap();
    assert_eq!(state.me, "alice");
    assert_eq!(state.chats[0].name, "friends-chat group");
    assert_eq!(state.chats[0].log[0].text.as_bytes(), WORDS);
    assert_eq!(&*state.chats[0].write_cap, CAP);
    assert_eq!(st.files().read(ATTACHMENT).unwrap(), FILE);
    assert!(st.unsaved(&state).unwrap().is_empty());
}

#[test]
fn every_commit_is_saved() {
    let dir = tmp();
    let mut st = Store::open(dir.path(), opts(key(1))).unwrap();
    fill(&mut st, &["friends-chat"]);
    // Read back while the first store is still open, as after a crash.
    let copy = tmp();
    std::fs::copy(dir.path().join("state.sealed"), copy.path().join("state.sealed")).unwrap();
    let mut again = Store::open(copy.path(), opts(key(1))).unwrap();
    assert_eq!(again.load("bob").unwrap().chats[0].log[0].text.as_bytes(), WORDS);
}

#[test]
fn wrong_or_no_key_is_locked() {
    let dir = tmp();
    {
        let mut st = Store::open(dir.path(), opts(key(1))).unwrap();
        fill(&mut st, &["friends-chat"]);
    }
    assert!(locked(Store::open(dir.path(), opts(key(2)))));
    assert!(locked(Store::open(dir.path(), opts(None))));
}

#[test]
fn a_changed_file_is_locked() {
    let dir = tmp();
    {
        let mut st = Store::open(dir.path(), opts(key(1))).unwrap();
        fill(&mut st, &["friends-chat"]);
    }
    let p = dir.path().join("state.sealed");
    let mut b = std::fs::read(&p).unwrap();
    let n = b.len() / 2;
    b[n] ^= 1;
    std::fs::write(&p, b).unwrap();
    assert!(locked(Store::open(dir.path(), opts(key(1)))));
}

#[test]
fn a_fresh_store_with_a_key_is_sealed() {
    let dir = tmp();
    drop(Store::open(dir.path(), opts(key(1))).unwrap());
    assert!(std::fs::read(dir.path().join("state.sealed")).unwrap().starts_with(MAGIC));
    assert!(locked(Store::open(dir.path(), opts(None))));
}

#[test]
fn plain_opened_with_a_key_is_unsealed() {
    let dir = tmp();
    {
        let mut st = Store::open(dir.path(), opts(None)).unwrap();
        fill(&mut st, &["friends-chat"]);
    }
    assert!(unsealed(Store::open(dir.path(), opts(key(1)))));
}

/// A write cut short before its rename leaves the last commit in place.
#[test]
fn a_write_cut_short_keeps_the_last_commit() {
    let dir = tmp();
    {
        let mut st = Store::open(dir.path(), opts(key(1))).unwrap();
        fill(&mut st, &["friends-chat"]);
    }
    std::fs::write(dir.path().join("state.sealed.tmp"), b"half a file").unwrap();
    let mut st = Store::open(dir.path(), opts(key(1))).unwrap();
    assert_eq!(st.load("bob").unwrap().chats[0].log[0].text.as_bytes(), WORDS);
}

#[test]
fn reseal_keeps_everything() {
    let dir = tmp();
    let want = {
        let mut st = Store::open(dir.path(), opts(None)).unwrap();
        fill(&mut st, &["friends-chat", "other-chat"])
    };
    assert!(holds(dir.path(), WORDS));
    Store::reseal(dir.path(), Secret::new(&[1; 32])).unwrap();
    assert!(!dir.path().join("state.redb").exists());
    assert!(!dir.path().join(".sealing").exists());
    all_sealed(dir.path());
    let mut st = Store::open(dir.path(), opts(key(1))).unwrap();
    let got = st.load("bob").unwrap();
    assert_eq!(got.me, want.me);
    let names = |s: &State| s.chats.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&got), names(&want));
    assert_eq!(got.chats[1].log, want.chats[1].log);
    assert_eq!(st.files().read(ATTACHMENT).unwrap(), FILE);
    assert!(st.unsaved(&got).unwrap().is_empty());
}

/// A sealing that stopped part way, with files left unsealed, is reported and finished.
#[test]
fn a_reseal_cut_short_is_finished() {
    let dir = tmp();
    {
        let mut st = Store::open(dir.path(), opts(None)).unwrap();
        fill(&mut st, &["friends-chat"]);
    }
    Store::reseal(dir.path(), Secret::new(&[1; 32])).unwrap();
    // As if it had stopped before sealing this file.
    std::fs::write(dir.path().join("attachments/g/late.bin"), FILE).unwrap();
    std::fs::write(dir.path().join(".sealing"), b"").unwrap();
    assert!(unsealed(Store::open(dir.path(), opts(key(1)))));
    Store::reseal(dir.path(), Secret::new(&[1; 32])).unwrap();
    all_sealed(dir.path());
    let st = Store::open(dir.path(), opts(key(1))).unwrap();
    assert_eq!(st.files().read("attachments/g/late.bin").unwrap(), FILE);
}

/// Without a key, the store is as it always was: one redb file and files as they are.
#[test]
fn without_a_key_nothing_changes() {
    let dir = tmp();
    {
        let mut st = Store::open(dir.path(), opts(None)).unwrap();
        fill(&mut st, &["friends-chat"]);
    }
    assert!(dir.path().join("state.redb").exists());
    assert!(!dir.path().join("state.sealed").exists());
    assert_eq!(std::fs::read(dir.path().join(ATTACHMENT)).unwrap(), FILE);
}

/// One store at a time, as when the state is not sealed.
#[test]
fn one_store_at_a_time() {
    let dir = tmp();
    let first = Store::open(dir.path(), opts(key(1))).unwrap();
    assert!(matches!(
        Store::open(dir.path(), opts(key(1))),
        Err(StoreError::Other(_))
    ));
    drop(first);
    Store::open(dir.path(), opts(key(1))).unwrap();
}
