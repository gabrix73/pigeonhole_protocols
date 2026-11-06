//! The store's files.

use pigeonhole_protocols::protocols::katzenqt1::client::store::{Options, Store};
use pigeonhole_protocols::protocols::katzenqt1::engine::{FileWrite, State, StepResult};

/// A file that cannot be put in place fails the commit, and leaves no temporary file behind.
#[test]
fn failed_keep_leaves_nothing() {
    let dir = tempfile::TempDir::new_in(
        std::env::var("TMPDIR")
            .unwrap_or_else(|_| format!("{}/scratch/tmp", std::env::var("HOME").unwrap())),
    )
    .unwrap();
    let mut st = Store::open(dir.path(), Options { no_sync: true, key: None }).unwrap();
    let taken = dir.path().join("attachments/g/a.bin");
    std::fs::create_dir_all(taken.join("in-the-way")).unwrap();
    let r = StepResult {
        files: vec![FileWrite {
            file: "attachments/g/a.bin".into(),
            bytes: b"bytes".to_vec(),
        }],
        ..StepResult::default()
    };
    assert!(st.commit(&State::default(), &r).is_err());
    let left: Vec<_> = std::fs::read_dir(taken.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(left, vec![std::ffi::OsString::from("a.bin")]);
}

/// A job keeps the lines packed into it.
#[test]
fn job_keeps_packed_lines() {
    use pigeonhole_protocols::protocols::katzenqt1::engine::{Chat, Job};
    let dir = tempfile::TempDir::new_in(
        std::env::var("TMPDIR")
            .unwrap_or_else(|_| format!("{}/scratch/tmp", std::env::var("HOME").unwrap())),
    )
    .unwrap();
    let mut st = Store::open(dir.path(), Options { no_sync: true, key: None }).unwrap();
    let job = Job {
        id: 1,
        token: Some(1),
        index: None,
        box_: b"F".to_vec(),
        line: Some(2),
        packed: vec![3, 5],
        upload: None,
    };
    let s = State {
        me: "alice".into(),
        chats: vec![Chat {
            id: "g".into(),
            name: "g".into(),
            jobs: vec![job.clone()],
            ..Chat::default()
        }],
    };
    let mut r = StepResult::default();
    r.changes.chats.insert("g".into());
    st.commit(&s, &r).unwrap();
    assert_eq!(st.load("alice").unwrap().chats[0].jobs, vec![job]);
}
