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
