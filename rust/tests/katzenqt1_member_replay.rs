//! katzenqt's traces, replayed through the member: the same results and the same states.

#![cfg(feature = "trace")]

use std::path::Path;

fn testdata(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/katzenqt1")
        .join(rel)
}

fn replay_dir(dir: &Path) -> (usize, usize, usize) {
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    files.sort();
    let (mut calls, mut checks) = (0, 0);
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        match pigeonhole_protocols::protocols::katzenqt1::member::trace::replay(&text) {
            Ok((n, c)) => {
                calls += n;
                checks += c;
            }
            Err(e) => panic!("{}: {e}", f.display()),
        }
    }
    (files.len(), calls, checks)
}

#[test]
fn katzenqt_traces() {
    let (files, calls, checks) = replay_dir(&testdata("groupchat_traces"));
    assert_eq!(files, 20);
    println!("{files} traces, {calls} calls, {checks} BACAP checks");
}

/// The traces in $TRACES, such as fresh random runs from katzenqt's tools/groupchat_traces.py.
#[test]
fn more_traces() {
    let Ok(dir) = std::env::var("TRACES") else {
        return;
    };
    let (files, calls, checks) = replay_dir(Path::new(&dir));
    assert!(files > 0);
    println!("{files} traces, {calls} calls, {checks} BACAP checks");
}

/// Every state in the traces reads back and writes as it was.
#[test]
fn state_round_trip() {
    let mut n = 0;
    let mut dirs = vec![testdata("groupchat_traces")];
    if let Ok(d) = std::env::var("TRACES") {
        dirs.push(d.into());
    }
    for dir in dirs {
        for f in std::fs::read_dir(dir).unwrap() {
            let f = f.unwrap().path();
            if f.extension().is_none_or(|e| e != "jsonl") {
                continue;
            }
            for line in std::fs::read_to_string(&f).unwrap().lines() {
                let l: serde_json::Value = serde_json::from_str(line).unwrap();
                let g = pigeonhole_protocols::protocols::katzenqt1::member::trace::read_group(&l["state"])
                    .unwrap_or_else(|e| panic!("{}: {e}", f.display()));
                let back: serde_json::Value = serde_json::from_str(
                    &pigeonhole_protocols::protocols::katzenqt1::member::trace::group(&g).to_string(),
                )
                .unwrap();
                if let Some(d) =
                    pigeonhole_protocols::protocols::katzenqt1::member::trace::diff("state", &back, &l["state"])
                {
                    panic!("{}: {d}", f.display());
                }
                n += 1;
            }
        }
    }
    println!("{n} states");
}
