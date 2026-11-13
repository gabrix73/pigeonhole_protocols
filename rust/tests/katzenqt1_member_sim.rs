//! katzenqt's scenarios through the member, and random scripts for katzenqt and Lean to check.

#![cfg(feature = "std")]

use std::path::{Path, PathBuf};

use pigeonhole_protocols::protocols::katzenqt1::member::{sim, trace};
use serde_json::Value;

fn testdata(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/katzenqt1")
        .join(rel)
}

fn scenarios() -> Vec<PathBuf> {
    let mut fs: Vec<PathBuf> = std::fs::read_dir(testdata("groupchat_scenarios"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    fs.sort();
    fs
}

#[test]
fn katzenqt_scenarios() {
    let fs = scenarios();
    assert_eq!(fs.len(), 14);
    for f in fs {
        let script = std::fs::read_to_string(&f).unwrap();
        let got = sim::run(&script, None).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        if got != script {
            let line = got.lines().zip(script.lines()).position(|(a, b)| a != b);
            panic!("{}: differs at line {:?}", f.display(), line.map(|l| l + 1));
        }
    }
}

/// Each scenario makes the calls katzenqt's simulator made, with the same arguments, results and
/// states, as its recorded trace says.
#[test]
fn traces_match_katzenqt() {
    for f in scenarios() {
        let name = f.file_stem().unwrap().to_str().unwrap().to_owned();
        let script = std::fs::read_to_string(&f).unwrap();
        let mut ours: Vec<Value> = Vec::new();
        sim::run(
            &script,
            Some(&mut |l| ours.push(serde_json::from_str(&l.to_string()).unwrap())),
        )
        .unwrap();
        let theirs: Vec<Value> =
            std::fs::read_to_string(testdata(&format!("groupchat_traces/scenario-{name}.jsonl")))
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
        assert_eq!(ours.len(), theirs.len(), "{name}: calls");
        for (i, (a, b)) in ours.iter().zip(&theirs).enumerate() {
            if let Some(d) = trace::diff(&format!("{name}:{}", i + 1), a, b) {
                panic!("{d}");
            }
        }
    }
}

/// Random scripts run as written and their traces replay; with RANDOM_OUT set, each is written
/// there for katzenqt's simulator and Lean's replay.
#[test]
fn random_scripts() {
    let runs: u64 = std::env::var("RANDOM_RUNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let out = std::env::var("RANDOM_OUT").ok();
    for seed in 0..runs {
        let mut lines = String::new();
        let script = sim::random_script(
            seed,
            60,
            Some(&mut |l| {
                lines.push_str(&l.to_string());
                lines.push('\n');
            }),
        )
        .unwrap_or_else(|e| panic!("seed {seed}: {e}"));
        assert_eq!(
            sim::run(&script, None).as_deref(),
            Ok(script.as_str()),
            "seed {seed}: does not run as written"
        );
        trace::replay(&lines).unwrap_or_else(|e| panic!("seed {seed}: own trace: {e}"));
        if let Some(dir) = &out {
            std::fs::write(format!("{dir}/rust-{seed:04}.txt"), &script).unwrap();
            std::fs::write(format!("{dir}/rust-{seed:04}.jsonl"), &lines).unwrap();
        }
    }
}
