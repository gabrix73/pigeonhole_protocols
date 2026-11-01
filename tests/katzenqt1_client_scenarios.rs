//! group_chat_client's client scenarios, through the engine.

#[path = "katzenqt1_client_harness/mod.rs"]
mod harness;

use std::path::Path;

#[test]
fn client_scenarios() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/katzenqt1/client_scenarios");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    assert_eq!(files.len(), 8);
    for f in files {
        let script = std::fs::read_to_string(&f).unwrap();
        let got = harness::World::default()
            .run_script(&script)
            .unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        for (n, (a, e)) in got.lines().zip(script.lines()).enumerate() {
            assert_eq!(a, e, "{}: line {}", f.display(), n + 1);
        }
        assert_eq!(
            got.lines().count(),
            script.lines().count(),
            "{}",
            f.display()
        );
    }
}
