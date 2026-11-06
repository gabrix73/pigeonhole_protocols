//! Restarts at any point: whatever a member had under way, once it starts again from what is on
//! disk and everyone runs on to the end, each member is where the run without a crash left it.

#[path = "katzenqt1_client_harness/mod.rs"]
mod harness;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;
use std::rc::Rc;

use harness::World;
use pigeonhole_protocols::protocols::katzenqt1::engine::Input;

const LIMIT: u64 = 600000;

fn found_and_join(w: &mut World) {
    w.feed(
        0,
        Input::Create {
            chat: "g".into(),
            name: "g".into(),
        },
    );
    w.feed(
        1,
        Input::Join {
            chat: "g".into(),
            name: "g".into(),
        },
    );
    assert!(w.run_until(|w| !w.code(1, "g").is_empty(), LIMIT));
    let code = w.code(1, "g");
    w.feed(
        0,
        Input::Induct {
            chat: "g".into(),
            code,
        },
    );
    assert!(w.run_until(
        |w| w.joined(1, "g") && w.noticed(0, "g", "added ~bob"),
        LIMIT
    ));
}

fn disk_world(names: &[&str]) -> World {
    let mut w = World::default();
    for n in names {
        w.who(n);
    }
    w.on_disk();
    w
}

#[test]
fn restart() {
    let mut w = disk_world(&["alice", "bob"]);
    found_and_join(&mut w);
    w.feed(
        0,
        Input::Send {
            chat: "g".into(),
            text: "before".into(),
        },
    );
    assert!(w.run_until(|w| w.says(1, "g", "before"), LIMIT));
    w.restart(0);
    w.feed(
        0,
        Input::Send {
            chat: "g".into(),
            text: "after".into(),
        },
    );
    w.feed(
        1,
        Input::Send {
            chat: "g".into(),
            text: "bob after".into(),
        },
    );
    assert!(w.run_until(
        |w| w.says(1, "g", "after") && w.says(0, "g", "bob after"),
        LIMIT
    ));
    assert!(w.sim.state().refused.is_empty());
}

#[test]
fn restart_mid_upload() {
    let mut w = disk_world(&["alice", "bob"]);
    found_and_join(&mut w);
    let doc: Vec<u8> = (0..40000).map(|i| ((i * 31 + 3) % 251) as u8).collect();
    w.feed(
        0,
        Input::SendFile {
            chat: "g".into(),
            name: "notes.txt".into(),
            bytes: doc.clone(),
        },
    );
    assert!(w.run_until(
        |w| {
            w.chat(0, "g")
                .unwrap()
                .jobs
                .iter()
                .any(|j| j.upload.as_ref().is_some_and(|u| u.sent >= 5))
        },
        LIMIT
    ));
    w.restart(0);
    let got = |w: &World| {
        let a = w
            .chat(1, "g")?
            .log
            .iter()
            .find_map(|l| l.attachment.clone())?;
        w.file(1, &a.file)
    };
    assert!(w.run_until(|w| got(w).is_some(), LIMIT));
    assert_eq!(got(&w), Some(doc));
}

/// The inducting member restarts after each of its actions in an induction, with what came of the
/// action lost or kept: the induction is finished, not given up.
#[test]
fn restart_mid_induction() {
    for lost in [false, true] {
        for crash_at in 1.. {
            let mut w = disk_world(&["alice", "bob", "carol"]);
            found_and_join(&mut w);
            w.feed(
                2,
                Input::Join {
                    chat: "g".into(),
                    name: "g".into(),
                },
            );
            w.run_until(|w| !w.code(2, "g").is_empty(), LIMIT);
            let code = w.code(2, "g");
            w.feed(
                0,
                Input::Induct {
                    chat: "g".into(),
                    code,
                },
            );
            let mut n = 0;
            w.crash = Some(Box::new(move |who, _| {
                if who != 0 {
                    return None;
                }
                n += 1;
                (n == crash_at).then_some(lost)
            }));
            assert!(
                w.run_until(|w| w.joined(2, "g"), LIMIT),
                "crash after {crash_at} (lost {lost}): carol does not join"
            );
            w.feed(
                2,
                Input::Send {
                    chat: "g".into(),
                    text: "carol here".into(),
                },
            );
            assert!(
                w.run_until(
                    |w| w.says(0, "g", "carol here") && w.says(1, "g", "carol here"),
                    LIMIT
                ),
                "crash after {crash_at} (lost {lost})"
            );
            assert!(w.sim.state().refused.is_empty());
            if !w.restarts.contains_key(&0) {
                println!(
                    "lost {lost}: restarted after each of {} actions",
                    crash_at - 1
                );
                break;
            }
        }
    }
}

/// What a run ends with, member by member.
fn settled(w: &mut World) -> BTreeMap<String, String> {
    w.held.clear();
    w.crash = None;
    w.run_to(w.clock + 1800 * 1000);
    let mut out = BTreeMap::new();
    for i in 0..w.members.len() {
        for c in &w.members[i].eng.state.chats {
            let mut msgs: Vec<String> = c
                .log
                .iter()
                .filter(|l| l.notice.is_none())
                .map(|l| format!("{}: {}", w.name_of(&l.sender), l.text))
                .collect();
            msgs.sort();
            out.insert(
                format!("{} {}", w.members[i].name, c.name),
                format!(
                    "members {:?}; jobs {}; inducting {}; joining {}; {}",
                    w.members_of(i, &c.name),
                    c.jobs.len(),
                    c.inducting.is_some(),
                    c.joining.is_some(),
                    msgs.join(" | ")
                ),
            );
        }
    }
    if !w.sim.state().refused.is_empty() {
        out.insert("refused".into(), format!("{:?}", w.refused()));
    }
    out
}

#[test]
fn crash_anywhere() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/katzenqt1/client_scenarios");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    // The runs with a crash share nothing, and one after another they take minutes. Threads help
    // little: each secret is guarded memory, and the kernel takes a lock of the whole process to
    // map, lock or protect it. So the test runs again in a process for each core, each taking every nth
    // run, and checks that each saw the same runs.
    let mut jobs = Vec::new();
    for f in files {
        let script = std::fs::read_to_string(&f).unwrap();
        let (want, counts) = uncrashed(&script);
        assert!(
            !want.contains_key("refused"),
            "{}: refused without a crash",
            f.display()
        );
        for (&who, &count) in &counts {
            let step = (count / 40).max(1);
            for k in (1..=count).step_by(step) {
                for lost in [false, true] {
                    jobs.push((f.clone(), script.clone(), want.clone(), who, k, lost));
                }
            }
        }
    }
    if let Ok(part) = std::env::var("CRASH_PART") {
        let (part, parts, total) = parse_part(&part);
        assert_eq!(jobs.len(), total, "part {part} of {parts}: other runs than the parent's");
        for (f, script, want, who, k, lost) in jobs.into_iter().skip(part).step_by(parts) {
            crashed(&f, &script, &want, who, k, lost);
        }
        return;
    }
    let parts = std::thread::available_parallelism().map_or(1, |n| n.get());
    let children: Vec<_> = (0..parts)
        .map(|part| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "crash_anywhere", "--test-threads", "1"])
                .env("CRASH_PART", format!("{part}/{parts}/{}", jobs.len()))
                .spawn()
                .unwrap()
        })
        .collect();
    for (part, mut c) in children.into_iter().enumerate() {
        assert!(c.wait().unwrap().success(), "part {part} of {parts} failed: see its output above");
    }
    println!("{} runs with a crash, in {parts} processes", jobs.len());
}

/// `CRASH_PART`: which part a process runs, of how many, and how many runs there are in all.
fn parse_part(s: &str) -> (usize, usize, usize) {
    let v: Vec<usize> = s.split('/').map(|x| x.parse().unwrap()).collect();
    (v[0], v[1], v[2])
}

/// The run of a script without a crash: what it ends with, and how many actions each member did.
fn uncrashed(script: &str) -> (BTreeMap<String, String>, BTreeMap<usize, usize>) {
    let mut w = World {
        disk: true,
        check_saved: true,
        plain: true,
        ..World::default()
    };
    let counts = Rc::new(RefCell::new(BTreeMap::<usize, usize>::new()));
    let c2 = counts.clone();
    w.crash = Some(Box::new(move |who, _| {
        *c2.borrow_mut().entry(who).or_default() += 1;
        None
    }));
    w.run_script(script).unwrap();
    let want = settled(&mut w);
    let counts = counts.borrow().clone();
    (want, counts)
}

/// The run of a script with member `who` restarted after its action `k`, what came of the action
/// lost or kept: it must end as the run without a crash did.
fn crashed(f: &Path, script: &str, want: &BTreeMap<String, String>, who: usize, k: usize, lost: bool) {
    let mut cw = World {
        disk: true,
        plain: true,
        ..World::default()
    };
    let mut n = 0;
    cw.crash = Some(Box::new(move |i, _| {
        if i != who {
            return None;
        }
        n += 1;
        (n == k).then_some(lost)
    }));
    cw.run_script(script).unwrap();
    assert_eq!(
        cw.restarts.get(&who),
        Some(&1),
        "{}: member {who} restarted not once",
        f.display()
    );
    let got = settled(&mut cw);
    assert_eq!(
        &got,
        want,
        "{}: member {who} restarted after action {k} (lost {lost})",
        f.display()
    );
}
