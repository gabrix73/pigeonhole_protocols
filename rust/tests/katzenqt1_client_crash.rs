//! Restarts at any point: whatever a member had under way, once it starts again from what is on
//! disk and everyone runs on to the end, each member is where the run without a crash left it.

#[path = "katzenqt1_client_harness/mod.rs"]
mod harness;

use std::collections::BTreeMap;
use std::path::Path;

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
    let mut runs = 0;
    for f in files {
        let script = std::fs::read_to_string(&f).unwrap();
        // The run without a crash, counting each member's actions.
        let mut w = World {
            disk: true,
            check_saved: true,
            ..World::default()
        };
        let counts = std::rc::Rc::new(std::cell::RefCell::new(BTreeMap::<usize, usize>::new()));
        let c2 = counts.clone();
        w.crash = Some(Box::new(move |who, _| {
            *c2.borrow_mut().entry(who).or_default() += 1;
            None
        }));
        w.run_script(&script).unwrap();
        let want = settled(&mut w);
        assert!(
            !want.contains_key("refused"),
            "{}: refused without a crash",
            f.display()
        );
        let counts = counts.borrow().clone();
        for (&who, &count) in &counts {
            let step = (count / 40).max(1);
            for k in (1..=count).step_by(step) {
                for lost in [false, true] {
                    let mut cw = World {
                        disk: true,
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
                    cw.run_script(&script).unwrap();
                    assert_eq!(
                        cw.restarts.get(&who),
                        Some(&1),
                        "{}: member {who} restarted not once",
                        f.display()
                    );
                    let got = settled(&mut cw);
                    runs += 1;
                    assert_eq!(
                        got,
                        want,
                        "{}: member {who} restarted after action {k} (lost {lost})",
                        f.display()
                    );
                }
            }
        }
    }
    println!("{runs} runs with a crash");
}
