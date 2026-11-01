//! Members chatting over the in-memory Pigeonhole, as group_chat_client's core and file tests do.

#[path = "katzenqt1_client_harness/mod.rs"]
mod harness;

use harness::World;
use pigeonhole_protocols::protocols::katzenqt1::engine::{Action, Input, Status, WINDOW};
use pigeonhole_protocols::protocols::katzenqt1::wire as wire;

const LIMIT: u64 = 600000;

fn world(names: &[&str]) -> World {
    let mut w = World::default();
    for n in names {
        w.who(n);
    }
    w
}

fn send(w: &mut World, i: usize, text: &str) {
    w.feed(
        i,
        Input::Send {
            chat: "g".into(),
            text: text.into(),
        },
    );
}

/// Member `i` adds member `j`, who mints a voucher to join g.
fn induct(w: &mut World, i: usize, j: usize) {
    w.feed(
        j,
        Input::Join {
            chat: "g".into(),
            name: "g".into(),
        },
    );
    assert!(
        w.run_until(|w| !w.code(j, "g").is_empty(), LIMIT),
        "no voucher code"
    );
    let code = w.code(j, "g");
    w.feed(
        i,
        Input::Induct {
            chat: "g".into(),
            code,
        },
    );
    let added = format!("added ~{}", w.members[j].name);
    assert!(
        w.run_until(|w| w.joined(j, "g") && w.noticed(i, "g", &added), LIMIT),
        "{} does not join",
        w.members[j].name
    );
}

fn found_and_join(w: &mut World) {
    w.feed(
        0,
        Input::Create {
            chat: "g".into(),
            name: "g".into(),
        },
    );
    induct(w, 0, 1);
}

#[test]
fn two_members() {
    let mut w = world(&["alice", "bob"]);
    found_and_join(&mut w);
    send(&mut w, 1, "hi from bob");
    send(&mut w, 0, "hi from alice");
    assert!(w.run_until(
        |w| w.says(0, "g", "hi from bob") && w.says(1, "g", "hi from alice"),
        LIMIT
    ));
    send(&mut w, 1, "read you");
    let acked = |w: &World| {
        let c = w.chat(0, "g").unwrap();
        c.log
            .iter()
            .any(|l| l.text == "hi from alice" && c.acknowledged(l))
    };
    assert!(
        w.run_until(acked, LIMIT),
        "bob's message does not acknowledge alice's"
    );
    assert!(w.idle());
    assert!(w.chat(0, "g").unwrap().names.values().any(|n| n == "bob"));
}

/// katzenqt replies to a voucher with the members' read caps alone when its conversation keeps no
/// rosters, as one does that had members before rosters or joined through such a reply. The
/// newcomer joins anyway, as katzenqt's own joiner does, and reads and is read by every member.
#[test]
fn joins_through_a_reply_without_rosters() {
    let mut w = world(&["alice", "bob", "carol"]);
    found_and_join(&mut w);
    w.rosterless.insert(0);
    induct(&mut w, 0, 2);
    send(&mut w, 2, "carol here");
    send(&mut w, 0, "hi carol");
    send(&mut w, 1, "bob too");
    assert!(
        w.run_until(
            |w| w.says(0, "g", "carol here")
                && w.says(1, "g", "carol here")
                && w.says(2, "g", "hi carol")
                && w.says(2, "g", "bob too"),
            LIMIT
        ),
        "carol does not read or is not read by every member"
    );
}

#[test]
fn three_members() {
    let mut w = world(&["alice", "bob", "carol"]);
    found_and_join(&mut w);
    induct(&mut w, 1, 2);
    assert!(w.run_until(|w| w.noticed(0, "g", "~bob added ~carol"), LIMIT));
    send(&mut w, 2, "carol here");
    send(&mut w, 0, "welcome carol");
    assert!(w.run_until(
        |w| w.says(0, "g", "carol here")
            && w.says(1, "g", "carol here")
            && w.says(2, "g", "welcome carol"),
        LIMIT
    ));
}

#[test]
fn remove_and_leave() {
    let mut w = world(&["alice", "bob", "carol"]);
    found_and_join(&mut w);
    induct(&mut w, 0, 2);
    assert!(w.run_until(|w| w.noticed(1, "g", "~alice added ~carol"), LIMIT));
    send(&mut w, 2, "carol before");
    w.run_until(
        |w| w.says(0, "g", "carol before") && w.says(1, "g", "carol before"),
        LIMIT,
    );
    let carol = w.chat(2, "g").unwrap().group.as_ref().unwrap().me();
    w.feed(
        0,
        Input::RemoveMember {
            chat: "g".into(),
            who: carol.clone(),
        },
    );
    let c = w.chat(0, "g").unwrap();
    assert!(c.group.as_ref().unwrap().readers.len() == 1 && !w.says(0, "g", "carol before"));
    send(&mut w, 2, "carol after");
    send(&mut w, 1, "bob after");
    assert!(w.run_until(
        |w| w.says(1, "g", "carol after") && w.says(0, "g", "bob after"),
        LIMIT
    ));
    assert!(!w.says(0, "g", "carol after"));
    w.feed(
        0,
        Input::RemoveMember {
            chat: "g".into(),
            who: carol,
        },
    );
    assert!(w.noticed(0, "g", "that member is no longer in this group"));
    w.feed(1, Input::Leave { chat: "g".into() });
    w.run_until(|_| false, 60000);
    assert!(w.chat(1, "g").is_none());
}

#[test]
fn rename() {
    let mut w = world(&["alice", "bob"]);
    found_and_join(&mut w);
    send(&mut w, 0, "before");
    w.feed(
        0,
        Input::Rename {
            chat: "g".into(),
            to: "friends".into(),
        },
    );
    assert!(w.chat(0, "g").unwrap().name == "friends" && w.noticed(0, "g", "renamed from g"));
    send(&mut w, 1, "from bob");
    assert!(w.run_until(
        |w| w.says(1, "g", "before") && w.says(0, "g", "from bob"),
        LIMIT
    ));
    w.feed(
        0,
        Input::Create {
            chat: "other".into(),
            name: "friends".into(),
        },
    );
    assert!(
        w.chat(0, "other").is_none()
            && w.noticed(0, "g", "you already have a group called friends")
    );
}

#[test]
fn failing_writes() {
    let mut w = world(&["alice", "bob"]);
    found_and_join(&mut w);
    w.sim.state().fail_writes = 3;
    send(&mut w, 0, "eventually");
    assert!(w.run_until(|w| w.says(1, "g", "eventually"), LIMIT));
}

#[test]
fn backfill() {
    let mut w = world(&["alice", "bob"]);
    found_and_join(&mut w);
    send(&mut w, 0, "one");
    w.run_until(|w| w.says(1, "g", "one"), LIMIT);
    let before = w.sim.state().writes;
    for e in [2u64, 3] {
        w.sim.set_epoch(e);
        w.feed(0, Input::Epoch { n: e as usize });
        w.feed(1, Input::Epoch { n: e as usize });
        w.run_until(|w| w.idle(), LIMIT);
    }
    assert!(w.sim.state().writes > before);
    assert!(w.idle() && w.sim.state().refused.is_empty());
}

#[test]
fn name_taken_and_bad_voucher() {
    let mut w = world(&["alice"]);
    w.feed(
        0,
        Input::Create {
            chat: "fu".into(),
            name: "fu".into(),
        },
    );
    w.run_until(|w| w.joined(0, "fu"), LIMIT);
    w.feed(
        0,
        Input::Join {
            chat: "fu2".into(),
            name: "fu".into(),
        },
    );
    assert!(
        w.members[0].eng.state.chats.len() == 1
            && w.noticed(0, "fu", "you already have a group called fu: to join")
    );
    w.feed(
        0,
        Input::Induct {
            chat: "fu".into(),
            code: "abc!".into(),
        },
    );
    assert!(w.noticed(0, "fu", "that is not a voucher code"));
}

fn bytes_of(n: usize, seed: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + seed) % 251) as u8).collect()
}

fn attachment<'a>(
    w: &'a World,
    i: usize,
    name: &str,
) -> Option<&'a pigeonhole_protocols::protocols::katzenqt1::engine::Attachment> {
    w.chat(i, "g")?
        .log
        .iter()
        .find_map(|l| l.attachment.as_ref().filter(|a| a.name == name))
}

fn file(w: &World, i: usize, name: &str) -> Option<Vec<u8>> {
    let a = attachment(w, i, name)?;
    w.members[i].files.0.lock().unwrap().get(&a.file).cloned()
}

#[test]
fn long_message() {
    let mut w = world(&["alice", "bob"]);
    found_and_join(&mut w);
    let text = "a long message ".repeat(400);
    send(&mut w, 0, &text);
    send(&mut w, 0, "after it");
    assert!(w.run_until(
        |w| w.says(1, "g", &text) && w.says(1, "g", "after it"),
        LIMIT
    ));
    let log = &w.chat(1, "g").unwrap().log;
    assert!(log[log.len() - 2].text == text && log[log.len() - 1].text == "after it");
}

#[test]
fn image() {
    let mut w = world(&["alice", "bob"]);
    found_and_join(&mut w);
    let pic = bytes_of(20000, 7);
    w.feed(
        0,
        Input::SendFile {
            chat: "g".into(),
            name: "cat.png".into(),
            bytes: pic.clone(),
        },
    );
    assert!(
        w.chat(0, "g")
            .unwrap()
            .log
            .iter()
            .any(|l| l.attachment.is_some() && l.status == Status::Pending)
    );
    assert!(w.run_until(|w| file(w, 1, "cat.png").is_some(), LIMIT));
    w.run_until(|w| w.chat(0, "g").unwrap().jobs.is_empty(), LIMIT);
    let a = attachment(&w, 1, "cat.png").unwrap();
    assert!(a.filetype == "image/png" && a.size == 20000);
    assert_eq!(file(&w, 1, "cat.png"), Some(pic.clone()));
    assert_eq!(file(&w, 0, "cat.png"), Some(pic));
    assert!(
        !w.members[0]
            .files
            .0
            .lock()
            .unwrap()
            .keys()
            .any(|f| f.starts_with("spool/"))
    );
}

#[test]
fn concurrent_chunks() {
    let mut w = world(&["alice", "bob"]);
    found_and_join(&mut w);
    let doc = bytes_of(30000, 5);
    w.feed(
        0,
        Input::SendFile {
            chat: "g".into(),
            name: "big.bin".into(),
            bytes: doc.clone(),
        },
    );
    let out = |w: &World| {
        w.queue
            .iter()
            .filter(|q| matches!(q.1, Action::WriteChunk { .. }))
            .count()
    };
    assert!(w.run_until(|w| out(w) >= WINDOW, LIMIT));
    w.queue.reverse();
    assert!(w.run_until(|w| file(w, 1, "big.bin").is_some(), LIMIT));
    assert_eq!(file(&w, 1, "big.bin"), Some(doc));
}

#[test]
fn file_limits_and_deletes() {
    let mut w = world(&["alice", "bob"]);
    found_and_join(&mut w);
    w.feed(
        0,
        Input::SendFile {
            chat: "g".into(),
            name: "huge.bin".into(),
            bytes: vec![0; wire::MAX_FILE + 1],
        },
    );
    assert!(w.noticed(0, "g", "that file is too large to send"));
    w.feed(
        0,
        Input::SendFile {
            chat: "g".into(),
            name: "a.png".into(),
            bytes: bytes_of(500, 7),
        },
    );
    assert!(w.run_until(|w| file(w, 1, "a.png").is_some(), LIMIT));
    let a = attachment(&w, 1, "a.png").unwrap().file.clone();
    let alice = w
        .chat(1, "g")
        .unwrap()
        .group
        .as_ref()
        .unwrap()
        .readers
        .keys()
        .next()
        .unwrap()
        .clone();
    w.feed(
        1,
        Input::RemoveMember {
            chat: "g".into(),
            who: alice,
        },
    );
    w.run_until(|_| false, LIMIT);
    assert!(!w.members[1].files.0.lock().unwrap().contains_key(&a));
    w.feed(0, Input::Leave { chat: "g".into() });
    w.run_until(|_| false, LIMIT);
    assert!(w.members[0].files.0.lock().unwrap().is_empty());
}

/// The replicas are at epoch 491 when the group is made, as on a real network, and the engines
/// heard so before. The first message must still be found by the acknowledgement that names it
/// after the next epoch report.
#[test]
fn group_made_late_in_a_high_epoch_keeps_its_records() {
    let mut w = world(&["alice", "bob"]);
    w.sim.set_epoch(491);
    w.feed(0, Input::Epoch { n: 491 });
    w.feed(1, Input::Epoch { n: 491 });
    found_and_join(&mut w);
    send(&mut w, 0, "first");
    assert!(w.run_until(|w| w.says(1, "g", "first"), LIMIT));
    w.feed(0, Input::Epoch { n: 491 });
    w.feed(1, Input::Epoch { n: 491 });
    send(&mut w, 1, "read it");
    let acked = |w: &World| {
        let c = w.chat(0, "g").unwrap();
        c.log.iter().any(|l| l.text == "first" && c.acknowledged(l))
    };
    assert!(
        w.run_until(acked, LIMIT),
        "the acknowledgement of a message written before the epoch report is lost"
    );
}
