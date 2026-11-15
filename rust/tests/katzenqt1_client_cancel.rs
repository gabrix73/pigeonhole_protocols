//! Cancelling a voucher exchange under way, on either side, over the in-memory Pigeonhole.

#![cfg(feature = "std")]

#[path = "katzenqt1_client_harness/mod.rs"]
mod harness;

use harness::World;
use pigeonhole_protocols::protocols::katzenqt1::engine::{Action, Input};
use pigeonhole_protocols::protocols::katzenqt1::member::Induction;

const LIMIT: u64 = 600000;

/// Alice founds g and Bob mints a voucher to join it; both keep their state on disk.
fn minted() -> World {
    let mut w = World::default();
    let (a, b) = (w.who("alice"), w.who("bob"));
    w.on_disk();
    w.feed(a, Input::Create { chat: "g".into(), name: "g".into() });
    w.feed(b, Input::Join { chat: "g".into(), name: "g".into() });
    assert!(w.run_until(|w| w.joined(a, "g") && !w.code(b, "g").is_empty(), LIMIT));
    w
}

fn cancel(w: &mut World, i: usize) {
    w.feed(i, Input::Cancel { chat: "g".into() });
}

fn induct(w: &mut World) {
    let code = w.code(1, "g");
    w.feed(0, Input::Induct { chat: "g".into(), code });
}

fn inducting(w: &World) -> bool {
    w.chat(0, "g").unwrap().inducting.is_some()
}

fn held(w: &World) -> bool {
    w.chat(0, "g").unwrap().group.as_ref().unwrap().ledger.induction == Induction::Inducting
}

fn readers(w: &World) -> usize {
    w.chat(0, "g").unwrap().group.as_ref().unwrap().readers.len()
}

/// A join cancelled is forgotten for good; its reply, come late, is ignored.
#[test]
fn cancelled_join_is_forgotten() {
    let mut w = minted();
    // Bob waits for no reply while Alice adds him by the voucher he already handed her.
    w.held.insert(1);
    induct(&mut w);
    assert!(w.run_until(|w| w.noticed(0, "g", "added ~bob"), LIMIT));
    let await_reply = w
        .queue
        .iter()
        .find(|q| q.0 == 1 && matches!(q.1, Action::AwaitReply { .. }))
        .map(|q| q.1.clone())
        .expect("bob waits for the reply");
    cancel(&mut w, 1);
    assert!(w.chat(1, "g").is_none());
    assert!(!w.members[1].eng.state.wanted(&await_reply), "the wait is still wanted");
    // The wait already out comes back with the reply: ignored.
    w.held.clear();
    w.run_to(w.clock + LIMIT);
    assert!(w.chat(1, "g").is_none(), "the reply joined the cancelled chat");
    w.restart(1);
    assert!(w.chat(1, "g").is_none(), "the cancelled join came back");
    assert_eq!(w.pending(1), ["none"]);
}

/// A join cancelled while its voucher is minted is forgotten; the voucher minted is ignored.
#[test]
fn cancelled_mint_is_forgotten() {
    let mut w = World::default();
    let b = w.who("bob");
    w.on_disk();
    w.feed(b, Input::Join { chat: "g".into(), name: "g".into() });
    assert!(w.run_until(|w| w.queue.iter().any(|q| matches!(q.1, Action::Mint { .. })), LIMIT));
    cancel(&mut w, b);
    w.run_to(w.clock + LIMIT);
    assert!(w.chat(b, "g").is_none());
    w.restart(b);
    assert!(w.chat(b, "g").is_none());
    assert_eq!(w.pending(b), ["none"]);
}

/// An add cancelled before the voucher is read leaves the group as it was, the voucher's box
/// 0, read late, is ignored, and the same voucher still adds the member afterwards.
#[test]
fn cancelled_add_leaves_the_group() {
    let mut w = minted();
    let before = readers(&w);
    induct(&mut w);
    let read = w.queue.iter().find(|q| q.0 == 0).map(|q| q.1.clone()).unwrap();
    assert!(matches!(read, Action::ReadVoucher { .. }));
    cancel(&mut w, 0);
    assert!(!inducting(&w));
    assert!(w.noticed(0, "g", "stopped adding the member"));
    assert!(!w.members[0].eng.state.wanted(&read), "the voucher is still read for");
    w.run_to(w.clock + LIMIT);
    assert!(!inducting(&w), "the voucher read late started the add again");
    assert!(!w.joined(1, "g"));
    assert!(!held(&w));
    assert_eq!(readers(&w), before);
    w.restart(0);
    assert!(!inducting(&w), "the cancelled add came back");
    assert_eq!(w.pending(0), ["none"]);
    induct(&mut w);
    assert!(w.run_until(|w| w.joined(1, "g") && w.noticed(0, "g", "added ~bob"), LIMIT));
}

/// An add cancelled while the voucher is read and what is owed is still being written releases
/// the group's hold.
#[test]
fn cancelled_add_releases_the_hold() {
    let mut w = minted();
    let before = readers(&w);
    w.delay_next.insert(0, "Write".into());
    w.feed(0, Input::Send { chat: "g".into(), text: "owed".into() });
    induct(&mut w);
    assert!(w.run_until(|w| w.chat(0, "g").unwrap().inducting.as_ref().is_some_and(|i| i.payload.is_some()), LIMIT));
    assert!(held(&w));
    cancel(&mut w, 0);
    assert!(!inducting(&w));
    assert!(!held(&w), "the group is still held for the member");
    for input in w.delayed.remove(&0).unwrap() {
        w.feed(0, input);
    }
    w.run_to(w.clock + LIMIT);
    assert!(!inducting(&w) && !w.joined(1, "g"));
    assert_eq!(readers(&w), before);
    w.restart(0);
    assert!(!inducting(&w) && !held(&w));
}

/// A cancel once the reply is sealed, or with nothing under way, says so and changes nothing.
#[test]
fn cancel_too_late_or_of_nothing() {
    let mut w = minted();
    cancel(&mut w, 0);
    assert!(w.noticed(0, "g", "nothing to cancel"));
    induct(&mut w);
    assert!(w.run_until(|w| w.chat(0, "g").unwrap().inducting.as_ref().is_some_and(|i| i.sealed.is_some()), LIMIT));
    cancel(&mut w, 0);
    assert!(w.noticed(0, "g", "too late to cancel"));
    assert!(w.run_until(|w| w.joined(1, "g") && w.noticed(0, "g", "added ~bob"), LIMIT));
    cancel(&mut w, 1);
    assert!(w.joined(1, "g"), "a cancel left the joined group");
    assert!(w.noticed(1, "g", "nothing to cancel"));
}
