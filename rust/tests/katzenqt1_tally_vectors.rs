//! Polls between katzenqt and this crate, through testdata/katzenqt1/tally (see
//! scripts/gen_tally_vectors.py): katzenqt.json, made by katzenqt's own tally code with pycrdt
//! 0.13.1, is counted here as katzenqt counted it, and its sync request answered; rust.json, polls
//! made here, is what the script checks katzenqt counts as this crate does. PP_WRITE_TALLY=1 writes
//! rust.json anew.

#![cfg(feature = "std")]

use std::path::PathBuf;

use pigeonhole_protocols::protocols::katzenqt1::engine::Line;
use pigeonhole_protocols::protocols::katzenqt1::tally::{self, Mode, Outcome, Poll, Polls};
use pigeonhole_protocols::protocols::katzenqt1::wire::{
    Gcm, MSG_TALLY_CREATE, MSG_TALLY_SYNC_REQ, MSG_TALLY_SYNC_RESP, Tally, tally_content,
};
use serde_json::{Value, json};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/katzenqt1/tally")
}

fn load(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(dir().join(name)).unwrap()).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn tally_of(v: &Value) -> Tally {
    Tally::of(&Gcm::from_bytes(&hex(v)).expect("a group chat message")).expect("a tally")
}

fn gcm(t: &Tally) -> String {
    hex::encode(tally_content(&[0; 32], t, 4))
}

fn line(id: usize, sender: Vec<u8>, t: Tally) -> Line {
    Line { id, sender, tally: Some(t), ..Line::default() }
}

/// What a poll counts to, in the script's terms.
fn counts(p: &Poll) -> Value {
    let v = p.view().expect("a poll");
    let (kind, winners) = match v.outcome() {
        Outcome::Winner(w) => ("winner", vec![w]),
        Outcome::Tie(w) => ("tie", w),
        Outcome::NoWinner => ("no_winner", vec![]),
    };
    json!({
        "topic": v.topic,
        "mode": v.mode.name(),
        "options": v.options.iter().map(|o| o.text.clone()).collect::<Vec<_>>(),
        "yes": v.options.iter().map(|o| o.yes).collect::<Vec<_>>(),
        "maybe": v.options.iter().map(|o| o.maybe).collect::<Vec<_>>(),
        "no": v.options.iter().map(|o| o.no).collect::<Vec<_>>(),
        "voters": v.ballots.len(),
        "closed": v.closed,
        "outcome": {"kind": kind, "winners": winners},
    })
}

/// A poll's create, votes and closes in a vector, as lines; the closes only if `closed`.
fn lines_of(p: &Value, closed: bool) -> Vec<Line> {
    let mut lines = vec![line(1, hex(&p["creator"]), tally_of(&p["create"]))];
    let closes = if closed { p["closes"].as_array().unwrap().as_slice() } else { &[] };
    for m in p["votes"].as_array().unwrap().iter().chain(closes) {
        lines.push(line(lines.len() + 1, hex(&m["sender"]), tally_of(&m["gcm"])));
    }
    lines
}

#[test]
fn katzenqt_polls_count_here_as_there() {
    let v = load("katzenqt.json");
    assert_eq!(v["pycrdt"], "0.13.1");
    let me = [9u8; 32];
    for mode in ["approval", "availability"] {
        let p = &v[mode];
        assert_eq!(tally_of(&p["create"]).kind, MSG_TALLY_CREATE);
        for (closed, want) in [(false, &p["want_open"]), (true, &p["want_closed"])] {
            let polls = Polls::from_lines(&lines_of(p, closed), &me);
            assert_eq!(counts(polls.at(1).unwrap()), *want, "{mode}, closed {closed}");
        }
        // katzenqt's document with the votes in it, whole.
        let voted = tally_of(&p["voted"]);
        assert_eq!(voted.kind, MSG_TALLY_SYNC_RESP);
        assert_eq!(counts(&Poll::load(voted.crdt.as_ref().unwrap()).unwrap()), p["want_open"], "{mode}: the document");
    }
    // katzenqt's sync request, answered from the approval poll held here.
    let mut lines = lines_of(&v["approval"], false);
    let req = tally_of(&v["sync_req"]);
    assert_eq!(req.kind, MSG_TALLY_SYNC_REQ);
    lines.push(line(lines.len() + 1, vec![4; 32], req));
    let resp = Polls::from_lines(&lines, &me).answers(&lines);
    assert_eq!(resp.len(), 1);
    assert_eq!(counts(&Poll::load(resp[0].crdt.as_ref().unwrap()).unwrap()), v["approval"]["want_open"]);
    // katzenqt's answer to the sync request rust.json makes: the poll, with its votes.
    if let Some(r) = v.get("sync_resp_for_rust") {
        let mut lines: Vec<Line> = lines_of(&v["approval"], false).into_iter().skip(1).collect();
        lines.push(line(100, hex(&v["approval"]["creator"]), tally_of(r)));
        assert_eq!(counts(Polls::from_lines(&lines, &me).at(100).unwrap()), v["approval"]["want_open"]);
    }
}

/// Polls made here in each mode, voted on and closed, the answer to katzenqt's sync request, and
/// a sync request for katzenqt's approval poll, for the script to read as katzenqt.
#[test]
fn rust_polls() {
    let path = dir().join("rust.json");
    let key = |n: u8| vec![n; 32];
    if std::env::var_os("PP_WRITE_TALLY").is_some() {
        let v = load("katzenqt.json");
        let mut out = json!({});
        for (name, mode, survey) in [("approval", Mode::Approval, [0xa1; 16]), ("availability", Mode::Availability, [0xa2; 16])] {
            let options = ["Monday".to_string(), "Tuesday".into(), "Wednesday".into()];
            let create = tally::create(&survey, "Lunch: which day?", mode, &options, &key(1));
            let mut lines = vec![line(1, key(1), create.clone())];
            let mut votes = Vec::new();
            for (n, pick) in [(2, 0), (3, 2), (2, 2), (1, 2), (2, 0), (3, 2)] {
                let vote = Polls::from_lines(&lines, &key(n)).cycle(1, pick).unwrap();
                votes.push(json!({"sender": hex::encode(key(n)), "gcm": gcm(&vote)}));
                lines.push(line(lines.len() + 1, key(n), vote));
            }
            let want_open = counts(Polls::from_lines(&lines, &key(1)).at(1).unwrap());
            let close = Polls::from_lines(&lines, &key(1)).close(1).unwrap();
            let not_creator = close.clone();
            let closes = vec![
                json!({"sender": hex::encode(key(2)), "gcm": gcm(&not_creator)}),
                json!({"sender": hex::encode(key(1)), "gcm": gcm(&close)}),
            ];
            lines.push(line(lines.len() + 1, key(2), not_creator));
            lines.push(line(lines.len() + 1, key(1), close));
            let want_closed = counts(Polls::from_lines(&lines, &key(1)).at(1).unwrap());
            out[name] = json!({
                "creator": hex::encode(key(1)),
                "create": gcm(&create),
                "votes": votes,
                "closes": closes,
                "want_open": want_open,
                "want_closed": want_closed,
            });
        }
        let mut lines = lines_of(&v["approval"], false);
        lines.push(line(lines.len() + 1, vec![4; 32], tally_of(&v["sync_req"])));
        out["sync_resp"] = json!(gcm(&Polls::from_lines(&lines, &key(9)).answers(&lines)[0]));
        // Seeing only the votes of katzenqt's approval poll, ask for it.
        let votes: Vec<Line> = lines_of(&v["approval"], false).into_iter().skip(1).collect();
        out["sync_req"] = json!(gcm(&Polls::from_lines(&votes, &key(9)).requests(&votes)[0]));
        std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    }
    // What was written still counts here as it did.
    let v = load("rust.json");
    for name in ["approval", "availability"] {
        for (closed, want) in [(false, "want_open"), (true, "want_closed")] {
            let polls = Polls::from_lines(&lines_of(&v[name], closed), &key(1));
            assert_eq!(counts(polls.at(1).unwrap()), v[name][want], "{name}, closed {closed}");
        }
    }
    assert_eq!(tally_of(&v["sync_req"]).kind, MSG_TALLY_SYNC_REQ);
    assert_eq!(tally_of(&v["sync_resp"]).kind, MSG_TALLY_SYNC_RESP);
}
