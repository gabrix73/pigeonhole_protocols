//! Reading the shared wire vectors and showing what this client reads of them as the JSON the
//! vectors use.

#![allow(dead_code)]

use pigeonhole_protocols::protocols::katzenqt1::wire::*;
use serde_json::{Value, json};

pub fn load(name: &str) -> Value {
    let path = format!(
        "{}/../testdata/katzenqt1/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

pub fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

pub fn nat(v: &Value) -> u64 {
    v.to_string().parse().unwrap()
}

pub fn num(n: u64) -> Value {
    serde_json::from_str(&n.to_string()).unwrap()
}

pub fn message_json(m: &Option<Message>) -> Value {
    let Some(m) = m else { return Value::Null };
    json!({
        "content": m.content.as_ref().map(hex::encode),
        "introduction": m.introduction.as_ref().map(|i| json!({"name": i.name, "read_cap": hex::encode(&i.read_cap)})),
        "numbers": m.numbers.iter().map(|n| json!([num(n.index as u64), n.prefix.as_ref().map(hex::encode)])).collect::<Vec<_>>(),
        "introduced_at": m.introduced_at.as_ref().map(|a| json!({"introducer": num(a.introducer as u64), "index": hex::encode(&a.index)})),
        "acks": m.acks.iter().map(|a| json!([num(a.member as u64), num(a.idx64)])).collect::<Vec<_>>(),
        "membership_hash": m.membership_hash.as_ref().map(hex::encode),
    })
}

pub fn join_reply_json(r: &Option<JoinReply>) -> Value {
    let Some(r) = r else { return Value::Null };
    json!({
        "members": r.members.iter().map(|m| m.as_ref().map(|m| json!([hex::encode(&m.read_cap), hex::encode(&m.start)]))).collect::<Vec<_>>(),
        "rosters": r.rosters.iter().map(|ro| ro.as_ref().map(|ro| ro.iter().map(|e| json!([num(e.index as u64), e.place.map(|p| num(p as u64))])).collect::<Vec<_>>())).collect::<Vec<_>>(),
        "introductions": r.introductions.iter().map(|i| json!([num(i.by as u64), hex::encode(&i.index), num(i.member as u64)])).collect::<Vec<_>>(),
        "introducer": num(r.introducer as u64),
        "newcomer": num(r.newcomer as u64),
    })
}

pub fn read_message(j: &Value) -> Message {
    Message {
        content: j["content"].as_str().map(|s| hex::decode(s).unwrap()),
        introduction: (!j["introduction"].is_null()).then(|| Introduction {
            name: j["introduction"]["name"].as_str().unwrap().into(),
            read_cap: unhex(&j["introduction"]["read_cap"]),
        }),
        numbers: j["numbers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| Number {
                index: nat(&p[0]) as usize,
                prefix: p[1].as_str().map(|s| hex::decode(s).unwrap()),
            })
            .collect(),
        introduced_at: (!j["introduced_at"].is_null()).then(|| IntroRef {
            introducer: nat(&j["introduced_at"]["introducer"]) as usize,
            index: unhex(&j["introduced_at"]["index"]),
        }),
        acks: j["acks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| Ack {
                member: nat(&p[0]) as usize,
                idx64: nat(&p[1]),
            })
            .collect(),
        membership_hash: j["membership_hash"]
            .as_str()
            .map(|s| hex::decode(s).unwrap()),
    }
}

/// The map form of what `m` is written as: a control message or an introduction made afresh
/// takes version 3; content keeps the version it carries.
pub fn map_gcm(m: &Message) -> Option<Vec<u8>> {
    message_to_gcm(m, MAP_VERSION).map(|mut g| {
        g.version = g.version.min(MAP_VERSION);
        g.to_bytes()
    })
}
