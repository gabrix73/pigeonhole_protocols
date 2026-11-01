//! The vectors shared with cryptlib and katzenqt.

use pigeonhole_protocols::protocols::katzenqt1::wire::*;
use serde_json::{Value, json};

fn load(name: &str) -> Value {
    let path = format!(
        "{}/../testdata/katzenqt1/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn nat(v: &Value) -> u64 {
    v.to_string().parse().unwrap()
}

fn num(n: u64) -> Value {
    serde_json::from_str(&n.to_string()).unwrap()
}

fn message_json(m: &Option<Message>) -> Value {
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

fn join_reply_json(r: &Option<JoinReply>) -> Value {
    let Some(r) = r else { return Value::Null };
    json!({
        "members": r.members.iter().map(|m| m.as_ref().map(|m| json!([hex::encode(&m.read_cap), hex::encode(&m.start)]))).collect::<Vec<_>>(),
        "rosters": r.rosters.iter().map(|ro| ro.as_ref().map(|ro| ro.iter().map(|e| json!([num(e.index as u64), e.place.map(|p| num(p as u64))])).collect::<Vec<_>>())).collect::<Vec<_>>(),
        "introductions": r.introductions.iter().map(|i| json!([num(i.by as u64), hex::encode(&i.index), num(i.member as u64)])).collect::<Vec<_>>(),
        "introducer": num(r.introducer as u64),
        "newcomer": num(r.newcomer as u64),
    })
}

fn read_message(j: &Value) -> Message {
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

#[test]
fn wire_vectors() {
    let v = load("groupchat_wire_vectors.json");
    let mut count = 0;
    for e in v["messages"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let cbor = unhex(&e["cbor"]);
        let got = message_from_cbor(&cbor);
        assert_eq!(message_json(&got), e["message"], "{name}: read differently");
        match (&got, e["rewritten"].as_str()) {
            (Some(m), Some(rw)) => {
                let rw = hex::decode(rw).unwrap();
                assert_eq!(
                    message_to_gcm(m).map(|g| g.to_bytes()),
                    Some(rw.clone()),
                    "{name}: written back differently"
                );
                if rw == cbor {
                    assert_eq!(
                        Gcm::from_bytes(&cbor).map(|g| g.to_bytes()),
                        Some(cbor.clone()),
                        "{name}: does not encode to itself"
                    );
                }
            }
            (None, None) => {}
            _ => panic!("{name}: inconsistent with the vector"),
        }
        count += 1;
    }
    for e in v["written"].as_array().unwrap() {
        assert_eq!(
            box_of(&read_message(&e["message"])),
            Some(unhex(&e["box"])),
            "{}: written as another box",
            e["name"]
        );
        count += 1;
    }
    for e in v["membership"].as_array().unwrap() {
        let caps: Vec<Vec<u8>> = e["read_caps"]
            .as_array()
            .unwrap()
            .iter()
            .map(unhex)
            .collect();
        assert_eq!(membership_hash(&caps).to_vec(), unhex(&e["hash"]));
        count += 1;
    }
    for e in v["replies"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let cbor = unhex(&e["cbor"]);
        let w = ReplyWho::from_bytes(&cbor).unwrap_or_else(|| panic!("{name}: does not decode"));
        assert_eq!(w.to_bytes(), cbor, "{name}: encodes differently");
        assert_eq!(
            join_reply_json(&w.to_join_reply()),
            e["join_reply"],
            "{name}: carries another JoinReply"
        );
        count += 1;
    }
    assert_eq!(count, 19 + 6 + 6 + 5);
}

fn read_acks(j: &Value) -> Vec<Ack> {
    let mut acks: Vec<Ack> = j
        .as_array()
        .unwrap()
        .iter()
        .map(|p| Ack {
            member: nat(&p[0]) as usize,
            idx64: nat(&p[1]),
        })
        .collect();
    // The vectors list a set of acknowledgements; the field holds them by roster index.
    acks.sort_by_key(|a| a.member);
    acks
}

#[test]
fn acks_vectors() {
    let v = load("acks_vectors.json");
    for e in v["valid"].as_array().unwrap() {
        let (acks, field) = (read_acks(&e["acks"]), unhex(&e["field"]));
        assert_eq!(acks_to_bytes(&acks), field, "{}", e["name"]);
        assert_eq!(acks_from_bytes(&field), Ok(acks), "{}", e["name"]);
    }
    for e in v["lenient"].as_array().unwrap() {
        assert_eq!(
            acks_from_bytes(&unhex(&e["field"])),
            Ok(read_acks(&e["acks"])),
            "{}",
            e["name"]
        );
    }
    for e in v["malformed"].as_array().unwrap() {
        assert!(
            acks_from_bytes(&unhex(&e["field"])).is_err(),
            "{} accepted",
            e["name"]
        );
    }
}

#[test]
fn numbers_and_introduced_at() {
    let p = |b: u8| Some(vec![b; PREFIX_SIZE]);
    for ns in [
        vec![],
        vec![Number {
            index: 7,
            prefix: None,
        }],
        vec![
            Number {
                index: 3,
                prefix: p(1),
            },
            Number {
                index: 4,
                prefix: p(2),
            },
        ],
    ] {
        assert_eq!(numbers_from_bytes(&numbers_to_bytes(&ns)), ns);
    }
    let repeated = [vec![0u8], vec![1; 16]].concat();
    assert!(numbers_from_bytes(&repeated).is_empty());
    assert!(numbers_from_bytes(&[[255u8].as_slice(), &[1; 8], &[2; 8]].concat()).is_empty());
    let r = IntroRef {
        introducer: 9,
        index: vec![5; INDEX_SIZE],
    };
    assert_eq!(
        introduced_at_from_bytes(&introduced_at_to_bytes(&r)),
        Some(r)
    );
    assert_eq!(introduced_at_from_bytes(&[0; INDEX_SIZE]), None);
}

#[test]
fn files_and_substreams() {
    for max in [3, 10, 1530] {
        for n in [1, max - 2, max - 1, max, 3 * max + 7] {
            let blob = vec![7u8; n];
            let boxes: Vec<Vec<u8>> = (0..chunk_count(n, max))
                .map(|i| substream_box(&blob, max, i))
                .collect();
            assert!(boxes.iter().all(|b| b.len() <= max));
            assert_eq!(assemble(&boxes), Some(blob));
        }
    }
    assert_eq!(indirection(3, &[0; READ_CAP_SIZE]).len(), 141);
    let f = FileUpload {
        payload: vec![],
        filetype: "image/png".into(),
        basename: "a.png".into(),
    };
    let content = file_content(&[0; 32], &f);
    let full = put_payload(&content, &[9; 70000]).unwrap();
    let (without, payload) = take_payload(&full).unwrap();
    assert_eq!((without, payload.len()), (content, 70000));
    assert_eq!(
        file_of(&Gcm::from_bytes(&full).unwrap())
            .unwrap()
            .payload
            .len(),
        70000
    );
    assert_eq!(safe_name("../../etc/passwd"), "_.._etc_passwd");
    assert_eq!(safe_name(""), "unnamed");
    assert_eq!(filetype_of("A.JPG"), "image/jpeg");
}
