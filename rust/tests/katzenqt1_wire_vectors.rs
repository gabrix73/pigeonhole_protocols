//! The vectors shared with cryptlib and katzenqt: the map form, version 3, which is read still
//! and written here on request.

mod katzenqt1_wire_common;

use katzenqt1_wire_common::*;
use pigeonhole_protocols::protocols::katzenqt1::wire::*;
use serde_json::Value;

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
                    map_gcm(m),
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
            map_gcm(&read_message(&e["message"])).map(|c| frame(&c)),
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
        assert_eq!(w.to_map_bytes(), cbor, "{name}: encodes differently");
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
