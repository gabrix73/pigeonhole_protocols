//! The vectors of the array form, version 4, and the rules they do not show: what is written by
//! default, what each message costs, and that the map form still reads.

mod katzenqt1_wire_common;

use katzenqt1_wire_common::*;
use pigeonhole_protocols::protocols::katzenqt1::wire::*;

const H: [u8; HASH_SIZE] = [0; HASH_SIZE];

#[test]
fn wire_vectors_v4() {
    let v = load("groupchat_wire_vectors_v4.json");
    let mut count = 0;
    for e in v["messages"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let cbor = unhex(&e["cbor"]);
        assert_eq!(cbor[0] >> 5, 4, "{name}: not the array form");
        let got = message_from_cbor(&cbor).unwrap_or_else(|| panic!("{name}: refused"));
        assert_eq!(message_json(&Some(got.clone())), e["message"], "{name}: read differently");
        let rw = unhex(&e["rewritten"]);
        assert_eq!(
            message_to_gcm(&got, ARRAY_VERSION).map(|g| g.to_bytes()),
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
        count += 1;
    }
    for e in v["written"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let b = box_of(&read_message(&e["message"]), ARRAY_VERSION).unwrap_or_else(|| panic!("{name}: not written"));
        assert_eq!(b, unhex(&e["box"]), "{name}: written as another box");
        assert!(b[0] == b'F' && b[1] >> 5 == 4, "{name}: not F and an array");
        count += 1;
    }
    for e in v["membership"].as_array().unwrap() {
        let caps: Vec<Vec<u8>> = e["read_caps"].as_array().unwrap().iter().map(unhex).collect();
        assert_eq!(membership_hash(&caps).to_vec(), unhex(&e["hash"]));
        count += 1;
    }
    for e in v["replies"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let cbor = unhex(&e["cbor"]);
        let w = ReplyWho::from_bytes(&cbor).unwrap_or_else(|| panic!("{name}: does not decode"));
        assert_eq!(
            join_reply_json(&w.to_join_reply()),
            e["join_reply"],
            "{name}: carries another JoinReply"
        );
        let again = w.to_bytes();
        assert_eq!(again[0] >> 5, 4, "{name}: not written as an array");
        assert_eq!(ReplyWho::from_bytes(&again), Some(w), "{name}: reads back differently");
        count += 1;
    }
    for e in v["malformed"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let cbor = unhex(&e["cbor"]);
        assert_eq!(Gcm::from_bytes(&cbor), None, "{name}: accepted");
        assert_eq!(message_from_cbor(&cbor), None, "{name}: read as a message");
        count += 1;
    }
    for e in v["unsupported"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let want = e["version"].as_u64().map(|v| (v, e["msg_type"].as_u64().unwrap()));
        assert_eq!(unsupported(&unhex(&e["cbor"])), want, "{name}");
        count += 1;
    }
    assert_eq!(count, 17 + 7 + 6 + 5 + 11 + 6);
}

#[test]
fn default_is_the_array_form_and_the_map_form_still_reads() {
    let text = text_content(&H, "hello", ARRAY_VERSION);
    assert_eq!(text[0] >> 5, 4);
    assert_eq!(Gcm::from_bytes(&text).unwrap().version, ARRAY_VERSION);
    let m3 = Gcm {
        version: MAP_VERSION,
        membership_hash: H.to_vec(),
        msg_type: MSG_TEXT,
        text: Some("hello".into()),
        ..Gcm::default()
    }
    .to_bytes();
    assert_eq!(m3[0] >> 5, 5);
    assert_eq!(Gcm::from_bytes(&m3).unwrap().text.as_deref(), Some("hello"));
    assert_eq!(text_of(&m3), text_of(&text));
    assert_eq!(message_from_cbor(&m3).unwrap().content, Some(m3.clone()));
    assert_eq!(message_from_cbor(&text).unwrap().content, Some(text.clone()));
    assert_eq!(Gcm::from_bytes(&m3).unwrap().to_bytes(), m3);
    let control = Gcm {
        version: ARRAY_VERSION,
        membership_hash: H.to_vec(),
        msg_type: MSG_CONTROL,
        acks: Some(vec![0; 10]),
        ..Gcm::default()
    };
    assert_eq!(&control.to_bytes()[..38], &[&[0x85, 0x04, 0x58, 0x20][..], &H, &[0x0a, 0xf6]].concat()[..]);
    assert_eq!(Gcm::from_bytes(&control.to_bytes()), Some(control));
}

#[test]
fn costs() {
    let intro = Gcm {
        version: ARRAY_VERSION,
        membership_hash: H.to_vec(),
        msg_type: MSG_INTRODUCTION,
        introduction: Some(Introduction {
            name: "bob".into(),
            read_cap: vec![1; READ_CAP_SIZE],
        }),
        ..Gcm::default()
    };
    let control = Gcm {
        version: ARRAY_VERSION,
        membership_hash: H.to_vec(),
        msg_type: MSG_CONTROL,
        ..Gcm::default()
    };
    assert_eq!(text_content(&H, "", ARRAY_VERSION).len(), 38);
    assert_eq!(text_content(&H, &"a".repeat(23), ARRAY_VERSION).len(), 38 + 23);
    assert_eq!(text_content(&H, &"a".repeat(24), ARRAY_VERSION).len(), 39 + 24);
    assert_eq!(control.to_bytes().len(), 38);
    assert_eq!(intro.to_bytes().len(), 180);
    assert_eq!(Gcm::from_bytes(&intro.to_bytes()), Some(intro));
}

#[test]
fn file_upload_body_round_trips_in_both_forms() {
    let f = FileUpload {
        payload: vec![1, 2],
        filetype: "image/png".into(),
        basename: "a.png".into(),
    };
    let content = file_content(&H, &f, ARRAY_VERSION);
    assert_eq!((content[0], content[37]), (0x84, 0x83), "an array whose body is a 3-array");
    let g = Gcm::from_bytes(&content).unwrap();
    assert_eq!(file_of(&g), Some(f.clone()));
    assert_eq!(g.to_bytes(), content);
    let m3 = Gcm {
        version: MAP_VERSION,
        ..g.clone()
    }
    .to_bytes();
    assert_eq!(m3[0] >> 5, 5);
    let g3 = Gcm::from_bytes(&m3).unwrap();
    assert_eq!((file_of(&g3), g3.to_bytes()), (Some(f), m3.clone()));
    assert_eq!(Gcm { version: ARRAY_VERSION, ..g3 }.to_bytes(), content);
    for c in [content, m3] {
        let full = put_payload(&c, &[9; 300]).unwrap();
        assert_eq!(file_of(&Gcm::from_bytes(&full).unwrap()).unwrap().payload, vec![9; 300]);
        let (without, payload) = take_payload(&full).unwrap();
        assert_eq!(payload, vec![9; 300]);
        assert_eq!(put_payload(&without, &[1, 2]), Some(c));
    }
    // Not a file: a text, and a who whose body starts with bytes.
    assert_eq!(take_payload(&text_content(&H, "x", ARRAY_VERSION)), None);
    let who = Gcm {
        version: ARRAY_VERSION,
        membership_hash: H.to_vec(),
        msg_type: MSG_WHO,
        other: vec![RawField {
            key: "who".into(),
            raw: vec![0x81, 0x41, 0x07],
        }],
        ..Gcm::default()
    }
    .to_bytes();
    assert_eq!(take_payload(&who), None);
    assert_eq!(Gcm::from_bytes(&who).unwrap().to_bytes(), who);
}
