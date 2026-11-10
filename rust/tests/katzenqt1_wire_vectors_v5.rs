//! The vectors of version 5: text messages packed in one box.

mod katzenqt1_wire_common;

use katzenqt1_wire_common::*;
use pigeonhole_protocols::protocols::katzenqt1::wire::*;

#[test]
fn wire_vectors_v5() {
    let v = load("groupchat_wire_vectors_v5.json");
    let mut count = 0;
    for e in v["packed"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let mut cbor = unhex(&e["start"]);
        for t in e["added"].as_array().unwrap() {
            cbor = pack(&cbor, t.as_str().unwrap()).unwrap_or_else(|| panic!("{name}: not packed"));
        }
        assert_eq!(cbor, unhex(&e["cbor"]), "{name}: packed differently");
        let texts: Vec<String> = e["texts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(texts_of(&cbor), texts, "{name}: reads differently");
        assert_eq!(
            text_of(&cbor),
            texts.join("\n"),
            "{name}: shows differently"
        );
        assert_eq!(
            message_json(&message_from_cbor(&cbor)),
            e["message"],
            "{name}: read differently"
        );
        assert_eq!(
            Gcm::from_bytes(&cbor).map(|g| g.to_bytes()),
            Some(cbor.clone()),
            "{name}: does not encode to itself"
        );
        assert_eq!(unsupported(&cbor), None, "{name}: taken for unsupported");
        count += 1;
    }
    for e in v["unsupported"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let cbor = unhex(&e["cbor"]);
        assert_eq!(Gcm::from_bytes(&cbor), None, "{name}: accepted");
        assert_eq!(
            unsupported(&cbor),
            Some((nat(&e["version"]), nat(&e["msg_type"]))),
            "{name}: another version or type"
        );
        count += 1;
    }
    for e in v["malformed"].as_array().unwrap() {
        let name = e["name"].as_str().unwrap();
        let cbor = unhex(&e["cbor"]);
        assert_eq!(Gcm::from_bytes(&cbor), None, "{name}: accepted");
        assert_eq!(unsupported(&cbor), None, "{name}: taken for unsupported");
        count += 1;
    }
    assert_eq!(count, 5 + 5 + 6);
}

#[test]
fn packs_only_text_of_the_array_form() {
    let h = [0u8; HASH_SIZE];
    assert_eq!(pack(&text_content(&h, "a", MAP_VERSION), "b"), None);
    let f = FileUpload {
        payload: b"x".to_vec(),
        filetype: "arbitrary".into(),
        basename: "x".into(),
    };
    assert_eq!(pack(&file_content(&h, &f, CURRENT_VERSION), "b"), None);
}
