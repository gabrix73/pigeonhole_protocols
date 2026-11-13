//! The v1 wire, in testdata/pigeonservice/v1/vectors.json for the plugins in katzenpost and Go
//! services to implement against: the address, every message and record from fixed inputs, what
//! each signature covers, and what a plugin or a client must refuse. Signing is deterministic, so
//! the file is stable; PIGEONSERVICE_WRITE_VECTORS=1 rewrites it.

#![cfg(feature = "std")]

use pigeonhole_protocols::pigeonservice::cbor;
use pigeonhole_protocols::pigeonservice::lease::MAX_CLOCK_SKEW;
use pigeonhole_protocols::pigeonservice::v1::address;
use pigeonhole_protocols::pigeonservice::v1::directory::check;
use pigeonhole_protocols::pigeonservice::v1::registrar::{Admitted, Registrar};
use pigeonhole_protocols::pigeonservice::v1::sign::{self, Identity, Scheme, SignScheme, Sizes};
use pigeonhole_protocols::pigeonservice::v1::size;
use pigeonhole_protocols::pigeonservice::v1::wire::*;
use pigeonhole_protocols::pigeonservice::version::{self, Kind, V1};
use pigeonhole_protocols::pigeonservice::{Error, MAX_LINK_TTL};
use serde_json::{Value, json};

const TIME: u64 = 1767225600;
const DAY: u64 = 24 * 3600;

fn x(b: &[u8]) -> Value {
    hex::encode(b).into()
}

fn seed() -> Vec<u8> {
    (0..Scheme::SEED as u8).collect()
}

struct Fixture {
    id: Identity,
    router: [u8; 32],
    directory: [u8; 32],
    entry: Entry,
}

fn fixture() -> Fixture {
    let id = Identity::from_seed(&seed()).unwrap();
    let v0: Value = serde_json::from_str(include_str!("../../testdata/pigeonservice/v0/vectors.json")).unwrap();
    let descriptor = Descriptor {
        nike_scheme: "X25519-CTIDH1024".into(),
        nike_public_key: hex::decode(v0["service_public_key"].as_str().unwrap()).unwrap(),
        routers: [0xa0, 0xa1].map(|n| RouterRef { node_id_hash: [n; 32], endpoint: Kind::VoucherRouter.capability(V1) }).to_vec(),
        protocols: vec!["eliza/1".into()],
        revision: 1,
        expiry: TIME + DAY,
        ..Default::default()
    };
    let listing = Listing {
        name: "ELIZA".into(),
        kind: "chatbot".into(),
        description: "A Rogerian psychotherapist, after Weizenbaum's.".into(),
        revision: 1,
        expiry: TIME + DAY,
        ..Default::default()
    };
    Fixture {
        router: registrar_id(&[0xa0; 32], Kind::VoucherRouter.capability(V1).as_bytes()),
        directory: registrar_id(&[0xdd; 32], Kind::Discovery.capability(V1).as_bytes()),
        entry: Entry { descriptor: descriptor.sign(&id).unwrap(), listing: Some(listing.sign(&id).unwrap()) },
        id,
    }
}

fn requests(f: &Fixture) -> Vec<(&'static str, Signed)> {
    let s = |ctx, registrar, revision, expiry, voucher: Vec<u8>, record| Signed::new(&f.id, ctx, registrar, TIME, revision, expiry, voucher, record).unwrap();
    vec![
        ("register", s(Ctx::Register, f.router, 1, TIME + 7 * DAY, vec![0x11; 32], None)),
        ("renew", s(Ctx::Renew, f.router, 2, TIME + 7 * DAY, vec![], None)),
        ("unregister", s(Ctx::Unregister, f.router, 3, 0, vec![], None)),
        ("advertise", s(Ctx::Advertise, f.directory, 4, TIME + DAY, vec![0x33; 32], Some(f.entry.digest()))),
        ("withdraw", s(Ctx::Withdraw, f.directory, 5, 0, vec![], None)),
    ]
}

fn golden(path: &str, got: Value) {
    let path = format!("{}/../testdata/{path}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("PIGEONSERVICE_WRITE_VECTORS").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(got, want, "{path} differs; PIGEONSERVICE_WRITE_VECTORS=1 rewrites it");
}

#[test]
fn vectors() {
    let f = fixture();
    let mut out = serde_json::Map::new();
    out.insert("version".into(), json!(V1));
    out.insert("scheme".into(), json!({
        "name": Scheme::NAME, "public_key_size": Scheme::PUBLIC_KEY, "signature_size": Scheme::SIGNATURE,
        "hybrid": "public key = Falcon-padded-512 (897 B) || Ed25519 (32 B); signature = Falcon-padded-512 (666 B) || Ed25519 (64 B), both over the signed message, both must verify (hpqc hybrid.FalconPadded512Ed25519)",
        "signed_message": "\"pigeonservice-v1-sig\" || 0x00 || ctx || 0x00 || canonical CBOR of the message without Signature",
        "falcon_signing": "deterministic in this crate: the Falcon reference PRNG seeded with SHAKE256(\"pigeonservice-v1 falcon sign\" || Falcon private key || signed message); any valid Falcon signature verifies",
    }));
    let address = f.id.address();
    out.insert("identity".into(), json!({
        "seed": x(&seed()),
        "seed_rule": "Falcon key generator seed (32 B, falcon-rs SHAKE256 PRNG) || Ed25519 seed (32 B)",
        "public_key": x(&f.id.public_key()),
    }));
    let period = address::period(TIME);
    out.insert("address".into(), json!({
        "rule": "base32(version || id || checksum), RFC 4648 lower case without padding; id = BLAKE2b-256(public key); checksum = BLAKE2b-256(\"pigeonservice address checksum\" || version || id)[..2]",
        "version": address::VERSION,
        "id": x(&address.0.0),
        "text": address.to_string(),
        "lookup_rule": "BLAKE2b-256(\"pigeonservice-v1-lookup\" || 0x00 || id || u64be(period)), period = unix time / 86400; a directory takes the periods either side of its own",
        "period": period,
        "lookup": x(&address.lookup(period)),
    }));
    out.insert("registrars".into(), json!({
        "rule": "BLAKE2b-256(node_id_hash || endpoint)",
        "router": {"node_id_hash": x(&[0xa0; 32]), "endpoint": Kind::VoucherRouter.capability(V1), "registrar": x(&f.router)},
        "directory": {"node_id_hash": x(&[0xdd; 32]), "endpoint": Kind::Discovery.capability(V1), "registrar": x(&f.directory)},
    }));
    out.insert("service_types".into(), json!({
        "voucher_router/v0": Kind::VoucherRouter.capability(0), "discovery/v0": Kind::Discovery.capability(0),
        "voucher_router/v1": Kind::VoucherRouter.capability(1), "discovery/v1": Kind::Discovery.capability(1),
    }));

    for (name, s) in requests(&f) {
        let raw = Request::Signed(s.clone()).encode();
        assert_eq!(Request::decode(&raw).unwrap(), Request::Signed(s.clone()));
        assert_eq!(version::of(&raw).unwrap(), V1);
        s.verify().unwrap();
        assert!(raw.len() <= s.ctx.max() && s.ctx.max() <= size::MIN_SPHINX_USER_PAYLOAD);
        let mut v = json!({
            "ctx": s.ctx.sig_ctx(), "time": s.time, "revision": s.revision,
            "signed_message": x(&sign::message(s.ctx.sig_ctx(), &s.body())),
            "signature": x(&s.signature),
            "request": x(&raw),
            "max": s.ctx.max(),
        });
        if s.ctx.leases() {
            v["expiry"] = json!(s.expiry);
        }
        if s.ctx.vouches() {
            v["voucher"] = x(&s.voucher);
        }
        if let Some(r) = s.record {
            v["record"] = x(&r);
        }
        out.insert(name.into(), v);
    }
    let ciphertext = vec![0x5c; size::ROUTE_CIPHERTEXT];
    let others = [
        ("route", Request::Route { service_id: address.0, ciphertext: ciphertext.clone() }),
        ("resolve", Request::Resolve(address.lookup(period))),
        ("search", Request::Search { name: "eliza".into(), kind: "chatbot".into() }),
    ];
    for (name, r) in &others {
        let raw = r.encode();
        assert_eq!(&Request::decode(&raw).unwrap(), r);
        out.insert(name.to_string(), json!({"request": x(&raw), "max": r.max()}));
    }
    out["route"]["ciphertext"] = x(&ciphertext);

    let d = &f.entry.descriptor;
    let l = f.entry.listing.as_ref().unwrap();
    d.verify().unwrap();
    l.verify().unwrap();
    assert_eq!(check(&f.entry, &address).unwrap_err().to_string(), "pigeonservice: descriptor expired", "valid but for its age");
    let entry = f.entry.encode();
    assert_eq!(Entry::decode(&entry).unwrap(), f.entry);
    let listings = encode_listings(std::slice::from_ref(l));
    assert_eq!(decode_listings(&listings).unwrap(), vec![l.clone()]);
    out.insert("records".into(), json!({
        "descriptor": {"ctx": "descriptor", "signed_message": x(&sign::message("descriptor", &d.body())), "signature": x(&d.signature)},
        "listing": {"ctx": "listing", "signed_message": x(&sign::message("listing", &l.body())), "signature": x(&l.signature)},
        "entry": x(&entry),
        "entry_digest": x(&f.entry.digest()),
        "entry_on_a_connection": x(&frame(&entry)),
        "listings": x(&listings),
        "framing": "a 4-byte big-endian length, then the CBOR, split over as many connection messages as it takes",
    }));

    let replies = [
        ("lease", Reply { expiry: TIME + 7 * DAY, ..Reply::status(Status::Ok) }),
        ("voucher", Reply { voucher: vec![0x22; 32], ..Reply::status(Status::Ok) }),
        ("unsupported_version", Reply { versions: vec![V1], ..Reply::status(Status::UnsupportedVersion) }),
    ];
    let mut section = serde_json::Map::new();
    for (name, r) in &replies {
        let raw = r.encode();
        if r.status == Status::UnsupportedVersion as u8 {
            assert!(Reply::decode(&raw).is_err());
        } else {
            assert_eq!(&Reply::decode(&raw).unwrap(), r);
        }
        section.insert(name.to_string(), x(&raw));
    }
    for n in 0..=9u8 {
        let s = Status::from_u8(n).unwrap();
        section.insert(format!("{s:?}"), x(&Reply::status(s).encode()));
    }
    assert!(Status::from_u8(10).is_none());
    out.insert("reply".into(), section.into());
    out.insert("limits".into(), json!({
        "min_sphinx_user_payload": size::MIN_SPHINX_USER_PAYLOAD,
        "max_routers": size::MAX_ROUTERS, "max_endpoint": size::MAX_ENDPOINT, "max_scheme": size::MAX_SCHEME,
        "max_protocols": size::MAX_PROTOCOLS, "max_protocol": size::MAX_PROTOCOL,
        "max_name": size::MAX_NAME, "max_type": size::MAX_TYPE, "max_description": size::MAX_DESCRIPTION,
        "max_clock_skew_seconds": MAX_CLOCK_SKEW.as_secs(), "lookup_period_seconds": address::PERIOD,
    }));
    out.insert("refused".into(), refused(&f));
    out.insert("refused_records".into(), refused_records(&f));
    golden("pigeonservice/v1/vectors.json", out.into());
}

/// Requests a plugin at `TIME` that already took `renew` must refuse, each with its status.
fn refused(f: &Fixture) -> Value {
    let reqs = requests(f);
    let renew = reqs[1].1.clone();
    let mut bad_sig = renew.clone();
    bad_sig.revision = 9;
    let mut forged_falcon = renew.clone();
    forged_falcon.signature[100] ^= 1;
    forged_falcon.revision = 10;
    let mut forged_ed25519 = Signed::new(&f.id, Ctx::Renew, f.router, TIME, 10, TIME + DAY, vec![], None).unwrap();
    *forged_ed25519.signature.last_mut().unwrap() ^= 1;
    let wrong = Signed::new(&f.id, Ctx::Renew, f.directory, TIME, 11, TIME + DAY, vec![], None).unwrap();
    let late = Signed::new(&f.id, Ctx::Renew, f.router, TIME - 3600, 12, TIME + DAY, vec![], None).unwrap();
    let old = Signed::new(&f.id, Ctx::Renew, f.router, TIME, 1, TIME + DAY, vec![], None).unwrap();
    let long = Signed::new(&f.id, Ctx::Renew, f.router, TIME, 13, TIME + 30 * DAY, vec![], None).unwrap();
    let mut as_register = Signed::new(&f.id, Ctx::Renew, f.router, TIME, 14, TIME + DAY, vec![], None).unwrap();
    as_register.ctx = Ctx::Register;
    as_register.voucher = vec![0x11; 32];
    let cases = [
        ("revision changed after signing", bad_sig, Status::BadSignature),
        ("Falcon half altered", forged_falcon, Status::BadSignature),
        ("Ed25519 half altered", forged_ed25519, Status::BadSignature),
        ("a Renew's signature on a Register", as_register, Status::BadSignature),
        ("signed for the directory, sent to the router", wrong, Status::WrongRegistrar),
        ("an hour old", late, Status::BadTime),
        ("revision below the last taken", old, Status::Stale),
        ("lease past the longest", long, Status::InvalidRequest),
    ];
    let mut r = Registrar::new(f.router, MAX_LINK_TTL);
    assert_eq!(r.admit(&renew, TIME), Ok(Admitted::Fresh));
    let mut out = vec![json!({"case": "accepted first", "request": x(&Request::Signed(renew.clone()).encode()), "status": 0})];
    for (case, s, want) in cases {
        assert_eq!(r.admit(&s, TIME), Err(want), "{case}");
        out.push(json!({"case": case, "request": x(&Request::Signed(s).encode()), "status": want as u8}));
    }
    assert_eq!(r.admit(&renew, TIME), Ok(Admitted::Repeat));
    out.push(json!({"case": "the first again: a retransmission, answered as before", "request": x(&Request::Signed(renew).encode()), "status": 0}));
    Value::Array(out)
}

/// Entries a client resolving the fixture's address must refuse.
fn refused_records(f: &Fixture) -> Value {
    let address = f.id.address();
    let mut moved = f.entry.clone();
    moved.descriptor.routers.truncate(1);
    let other = Identity::from_seed(&[9; 64]).unwrap();
    let theirs = Entry { descriptor: f.entry.descriptor.clone().sign(&other).unwrap(), listing: None };
    let mut mixed = f.entry.clone();
    mixed.listing = Some(f.entry.listing.clone().unwrap().sign(&other).unwrap());
    type Refusal = fn(&Error) -> bool;
    let cases: [(&str, Entry, Refusal); 3] = [
        ("routers changed after signing", moved, |e| matches!(e, Error::BadSignature)),
        ("another service's descriptor", theirs, |e| matches!(e, Error::BadAddress(_))),
        ("a listing signed by another key", mixed, |e| matches!(e, Error::BadSignature)),
    ];
    let mut out = vec![];
    for (case, e, want) in cases {
        let err = check(&e, &address).unwrap_err();
        assert!(want(&err), "{case}: {err}");
        out.push(json!({"case": case, "address": address.to_string(), "entry": x(&e.encode())}));
    }
    Value::Array(out)
}

/// A v0 message is no v1 request, and a v0 plugin's answer is no v1 reply.
#[test]
fn versions_do_not_mix() {
    let v0_list = cbor::encode(&cbor::map(vec![("List", cbor::map(vec![]))]));
    match Request::decode(&v0_list) {
        Err(e @ Error::VersionMismatch { .. }) => assert_eq!(
            e.to_string(),
            "pigeonservice: version mismatch with a layer-0 plugin: the client speaks v0, the service supports v1; upgrade the client or app, or use a service that offers v0"
        ),
        other => panic!("{other:?}"),
    }
    let v0_reply = pigeonhole_protocols::pigeonservice::wire::encode_router_reply(pigeonhole_protocols::pigeonservice::wire::Status::InvalidRequest);
    assert!(matches!(Reply::decode(&v0_reply), Err(Error::VersionMismatch { requested: 1, .. })));
    let v2 = cbor::encode(&cbor::map(vec![("V", cbor::uint(2)), ("Search", cbor::map(vec![]))]));
    assert!(matches!(Request::decode(&v2), Err(Error::VersionMismatch { requested: 2, ref supported, .. }) if supported == &[1]));
    // A record of another version is refused the same way.
    let mut e = cbor::decode(&fixture().entry.encode()).unwrap();
    if let cbor::Value::Map(m) = &mut e
        && let Some((_, cbor::Value::Map(d))) = m.iter_mut().find(|(k, _)| k.as_text() == Some("Descriptor"))
    {
        d.iter_mut().find(|(k, _)| k.as_text() == Some("V")).unwrap().1 = cbor::uint(2);
    }
    match Entry::decode(&cbor::encode(&e)) {
        Err(e @ Error::VersionMismatch { .. }) => assert_eq!(
            e.to_string(),
            "pigeonservice: version mismatch with a service record: the client speaks v1, the service supports v2; upgrade the client or app, or use a service that offers v1"
        ),
        other => panic!("{other:?}"),
    }
}
