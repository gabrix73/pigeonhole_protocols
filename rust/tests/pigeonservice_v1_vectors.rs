//! The v1 wire, in testdata/pigeonservice/v1/vectors.json for the plugins in katzenpost to
//! implement against: every message from fixed inputs, what each signature covers, and requests
//! a plugin must refuse. Ed25519 signs deterministically, so the file is stable;
//! PIGEONSERVICE_WRITE_VECTORS=1 rewrites it.

use pigeonhole_protocols::pigeonservice::cbor;
use pigeonhole_protocols::pigeonservice::lease::MAX_CLOCK_SKEW;
use pigeonhole_protocols::pigeonservice::v1::registrar::{Admitted, Registrar};
use pigeonhole_protocols::pigeonservice::v1::sign::{self, Identity, Scheme, Sizes};
use pigeonhole_protocols::pigeonservice::v1::size;
use pigeonhole_protocols::pigeonservice::v1::wire::*;
use pigeonhole_protocols::pigeonservice::version::{self, Kind, V1};
use serde_json::{Value, json};

const TIME: u64 = 1767225600;
const DAY: u64 = 24 * 3600;

fn x(b: &[u8]) -> Value {
    hex::encode(b).into()
}

struct Fixture {
    id: Identity,
    router: [u8; 32],
    directory: [u8; 32],
    descriptor: Descriptor,
}

fn fixture() -> Fixture {
    let id = Identity::from_seed(&(0..32).collect::<Vec<u8>>()).unwrap();
    let v0: Value = serde_json::from_str(include_str!("../../testdata/pigeonservice/v0/vectors.json")).unwrap();
    let descriptor = Descriptor {
        nike_scheme: "X25519-CTIDH1024".into(),
        nike_public_key: hex::decode(v0["service_public_key"].as_str().unwrap()).unwrap(),
        routers: [0xa0, 0xa1]
            .map(|n| RouterRef { node_id_hash: [n; 32], endpoint: Kind::VoucherRouter.capability(V1) })
            .to_vec(),
    };
    Fixture {
        id,
        router: registrar_id(&[0xa0; 32], Kind::VoucherRouter.capability(V1).as_bytes()),
        directory: registrar_id(&[0xdd; 32], Kind::Discovery.capability(V1).as_bytes()),
        descriptor,
    }
}

fn requests(f: &Fixture) -> Vec<(&'static str, Signed)> {
    let s = |ctx, registrar, revision, expiry, voucher: Vec<u8>, d: Option<Descriptor>| {
        Signed::new(&f.id, ctx, registrar, TIME, revision, expiry, voucher, d).unwrap()
    };
    vec![
        ("register", s(Ctx::Register, f.router, 1, TIME + 7 * DAY, vec![0x11; 32], None)),
        ("renew", s(Ctx::Renew, f.router, 2, TIME + 7 * DAY, vec![], None)),
        ("unregister", s(Ctx::Unregister, f.router, 3, 0, vec![], None)),
        ("advertise", s(Ctx::Advertise, f.directory, 4, TIME + DAY, vec![], Some(f.descriptor.clone()))),
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
        "signed_message": "\"pigeonservice-v1-sig\" || 0x00 || ctx || 0x00 || canonical CBOR of the request body without Signature",
    }));
    out.insert("identity".into(), json!({
        "seed": x(&(0..32).collect::<Vec<u8>>()),
        "public_key": x(&f.id.public_key()),
        "service_id": x(&ServiceId::from_public_key(&f.id.public_key()).0),
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
        let ctx = name;
        let raw = Request::Signed(s.clone()).encode();
        assert_eq!(Request::decode(&raw).unwrap(), Request::Signed(s.clone()));
        assert_eq!(version::of(&raw).unwrap(), V1);
        s.verify().unwrap();
        let mut v = json!({
            "time": s.time, "revision": s.revision,
            "signed_message": x(&sign::message(ctx, &s.body())),
            "signature": x(&s.signature),
            "request": x(&raw),
            "max": s.ctx.max(),
        });
        if s.ctx.leases() {
            v["expiry"] = json!(s.expiry);
        }
        if !s.voucher.is_empty() {
            v["voucher"] = x(&s.voucher);
        }
        out.insert(name.into(), v);
    }
    let ciphertext = vec![0x5c; size::ROUTE_CIPHERTEXT];
    let id = ServiceId::from_public_key(&f.id.public_key());
    let others = [
        ("route", Request::Route { service_id: id, ciphertext: ciphertext.clone() }),
        ("lookup", Request::Lookup(id)),
        ("list", Request::List),
    ];
    for (name, r) in &others {
        let raw = r.encode();
        assert_eq!(&Request::decode(&raw).unwrap(), r);
        out.insert(name.to_string(), json!({"request": x(&raw), "max": r.max()}));
    }
    out["route"]["ciphertext"] = x(&ciphertext);

    let advertise = requests(&f).remove(3).1;
    let replies = [
        ("lease", Reply { expiry: TIME + 7 * DAY, ..Reply::status(Status::Ok) }),
        ("lookup", Reply { record: Some(advertise.clone()), ..Reply::status(Status::Ok) }),
        ("list", Reply { voucher: vec![0x22; 32], ..Reply::status(Status::Ok) }),
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
    let snap = Snapshot { seq: 7, records: vec![advertise] };
    let raw = snap.encode();
    assert_eq!(Snapshot::decode(&raw[4..]).unwrap(), snap);
    out.insert("list_connection".into(), json!({"seq": 7, "stream": x(&raw)}));
    out.insert("limits".into(), json!({
        "min_sphinx_user_payload": size::MIN_SPHINX_USER_PAYLOAD,
        "max_routers": size::MAX_ROUTERS, "max_endpoint": size::MAX_ENDPOINT, "max_scheme": size::MAX_SCHEME,
        "max_clock_skew_seconds": MAX_CLOCK_SKEW.as_secs(),
    }));
    out.insert("refused".into(), refused(&f));
    golden("pigeonservice/v1/vectors.json", out.into());
}

/// Requests a plugin at `TIME` that already took `renew` must refuse, each with its status.
fn refused(f: &Fixture) -> Value {
    let reqs = requests(f);
    let renew = reqs[1].1.clone();
    let mut bad_sig = renew.clone();
    bad_sig.revision = 9;
    let mut forged = renew.clone();
    forged.signature[0] ^= 1;
    forged.revision = 10;
    let wrong = Signed::new(&f.id, Ctx::Renew, f.directory, TIME, 11, TIME + DAY, vec![], None).unwrap();
    let late = Signed::new(&f.id, Ctx::Renew, f.router, TIME - 3600, 12, TIME + DAY, vec![], None).unwrap();
    let old = Signed::new(&f.id, Ctx::Renew, f.router, TIME, 1, TIME + DAY, vec![], None).unwrap();
    let long = Signed::new(&f.id, Ctx::Renew, f.router, TIME, 13, TIME + 30 * DAY, vec![], None).unwrap();
    let cases = [
        ("revision changed after signing", bad_sig, Status::BadSignature),
        ("signature altered", forged, Status::BadSignature),
        ("signed for the directory, sent to the router", wrong, Status::WrongRegistrar),
        ("an hour old", late, Status::BadTime),
        ("revision below the last taken", old, Status::Stale),
        ("lease past the longest", long, Status::InvalidRequest),
    ];
    let mut r = Registrar::new(f.router, pigeonhole_protocols::pigeonservice::MAX_LINK_TTL);
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

/// A v0 message is no v1 request, and a v0 plugin's answer is no v1 reply.
#[test]
fn versions_do_not_mix() {
    let v0_list = cbor::encode(&cbor::map(vec![("List", cbor::map(vec![]))]));
    match Request::decode(&v0_list) {
        Err(pigeonhole_protocols::pigeonservice::Error::UnsupportedVersion { ours, theirs }) => assert_eq!((ours, theirs), (vec![1], vec![0])),
        other => panic!("{other:?}"),
    }
    let v0_reply = pigeonhole_protocols::pigeonservice::wire::encode_router_reply(pigeonhole_protocols::pigeonservice::wire::Status::InvalidRequest);
    assert!(matches!(Reply::decode(&v0_reply), Err(pigeonhole_protocols::pigeonservice::Error::UnsupportedVersion { .. })));
    let v2 = cbor::encode(&cbor::map(vec![("V", cbor::uint(2)), ("List", cbor::map(vec![]))]));
    assert!(matches!(Request::decode(&v2), Err(pigeonhole_protocols::pigeonservice::Error::UnsupportedVersion { .. })));
}
