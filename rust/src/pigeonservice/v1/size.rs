//! Every v1 layer-0 message is one Sphinx packet, each way. The largest each can encode to is a
//! constant of the signature scheme's sizes, checked against the smallest Sphinx user payload
//! this crate supports when it compiles, and against the live mixnet's before each request. The
//! records that do not fit, the descriptor with its 929-byte key, travel in layer 1.

use crate::pigeonservice::Error;
use crate::pigeonservice::nike;
use crate::pigeonservice::v1::sign::{Scheme, Sizes};

/// The smallest Sphinx user payload this crate supports: namenlos' `UserForwardPayloadLength`.
pub const MIN_SPHINX_USER_PAYLOAD: usize = 2000;
/// The longest signature or NIKE scheme name.
pub const MAX_SCHEME: usize = 32;
/// The longest router endpoint, katzenpost's `RecipientIDLength`.
pub const MAX_ENDPOINT: usize = 32;
/// The most routers a descriptor names.
pub const MAX_ROUTERS: usize = 8;
/// The most protocols a descriptor names, and the longest name of one.
pub const MAX_PROTOCOLS: usize = 8;
pub const MAX_PROTOCOL: usize = 32;
/// A listing's longest name, type and description, in bytes.
pub const MAX_NAME: usize = 64;
pub const MAX_TYPE: usize = 32;
pub const MAX_DESCRIPTION: usize = 280;
/// A voucher sealed to a service's NIKE key.
pub const ROUTE_CIPHERTEXT: usize = nike::PUBLIC_KEY_SIZE + 32 + 16;

/// The largest CBOR unsigned integer.
const U64: usize = 9;
const ID: usize = 32;
const VOUCHER: usize = 32;
/// At least the CBOR keys and headers of any one message, measured by the tests below.
const FRAMING: usize = 160;

/// Unregister and Withdraw: V, Scheme, PublicKey, Registrar, Time, Revision, Signature.
pub const fn unregister_max<S: Sizes>() -> usize {
    U64 + MAX_SCHEME + S::PUBLIC_KEY + ID + 2 * U64 + S::SIGNATURE + FRAMING
}
/// Renew: an Unregister and Expiry.
pub const fn renew_max<S: Sizes>() -> usize {
    unregister_max::<S>() + U64
}
/// Register: a Renew and Voucher.
pub const fn register_max<S: Sizes>() -> usize {
    renew_max::<S>() + VOUCHER
}
/// Advertise: a Register and Record.
pub const fn advertise_max<S: Sizes>() -> usize {
    register_max::<S>() + ID
}
pub const ROUTE_MAX: usize = ID + ROUTE_CIPHERTEXT + FRAMING;
pub const RESOLVE_MAX: usize = ID + FRAMING;
pub const SEARCH_MAX: usize = MAX_NAME + MAX_TYPE + FRAMING;
/// A reply: Status, Expiry, Voucher, Versions.
pub const REPLY_MAX: usize = 2 * U64 + VOUCHER + 8 + FRAMING;

const _: () = assert!(register_max::<Scheme>() <= MIN_SPHINX_USER_PAYLOAD, "v1 Register does not fit one Sphinx packet with sign::Scheme");
const _: () = assert!(renew_max::<Scheme>() <= MIN_SPHINX_USER_PAYLOAD, "v1 Renew does not fit one Sphinx packet with sign::Scheme");
const _: () = assert!(unregister_max::<Scheme>() <= MIN_SPHINX_USER_PAYLOAD, "v1 Unregister and Withdraw do not fit one Sphinx packet with sign::Scheme");
const _: () = assert!(advertise_max::<Scheme>() <= MIN_SPHINX_USER_PAYLOAD, "v1 Advertise does not fit one Sphinx packet with sign::Scheme");
const _: () = assert!(ROUTE_MAX <= MIN_SPHINX_USER_PAYLOAD, "v1 Route does not fit one Sphinx packet");
const _: () = assert!(RESOLVE_MAX <= MIN_SPHINX_USER_PAYLOAD, "v1 Resolve does not fit one Sphinx packet");
const _: () = assert!(SEARCH_MAX <= MIN_SPHINX_USER_PAYLOAD, "v1 Search does not fit one Sphinx packet");
const _: () = assert!(REPLY_MAX <= MIN_SPHINX_USER_PAYLOAD, "a v1 reply does not fit one Sphinx packet");

fn refuse(what: &str, need: usize, limit: usize) -> Error {
    Error::Oversize(format!(
        "refusing to send a v1 {what}: with {} (public key {} B, signature {} B) it takes up to {need} B, \
         but this mixnet's Sphinx user payload (UserForwardPayloadLength) is {limit} B",
        Scheme::NAME,
        Scheme::PUBLIC_KEY,
        Scheme::SIGNATURE
    ))
}

/// Checks that a `what` request of `len` bytes, which with its reply may take up to `max`, fits a
/// Sphinx user payload of `limit` bytes.
pub fn fits(what: &str, max: usize, len: usize, limit: usize) -> Result<(), Error> {
    let need = max.max(len);
    if need > limit {
        return Err(refuse(what, need, limit));
    }
    Ok(())
}

/// Checks every v1 message against a Sphinx user payload of `limit` bytes, as a service does
/// before it registers.
pub fn check_geometry(limit: usize) -> Result<(), Error> {
    [
        ("Register", register_max::<Scheme>()),
        ("Renew", renew_max::<Scheme>()),
        ("Unregister", unregister_max::<Scheme>()),
        ("Advertise", advertise_max::<Scheme>()),
        ("Withdraw", unregister_max::<Scheme>()),
        ("Route", ROUTE_MAX),
        ("Resolve", RESOLVE_MAX),
        ("Search", SEARCH_MAX),
        ("reply", REPLY_MAX),
    ]
    .into_iter()
    .try_for_each(|(what, max)| fits(what, max, 0, limit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pigeonservice::v1::sign::{Ed25519, FalconPadded512Ed25519, Identity};
    use crate::pigeonservice::v1::wire::*;

    fn maximal(id: &Identity, ctx: Ctx) -> Signed {
        let voucher = if ctx.vouches() { vec![0xff; 32] } else { vec![] };
        let record = (ctx == Ctx::Advertise).then_some([0xff; 32]);
        let mut s = Signed::new(id, ctx, [0xff; 32], u64::MAX, u64::MAX, u64::MAX, voucher, record).unwrap();
        // The longest scheme name the decoder takes.
        s.scheme = "S".repeat(MAX_SCHEME);
        s
    }

    fn maximal_entry(id: &Identity) -> Entry {
        let descriptor = Descriptor {
            nike_scheme: "N".repeat(MAX_SCHEME),
            nike_public_key: vec![0xff; nike::PUBLIC_KEY_SIZE],
            routers: vec![RouterRef { node_id_hash: [0xff; 32], endpoint: "e".repeat(MAX_ENDPOINT) }; MAX_ROUTERS],
            protocols: vec!["p".repeat(MAX_PROTOCOL); MAX_PROTOCOLS],
            revision: u64::MAX,
            expiry: u64::MAX,
            ..Default::default()
        };
        let listing = Listing {
            name: "n".repeat(MAX_NAME),
            kind: "t".repeat(MAX_TYPE),
            description: "d".repeat(MAX_DESCRIPTION),
            revision: u64::MAX,
            expiry: u64::MAX,
            ..Default::default()
        };
        Entry { descriptor: descriptor.sign(id).unwrap(), listing: Some(listing.sign(id).unwrap()) }
    }

    /// Each message at its fields' maxima encodes to at most its bound, so FRAMING is enough.
    #[test]
    fn bounds_hold() {
        let id = Identity::from_seed(&[1; 64]).unwrap();
        for ctx in Ctx::ALL {
            let len = Request::Signed(maximal(&id, ctx)).encode().len();
            assert!(len <= ctx.max(), "{ctx:?}: {len} > {}", ctx.max());
        }
        let route = Request::Route { service_id: ServiceId([0xff; 32]), ciphertext: vec![0xff; ROUTE_CIPHERTEXT] };
        assert!(route.encode().len() <= ROUTE_MAX);
        assert!(Request::Resolve([0xff; 32]).encode().len() <= RESOLVE_MAX);
        assert!(Request::Search { name: "n".repeat(MAX_NAME), kind: "t".repeat(MAX_TYPE) }.encode().len() <= SEARCH_MAX);
        let reply = Reply { status: 255, expiry: u64::MAX, voucher: vec![0xff; 32], versions: vec![0xff; 8] };
        assert!(reply.encode().len() <= REPLY_MAX);
    }

    #[test]
    fn oversize_is_refused() {
        check_geometry(MIN_SPHINX_USER_PAYLOAD).unwrap();
        let Err(Error::Oversize(e)) = check_geometry(1000) else { panic!() };
        assert!(e.contains("Falcon-padded-512-Ed25519 (public key 929 B, signature 730 B)") && e.contains("UserForwardPayloadLength) is 1000 B"), "{e}");
        assert!(fits("Register", register_max::<Scheme>(), 2500, MIN_SPHINX_USER_PAYLOAD).is_err());
        let long = Listing { name: "n".repeat(MAX_NAME + 1), ..Default::default() };
        assert!(matches!(long.sign(&Identity::from_seed(&[1; 64]).unwrap()), Err(Error::Oversize(_))));
    }

    /// The table in the pull request.
    #[test]
    fn table() {
        fn row<S: Sizes>() {
            println!(
                "{:<26} Register {:>4}  Renew {:>4}  Unregister/Withdraw {:>4}  Advertise {:>4}  (limit {MIN_SPHINX_USER_PAYLOAD})",
                S::NAME,
                register_max::<S>(),
                renew_max::<S>(),
                unregister_max::<S>(),
                advertise_max::<S>(),
            );
        }
        row::<Ed25519>();
        row::<FalconPadded512Ed25519>();
        println!("Route {ROUTE_MAX}  Resolve {RESOLVE_MAX}  Search {SEARCH_MAX}  reply {REPLY_MAX}");
        let id = Identity::from_seed(&[1; 64]).unwrap();
        for ctx in Ctx::ALL {
            println!("{:<10} at maxima: {} B, bound {}", ctx.name(), Request::Signed(maximal(&id, ctx)).encode().len(), ctx.max());
        }
        let e = maximal_entry(&id);
        println!(
            "layer 1 at maxima: descriptor entry {} B, with the listing {} B (namenlos box 1549 B)",
            Entry { listing: None, ..e.clone() }.encode().len(),
            e.encode().len()
        );
    }
}
