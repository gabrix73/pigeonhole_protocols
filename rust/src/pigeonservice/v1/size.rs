//! Every v1 message is one Sphinx packet, each way. The largest each can encode to is a constant
//! of the signature scheme's sizes, checked against the smallest Sphinx user payload this crate
//! supports when it compiles, and against the live mixnet's before each request.

use crate::pigeonservice::Error;
use crate::pigeonservice::nike;
use crate::pigeonservice::v1::sign::{FalconPadded512Ed25519, Scheme, Sizes};

/// The smallest Sphinx user payload this crate supports: namenlos' `UserForwardPayloadLength`.
pub const MIN_SPHINX_USER_PAYLOAD: usize = 2000;
/// The longest signature or NIKE scheme name.
pub const MAX_SCHEME: usize = 32;
/// The longest router endpoint, katzenpost's `RecipientIDLength`.
pub const MAX_ENDPOINT: usize = 32;
/// The most routers a descriptor names.
pub const MAX_ROUTERS: usize = 8;
/// A voucher sealed to a service's NIKE key.
pub const ROUTE_CIPHERTEXT: usize = nike::PUBLIC_KEY_SIZE + 32 + 16;

/// The largest CBOR unsigned integer.
const U64: usize = 9;
const ID: usize = 32;
const VOUCHER: usize = 32;
/// At least the CBOR keys and headers of any one message, measured by the tests below.
const FRAMING: usize = 160;
/// One router in a descriptor, with its framing.
const ROUTER: usize = 32 + MAX_ENDPOINT + 25;
const DESCRIPTOR: usize = MAX_SCHEME + nike::PUBLIC_KEY_SIZE + MAX_ROUTERS * ROUTER;

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
/// Advertise: a Renew and Descriptor.
pub const fn advertise_max<S: Sizes>() -> usize {
    renew_max::<S>() + DESCRIPTOR
}
/// A reply: Status, Expiry, Versions, and an Advertise or a voucher.
pub const fn reply_max<S: Sizes>() -> usize {
    advertise_max::<S>() + 2 * U64 + FRAMING
}
pub const ROUTE_MAX: usize = ID + ROUTE_CIPHERTEXT + FRAMING;
/// Lookup and List.
pub const LOOKUP_MAX: usize = ID + FRAMING;

const _: () = assert!(register_max::<Scheme>() <= MIN_SPHINX_USER_PAYLOAD, "v1 Register does not fit one Sphinx packet with sign::Scheme");
const _: () = assert!(renew_max::<Scheme>() <= MIN_SPHINX_USER_PAYLOAD, "v1 Renew does not fit one Sphinx packet with sign::Scheme");
const _: () = assert!(unregister_max::<Scheme>() <= MIN_SPHINX_USER_PAYLOAD, "v1 Unregister and Withdraw do not fit one Sphinx packet with sign::Scheme");
const _: () = assert!(advertise_max::<Scheme>() <= MIN_SPHINX_USER_PAYLOAD, "v1 Advertise does not fit one Sphinx packet with sign::Scheme");
const _: () = assert!(reply_max::<Scheme>() <= MIN_SPHINX_USER_PAYLOAD, "a v1 Lookup reply does not fit one Sphinx packet with sign::Scheme");
const _: () = assert!(ROUTE_MAX <= MIN_SPHINX_USER_PAYLOAD, "v1 Route does not fit one Sphinx packet");
// The router's requests fit with the hybrid scheme v1 is meant for too. Advertise and its
// Lookup reply do not (2832 B): with it the descriptor has to move to layer 1.
const _: () = assert!(register_max::<FalconPadded512Ed25519>() <= MIN_SPHINX_USER_PAYLOAD, "v1 Register does not fit one Sphinx packet with Falcon-padded-512-Ed25519");
const _: () = assert!(renew_max::<FalconPadded512Ed25519>() <= MIN_SPHINX_USER_PAYLOAD, "v1 Renew does not fit one Sphinx packet with Falcon-padded-512-Ed25519");
const _: () = assert!(unregister_max::<FalconPadded512Ed25519>() <= MIN_SPHINX_USER_PAYLOAD, "v1 Unregister does not fit one Sphinx packet with Falcon-padded-512-Ed25519");

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
        ("Lookup and its reply", reply_max::<Scheme>()),
        ("List", LOOKUP_MAX),
    ]
    .into_iter()
    .try_for_each(|(what, max)| fits(what, max, 0, limit))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pigeonservice::v1::sign::{Ed25519, Identity};
    use crate::pigeonservice::v1::wire::*;

    fn maximal(ctx: Ctx) -> Signed {
        let descriptor = (ctx == Ctx::Advertise).then(|| Descriptor {
            nike_scheme: "N".repeat(MAX_SCHEME),
            nike_public_key: vec![0xff; nike::PUBLIC_KEY_SIZE],
            routers: vec![RouterRef { node_id_hash: [0xff; 32], endpoint: "e".repeat(MAX_ENDPOINT) }; MAX_ROUTERS],
        });
        let voucher = if ctx == Ctx::Register { vec![0xff; 32] } else { vec![] };
        let mut s = Signed::new(&Identity::generate(), ctx, [0xff; 32], u64::MAX, u64::MAX, u64::MAX, voucher, descriptor).unwrap();
        // The longest scheme name the decoder takes.
        s.scheme = "S".repeat(MAX_SCHEME);
        s
    }

    /// Each message at its fields' maxima encodes to at most its bound, so FRAMING is enough.
    #[test]
    fn bounds_hold() {
        for ctx in [Ctx::Register, Ctx::Renew, Ctx::Unregister, Ctx::Advertise, Ctx::Withdraw] {
            let len = Request::Signed(maximal(ctx)).encode().len();
            assert!(len <= ctx.max(), "{ctx:?}: {len} > {}", ctx.max());
        }
        let route = Request::Route { service_id: ServiceId([0xff; 32]), ciphertext: vec![0xff; ROUTE_CIPHERTEXT] };
        assert!(route.encode().len() <= ROUTE_MAX);
        assert!(Request::Lookup(ServiceId([0xff; 32])).encode().len() <= LOOKUP_MAX);
        let reply = Reply { status: 255, expiry: u64::MAX, record: Some(maximal(Ctx::Advertise)), voucher: vec![0xff; 32], versions: vec![0xff; 8] };
        assert!(reply.encode().len() <= reply_max::<Scheme>());
    }

    #[test]
    fn oversize_is_refused() {
        check_geometry(MIN_SPHINX_USER_PAYLOAD).unwrap();
        let Err(Error::Oversize(e)) = check_geometry(1000) else { panic!() };
        assert!(e.contains("UserForwardPayloadLength) is 1000 B"), "{e}");
        assert!(fits("Register", register_max::<Scheme>(), 2500, MIN_SPHINX_USER_PAYLOAD).is_err());
    }

    /// The table in the pull request.
    #[test]
    fn table() {
        fn row<S: Sizes>() {
            println!(
                "{:<28} Register {:>4}  Renew {:>4}  Unregister/Withdraw {:>4}  Advertise {:>4}  reply {:>4}  (limit {MIN_SPHINX_USER_PAYLOAD})",
                S::NAME,
                register_max::<S>(),
                renew_max::<S>(),
                unregister_max::<S>(),
                advertise_max::<S>(),
                reply_max::<S>()
            );
        }
        row::<Ed25519>();
        row::<FalconPadded512Ed25519>();
        println!("Route {ROUTE_MAX}  Lookup/List {LOOKUP_MAX}");
        for ctx in [Ctx::Register, Ctx::Renew, Ctx::Unregister, Ctx::Advertise, Ctx::Withdraw] {
            println!("{:<10} at maxima, Ed25519: {} B", ctx.name(), Request::Signed(maximal(ctx)).encode().len());
        }
    }
}
