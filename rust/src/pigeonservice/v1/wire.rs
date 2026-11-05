//! The v1 messages, as CBOR maps with text keys in canonical order (shortest first, then
//! bytewise), as v0's. A request is `{"V": 1, <type>: <body>}`, a reply `{"V": 1, "Status": n,
//! ...}`.
//!
//! Layer 0, to the plugins, each one Sphinx packet ([`super::size`]):
//!
//! ```text
//! Register   { Scheme, PublicKey, Registrar, Time, Revision, Expiry, Voucher, Signature }          router
//! Renew      { Scheme, PublicKey, Registrar, Time, Revision, Expiry, Signature }                   router
//! Unregister { Scheme, PublicKey, Registrar, Time, Revision, Signature }                           router
//! Route      { ServiceID, Ciphertext }                                                             router
//! Advertise  { Scheme, PublicKey, Registrar, Time, Revision, Expiry, Voucher, Record, Signature }  directory
//! Withdraw   { Scheme, PublicKey, Registrar, Time, Revision, Signature }                           directory
//! Resolve    { Lookup }                                                                            directory
//! Search     { Name, Type }                                                                        directory
//! Reply      { V, Status, Expiry?, Voucher?, Versions? }
//! ```
//!
//! Layer 1, over Pigeonhole connections, each signed by the service on its own:
//!
//! ```text
//! Descriptor { V, PublicKey, NIKEScheme, NIKEPublicKey, Routers: [{NodeIDHash, Endpoint}], Protocols, Revision, Expiry, Signature }
//! Listing    { V, PublicKey, Name, Type, Description, Revision, Expiry, Signature }
//! Entry      { Descriptor, Listing? }     a service to a directory, and a directory to a client resolving
//! Listings   { Listings: [Listing] }      a directory to a client searching
//! ```
//!
//! each sent as a 4-byte big-endian length and the CBOR, over as many messages as it takes.
//!
//! A service is its key: its [`Address`] is BLAKE2b-256 of it, the ServiceID routers route by,
//! and its descriptor carries the key for a client to check against the address. A request's
//! `Registrar` is BLAKE2b-256 of the plugin's node ID hash and endpoint ([`registrar_id`]); `Time`
//! is the sender's clock in Unix seconds; `Revision` exceeds that of the sender's last request to
//! the registrar. Each signature is over its message without `Signature` ([`super::sign`]).
//!
//! Register and Advertise carry a voucher the service minted: the router inducts it to open the
//! service's link, the directory to read the service's Entry, whose digest is Advertise's
//! `Record`. A service with a Listing in its Entry is public and found by Search; one without is
//! hidden, found only by those who know its address. Resolve names the service by its lookup for
//! the current period ([`Address::lookup`]), Search by a name and a type, either empty for any.
//! Both are answered with a one-time `Voucher` whose connection carries the answer. Layer 0
//! hands out no read caps.

use blake2::{Blake2b, Digest, digest::consts::U32};

use crate::pigeonservice::Error;
use crate::pigeonservice::cbor::{self, Fields, Value};
use crate::pigeonservice::nike;
use crate::pigeonservice::v1::address::Address;
use crate::pigeonservice::v1::sign::{self, Identity, Scheme, Sizes};
use crate::pigeonservice::v1::size;
use crate::pigeonservice::version::{FIELD, V1};
pub use crate::pigeonservice::v0::wire::{RouterRef, ServiceId};

/// Reply status codes, v0's and then v1's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    InvalidRequest,
    BadSignature,
    UnknownService,
    /// A revision no higher than the last.
    Stale,
    Busy,
    InternalError,
    /// The message's version is not one the plugin serves; the reply lists those it does.
    UnsupportedVersion,
    /// The request names another registrar.
    WrongRegistrar,
    /// The request's time is too far from the plugin's clock.
    BadTime,
}

impl Status {
    pub fn from_u8(n: u8) -> Option<Self> {
        use Status::*;
        [Ok, InvalidRequest, BadSignature, UnknownService, Stale, Busy, InternalError, UnsupportedVersion, WrongRegistrar, BadTime]
            .get(n as usize)
            .copied()
    }
}

/// The registrar ID of the plugin at `endpoint` on the node whose identity hash is `node`.
pub fn registrar_id(node: &[u8; 32], endpoint: &[u8]) -> [u8; 32] {
    Blake2b::<U32>::new().chain_update(node).chain_update(endpoint).finalize().into()
}

fn too_long(what: &str, max: usize) -> Error {
    Error::Oversize(format!("{what} is at most {max}"))
}

/// What a client needs to reach a service, signed by it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Descriptor {
    pub public_key: Vec<u8>,
    pub nike_scheme: String,
    pub nike_public_key: Vec<u8>,
    pub routers: Vec<RouterRef>,
    /// The protocols the service speaks, with their versions: `echo/1`.
    pub protocols: Vec<String>,
    pub revision: u64,
    /// Unix seconds.
    pub expiry: u64,
    pub signature: Vec<u8>,
}

impl Descriptor {
    const CTX: &'static str = "descriptor";

    /// The descriptor, with `id`'s key, signed by it.
    pub fn sign(mut self, id: &Identity) -> Result<Self, Error> {
        self.public_key = id.public_key();
        self.check()?;
        self.signature = id.sign(Self::CTX, &self.body());
        Ok(self)
    }

    pub fn address(&self) -> Address {
        Address::of(&self.public_key)
    }

    /// Checks the signature.
    pub fn verify(&self) -> Result<(), Error> {
        sign::verify(&self.public_key, Self::CTX, &self.body(), &self.signature)
    }

    fn check(&self) -> Result<(), Error> {
        if self.routers.len() > size::MAX_ROUTERS {
            return Err(too_long("a descriptor's router list", size::MAX_ROUTERS));
        }
        if self.routers.iter().any(|r| r.endpoint.len() > size::MAX_ENDPOINT) {
            return Err(too_long("a router endpoint, in bytes", size::MAX_ENDPOINT));
        }
        if self.nike_scheme.len() > size::MAX_SCHEME || self.nike_public_key.len() > nike::PUBLIC_KEY_SIZE {
            return Err(Error::Oversize("NIKE scheme name or key too long".into()));
        }
        if self.protocols.len() > size::MAX_PROTOCOLS || self.protocols.iter().any(|p| p.len() > size::MAX_PROTOCOL) {
            return Err(Error::Oversize(format!("a descriptor names at most {} protocols of at most {} bytes", size::MAX_PROTOCOLS, size::MAX_PROTOCOL)));
        }
        if self.public_key.len() > Scheme::PUBLIC_KEY {
            return Err(Error::Decode("descriptor: key too long".into()));
        }
        Ok(())
    }

    pub fn body(&self) -> Value {
        cbor::map(self.fields())
    }

    fn fields(&self) -> Vec<(&'static str, Value)> {
        vec![
            (FIELD, cbor::uint(V1 as u64)),
            ("PublicKey", cbor::bytes(&self.public_key)),
            ("NIKEScheme", cbor::text(&self.nike_scheme)),
            ("NIKEPublicKey", cbor::bytes(&self.nike_public_key)),
            ("Routers", Value::Array(self.routers.iter().map(RouterRef::to_value).collect())),
            ("Protocols", Value::Array(self.protocols.iter().map(|p| cbor::text(p)).collect())),
            ("Revision", cbor::uint(self.revision)),
            ("Expiry", cbor::uint(self.expiry)),
        ]
    }

    fn to_value(&self) -> Value {
        let mut f = self.fields();
        f.push(("Signature", cbor::bytes(&self.signature)));
        cbor::map(f)
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = Fields::of(v)?;
        record_version(&f)?;
        let d = Descriptor {
            public_key: f.bytes("PublicKey")?,
            nike_scheme: f.text("NIKEScheme")?,
            nike_public_key: f.bytes("NIKEPublicKey")?,
            routers: f.array("Routers")?.iter().map(RouterRef::from_value).collect::<Result<_, _>>()?,
            protocols: f.array("Protocols")?.iter().map(text).collect::<Result<_, _>>()?,
            revision: f.uint("Revision")?,
            expiry: f.uint("Expiry")?,
            signature: f.bytes("Signature")?,
        };
        d.check()?;
        Ok(d)
    }
}

fn text(v: &Value) -> Result<String, Error> {
    v.as_text().map(str::to_string).ok_or_else(|| Error::Decode("expected text".into()))
}

fn record_version(f: &Fields) -> Result<(), Error> {
    match f.uint(FIELD)? {
        1 => Ok(()),
        v => Err(Error::VersionMismatch { service: "a service record".into(), requested: V1, supported: vec![v as u8] }),
    }
}

/// A public service's listing: what it is, for anyone to find. Names are labels, not unique;
/// the address is the service.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Listing {
    pub public_key: Vec<u8>,
    pub name: String,
    /// What kind of service it is: `chatbot`.
    pub kind: String,
    pub description: String,
    pub revision: u64,
    /// Unix seconds.
    pub expiry: u64,
    pub signature: Vec<u8>,
}

impl Listing {
    const CTX: &'static str = "listing";

    /// The listing, with `id`'s key, signed by it.
    pub fn sign(mut self, id: &Identity) -> Result<Self, Error> {
        self.public_key = id.public_key();
        self.check()?;
        self.signature = id.sign(Self::CTX, &self.body());
        Ok(self)
    }

    pub fn address(&self) -> Address {
        Address::of(&self.public_key)
    }

    pub fn verify(&self) -> Result<(), Error> {
        sign::verify(&self.public_key, Self::CTX, &self.body(), &self.signature)
    }

    /// Whether a search for `name` and `kind` finds it: `name` within its name and `kind` its
    /// kind, either case; empty matches any.
    pub fn matches(&self, name: &str, kind: &str) -> bool {
        self.name.to_lowercase().contains(&name.to_lowercase()) && (kind.is_empty() || self.kind.eq_ignore_ascii_case(kind))
    }

    fn check(&self) -> Result<(), Error> {
        if self.name.len() > size::MAX_NAME || self.kind.len() > size::MAX_TYPE || self.description.len() > size::MAX_DESCRIPTION {
            return Err(Error::Oversize(format!(
                "a listing's name, type and description are at most {}, {} and {} bytes",
                size::MAX_NAME,
                size::MAX_TYPE,
                size::MAX_DESCRIPTION
            )));
        }
        if self.public_key.len() > Scheme::PUBLIC_KEY {
            return Err(Error::Decode("listing: key too long".into()));
        }
        Ok(())
    }

    pub fn body(&self) -> Value {
        cbor::map(self.fields())
    }

    fn fields(&self) -> Vec<(&'static str, Value)> {
        vec![
            (FIELD, cbor::uint(V1 as u64)),
            ("PublicKey", cbor::bytes(&self.public_key)),
            ("Name", cbor::text(&self.name)),
            ("Type", cbor::text(&self.kind)),
            ("Description", cbor::text(&self.description)),
            ("Revision", cbor::uint(self.revision)),
            ("Expiry", cbor::uint(self.expiry)),
        ]
    }

    fn to_value(&self) -> Value {
        let mut f = self.fields();
        f.push(("Signature", cbor::bytes(&self.signature)));
        cbor::map(f)
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = Fields::of(v)?;
        record_version(&f)?;
        let l = Listing {
            public_key: f.bytes("PublicKey")?,
            name: f.text("Name")?,
            kind: f.text("Type")?,
            description: f.text("Description")?,
            revision: f.uint("Revision")?,
            expiry: f.uint("Expiry")?,
            signature: f.bytes("Signature")?,
        };
        l.check()?;
        Ok(l)
    }
}

/// What a directory holds of a service: its descriptor, and its listing if it is public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub descriptor: Descriptor,
    pub listing: Option<Listing>,
}

impl Entry {
    pub fn encode(&self) -> Vec<u8> {
        let mut f = vec![("Descriptor", self.descriptor.to_value())];
        if let Some(l) = &self.listing {
            f.push(("Listing", l.to_value()));
        }
        cbor::encode(&cbor::map(f))
    }

    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let v = cbor::decode(raw)?;
        let f = Fields::of(&v)?;
        Ok(Entry {
            descriptor: Descriptor::from_value(f.get("Descriptor").ok_or_else(|| Error::Decode("entry without a descriptor".into()))?)?,
            listing: f.get("Listing").map(Listing::from_value).transpose()?,
        })
    }

    /// What Advertise's `Record` names.
    pub fn digest(&self) -> [u8; 32] {
        Blake2b::<U32>::digest(self.encode()).into()
    }

    pub fn address(&self) -> Address {
        self.descriptor.address()
    }

    /// Checks that the service signed both records.
    pub fn verify(&self) -> Result<(), Error> {
        self.descriptor.verify()?;
        if let Some(l) = &self.listing {
            if l.public_key != self.descriptor.public_key {
                return Err(Error::BadSignature);
            }
            l.verify()?;
        }
        Ok(())
    }
}

pub fn encode_listings(listings: &[Listing]) -> Vec<u8> {
    cbor::encode(&cbor::map(vec![("Listings", Value::Array(listings.iter().map(Listing::to_value).collect()))]))
}

pub fn decode_listings(raw: &[u8]) -> Result<Vec<Listing>, Error> {
    let v = cbor::decode(raw)?;
    Fields::of(&v)?.array("Listings")?.iter().map(Listing::from_value).collect()
}

/// A layer-1 message as it goes on a connection: a 4-byte big-endian length, then `body`.
pub fn frame(body: &[u8]) -> Vec<u8> {
    [&(body.len() as u32).to_be_bytes()[..], body].concat()
}

/// A signed request's type, and its signature context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ctx {
    Register,
    Renew,
    Unregister,
    Advertise,
    Withdraw,
}

impl Ctx {
    pub const ALL: [Ctx; 5] = [Ctx::Register, Ctx::Renew, Ctx::Unregister, Ctx::Advertise, Ctx::Withdraw];

    /// The request's key in the message.
    pub fn name(self) -> &'static str {
        match self {
            Ctx::Register => "Register",
            Ctx::Renew => "Renew",
            Ctx::Unregister => "Unregister",
            Ctx::Advertise => "Advertise",
            Ctx::Withdraw => "Withdraw",
        }
    }

    /// Its signature context.
    pub fn sig_ctx(self) -> &'static str {
        match self {
            Ctx::Register => "register",
            Ctx::Renew => "renew",
            Ctx::Unregister => "unregister",
            Ctx::Advertise => "advertise",
            Ctx::Withdraw => "withdraw",
        }
    }

    /// Whether the request asks for a lease.
    pub fn leases(self) -> bool {
        matches!(self, Ctx::Register | Ctx::Renew | Ctx::Advertise)
    }

    /// Whether it carries a voucher.
    pub fn vouches(self) -> bool {
        matches!(self, Ctx::Register | Ctx::Advertise)
    }

    /// The most the request can encode to with [`Scheme`].
    pub fn max(self) -> usize {
        match self {
            Ctx::Register => size::register_max::<Scheme>(),
            Ctx::Renew => size::renew_max::<Scheme>(),
            Ctx::Unregister | Ctx::Withdraw => size::unregister_max::<Scheme>(),
            Ctx::Advertise => size::advertise_max::<Scheme>(),
        }
    }
}

/// A request signed by the service whose key it carries: a registration, an update or a
/// revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub ctx: Ctx,
    pub scheme: String,
    pub public_key: Vec<u8>,
    pub registrar: [u8; 32],
    pub time: u64,
    pub revision: u64,
    /// The lease asked for, in Unix seconds; 0 in requests that ask for none.
    pub expiry: u64,
    /// The voucher of a Register or an Advertise; else empty.
    pub voucher: Vec<u8>,
    /// An Advertise's [`Entry::digest`].
    pub record: Option<[u8; 32]>,
    pub signature: Vec<u8>,
}

impl Signed {
    /// A `ctx` request by `id` to `registrar`, signed. `voucher` is for a Register or an
    /// Advertise, and `record` for an Advertise.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &Identity,
        ctx: Ctx,
        registrar: [u8; 32],
        time: u64,
        revision: u64,
        expiry: u64,
        voucher: Vec<u8>,
        record: Option<[u8; 32]>,
    ) -> Result<Self, Error> {
        let mut s = Signed {
            ctx,
            scheme: Scheme::NAME.into(),
            public_key: id.public_key(),
            registrar,
            time,
            revision,
            expiry: if ctx.leases() { expiry } else { 0 },
            voucher,
            record,
            signature: vec![],
        };
        s.check()?;
        s.signature = id.sign(ctx.sig_ctx(), &s.body());
        Ok(s)
    }

    /// The service the request is from.
    pub fn id(&self) -> ServiceId {
        ServiceId::from_public_key(&self.public_key)
    }

    /// Checks the signature.
    pub fn verify(&self) -> Result<(), Error> {
        if self.scheme != Scheme::NAME {
            return Err(Error::BadSignature);
        }
        sign::verify(&self.public_key, self.ctx.sig_ctx(), &self.body(), &self.signature)
    }

    fn check(&self) -> Result<(), Error> {
        let voucher_ok = if self.ctx.vouches() { self.voucher.len() == 32 } else { self.voucher.is_empty() };
        if !voucher_ok || self.record.is_some() != (self.ctx == Ctx::Advertise) || (self.ctx.leases() && self.expiry == 0) {
            return Err(Error::Decode(format!("malformed {}", self.ctx.name())));
        }
        if self.scheme.len() > size::MAX_SCHEME || self.public_key.len() > Scheme::PUBLIC_KEY {
            return Err(Error::Decode(format!("{}: scheme name or key too long", self.ctx.name())));
        }
        Ok(())
    }

    fn fields(&self) -> Vec<(&'static str, Value)> {
        let mut fields = vec![
            ("Scheme", cbor::text(&self.scheme)),
            ("PublicKey", cbor::bytes(&self.public_key)),
            ("Registrar", cbor::bytes(&self.registrar)),
            ("Time", cbor::uint(self.time)),
            ("Revision", cbor::uint(self.revision)),
        ];
        if self.ctx.leases() {
            fields.push(("Expiry", cbor::uint(self.expiry)));
        }
        if self.ctx.vouches() {
            fields.push(("Voucher", cbor::bytes(&self.voucher)));
        }
        if let Some(r) = &self.record {
            fields.push(("Record", cbor::bytes(r)));
        }
        fields
    }

    /// The request as signed: without its signature.
    pub fn body(&self) -> Value {
        cbor::map(self.fields())
    }

    fn to_value(&self) -> Value {
        let mut fields = self.fields();
        fields.push(("Signature", cbor::bytes(&self.signature)));
        cbor::map(fields)
    }

    fn from_value(ctx: Ctx, v: &Value) -> Result<Self, Error> {
        let f = Fields::of(v)?;
        let s = Signed {
            ctx,
            scheme: f.text("Scheme")?,
            public_key: f.bytes("PublicKey")?,
            registrar: f.array32("Registrar")?,
            time: f.uint("Time")?,
            revision: f.uint("Revision")?,
            expiry: if ctx.leases() { f.uint("Expiry")? } else { 0 },
            voucher: if ctx.vouches() { f.bytes("Voucher")? } else { vec![] },
            record: if ctx == Ctx::Advertise { Some(f.array32("Record")?) } else { None },
            signature: f.bytes("Signature")?,
        };
        s.check()?;
        Ok(s)
    }
}

/// A v1 request to a router or a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Signed(Signed),
    Route { service_id: ServiceId, ciphertext: Vec<u8> },
    /// A service by its [`Address::lookup`].
    Resolve([u8; 32]),
    /// Public services by name and type.
    Search { name: String, kind: String },
}

impl Request {
    pub fn name(&self) -> &'static str {
        match self {
            Request::Signed(s) => s.ctx.name(),
            Request::Route { .. } => "Route",
            Request::Resolve(_) => "Resolve",
            Request::Search { .. } => "Search",
        }
    }

    /// The most the request or its reply can encode to.
    pub fn max(&self) -> usize {
        let request = match self {
            Request::Signed(s) => s.ctx.max(),
            Request::Route { .. } => size::ROUTE_MAX,
            Request::Resolve(_) => size::RESOLVE_MAX,
            Request::Search { .. } => size::SEARCH_MAX,
        };
        request.max(size::REPLY_MAX)
    }

    pub fn encode(&self) -> Vec<u8> {
        let (name, body) = match self {
            Request::Signed(s) => (s.ctx.name(), s.to_value()),
            Request::Route { service_id, ciphertext } => {
                ("Route", cbor::map(vec![("ServiceID", cbor::bytes(&service_id.0)), ("Ciphertext", cbor::bytes(ciphertext))]))
            }
            Request::Resolve(lookup) => ("Resolve", cbor::map(vec![("Lookup", cbor::bytes(lookup))])),
            Request::Search { name, kind } => ("Search", cbor::map(vec![("Name", cbor::text(name)), ("Type", cbor::text(kind))])),
        };
        cbor::encode(&cbor::map(vec![(FIELD, cbor::uint(V1 as u64)), (name, body)]))
    }

    /// Decodes a v1 request. A request in another version is [`Error::VersionMismatch`].
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if let Some(v) = other_version(raw)? {
            return Err(mismatch(v, vec![V1]));
        }
        let v = cbor::decode(raw)?;
        let f = Fields::of(&v)?;
        for ctx in Ctx::ALL {
            if let Some(b) = f.get(ctx.name()) {
                return Ok(Request::Signed(Signed::from_value(ctx, b)?));
            }
        }
        if let Some(r) = f.get("Route") {
            let r = Fields::of(r)?;
            let ciphertext = r.bytes("Ciphertext")?;
            if ciphertext.len() > size::ROUTE_CIPHERTEXT {
                return Err(Error::Decode("Route: ciphertext too long".into()));
            }
            return Ok(Request::Route { service_id: ServiceId(r.array32("ServiceID")?), ciphertext });
        }
        if let Some(r) = f.get("Resolve") {
            return Ok(Request::Resolve(Fields::of(r)?.array32("Lookup")?));
        }
        if let Some(r) = f.get("Search") {
            let r = Fields::of(r)?;
            let (name, kind) = (r.text("Name")?, r.text("Type")?);
            if name.len() > size::MAX_NAME || kind.len() > size::MAX_TYPE {
                return Err(Error::Decode("Search: name or type too long".into()));
            }
            return Ok(Request::Search { name, kind });
        }
        Err(Error::Decode("empty v1 request".into()))
    }
}

/// The client speaks `requested`, the service `supported`. Callers that know the service type
/// fill it in.
fn mismatch(requested: u8, supported: Vec<u8>) -> Error {
    Error::VersionMismatch { service: "a layer-0 plugin".into(), requested, supported }
}

/// The version of `raw`, a message from a peer, if it is not v1.
fn other_version(raw: &[u8]) -> Result<Option<u8>, Error> {
    Ok(Some(crate::pigeonservice::version::of(raw)?).filter(|v| *v != V1))
}

/// A v1 plugin's reply.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reply {
    pub status: u8,
    /// The lease granted.
    pub expiry: u64,
    /// A Resolve's or a Search's answer: a one-time voucher for a connection that carries it.
    pub voucher: Vec<u8>,
    /// With [`Status::UnsupportedVersion`], the versions the plugin serves.
    pub versions: Vec<u8>,
}

impl Reply {
    pub fn status(status: Status) -> Self {
        Reply { status: status as u8, ..Reply::default() }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut fields = vec![(FIELD, cbor::uint(V1 as u64)), ("Status", cbor::uint(self.status as u64))];
        if self.expiry != 0 {
            fields.push(("Expiry", cbor::uint(self.expiry)));
        }
        if !self.voucher.is_empty() {
            fields.push(("Voucher", cbor::bytes(&self.voucher)));
        }
        if !self.versions.is_empty() {
            fields.push(("Versions", cbor::bytes(&self.versions)));
        }
        cbor::encode(&cbor::map(fields))
    }

    /// Decodes a reply. A plugin that does not serve v1 answers in its own version, or with
    /// [`Status::UnsupportedVersion`]; both are [`Error::VersionMismatch`].
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        if let Some(v) = other_version(raw)? {
            return Err(mismatch(V1, vec![v]));
        }
        let v = cbor::decode(raw)?;
        let f = Fields::of(&v)?;
        let r = Reply {
            status: u8::try_from(f.uint("Status")?).map_err(|_| Error::Decode("Status: out of range".into()))?,
            expiry: f.uint("Expiry")?,
            voucher: f.bytes("Voucher")?,
            versions: f.bytes("Versions")?,
        };
        if r.status == Status::UnsupportedVersion as u8 {
            return Err(mismatch(V1, r.versions));
        }
        Ok(r)
    }
}
