//! The v1 messages, as CBOR maps with text keys in canonical order (shortest first, then
//! bytewise), as v0's. A request is `{"V": 1, <type>: <body>}`, a reply `{"V": 1, "Status": n,
//! ...}`.
//!
//! ```text
//! Register   { Scheme, PublicKey, Registrar, Time, Revision, Expiry, Voucher, Signature }  router
//! Renew      { Scheme, PublicKey, Registrar, Time, Revision, Expiry, Signature }           router
//! Unregister { Scheme, PublicKey, Registrar, Time, Revision, Signature }                   router
//! Route      { ServiceID, Ciphertext }                                                     router
//! Advertise  { Scheme, PublicKey, Registrar, Time, Revision, Expiry, Descriptor, Signature } directory
//! Withdraw   { Scheme, PublicKey, Registrar, Time, Revision, Signature }                   directory
//! Lookup     { ServiceID }                                                                 directory
//! List       {}                                                                            directory
//! Descriptor { NIKEScheme, NIKEPublicKey, Routers: [{NodeIDHash, Endpoint}] }
//! Reply      { V, Status, Expiry?, Record?, Voucher?, Versions? }
//! ```
//!
//! `Registrar` is BLAKE2b-256 of the plugin's node ID hash and endpoint ([`registrar_id`]); `Time`
//! is the sender's clock in Unix seconds; `Revision` exceeds that of the sender's last request to
//! the registrar. The signature is over the body without `Signature` ([`super::sign`]). A
//! service's ID is BLAKE2b-256 of its signing key; a voucher is sealed to its descriptor's NIKE
//! key. A `Lookup` answers with the service's signed `Advertise` as `Record`, which a client
//! checks itself; a `List` answers with a one-time `Voucher` whose connection carries the
//! directory's records. Layer 0 hands out no read caps.

use blake2::{Blake2b, Digest, digest::consts::U32};

use crate::pigeonservice::Error;
use crate::pigeonservice::cbor::{self, Fields, Value};
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

/// What a client needs to reach a service, besides its signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub nike_scheme: String,
    pub nike_public_key: Vec<u8>,
    pub routers: Vec<RouterRef>,
}

impl Descriptor {
    fn check(&self) -> Result<(), Error> {
        if self.routers.len() > size::MAX_ROUTERS {
            return Err(Error::Oversize(format!("a v1 descriptor names at most {} routers", size::MAX_ROUTERS)));
        }
        if self.routers.iter().any(|r| r.endpoint.len() > size::MAX_ENDPOINT) {
            return Err(Error::Oversize(format!("a router endpoint is at most {} bytes", size::MAX_ENDPOINT)));
        }
        if self.nike_scheme.len() > size::MAX_SCHEME || self.nike_public_key.len() > crate::pigeonservice::nike::PUBLIC_KEY_SIZE {
            return Err(Error::Oversize("NIKE scheme name or key too long".into()));
        }
        Ok(())
    }

    fn to_value(&self) -> Value {
        cbor::map(vec![
            ("NIKEScheme", cbor::text(&self.nike_scheme)),
            ("NIKEPublicKey", cbor::bytes(&self.nike_public_key)),
            ("Routers", Value::Array(self.routers.iter().map(RouterRef::to_value).collect())),
        ])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = Fields::of(v)?;
        let d = Descriptor {
            nike_scheme: f.text("NIKEScheme")?,
            nike_public_key: f.bytes("NIKEPublicKey")?,
            routers: f.array("Routers")?.iter().map(RouterRef::from_value).collect::<Result<_, _>>()?,
        };
        d.check()?;
        Ok(d)
    }
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
    const ALL: [Ctx; 5] = [Ctx::Register, Ctx::Renew, Ctx::Unregister, Ctx::Advertise, Ctx::Withdraw];

    /// The request's key in the message, and its signature context in lower case.
    pub fn name(self) -> &'static str {
        match self {
            Ctx::Register => "Register",
            Ctx::Renew => "Renew",
            Ctx::Unregister => "Unregister",
            Ctx::Advertise => "Advertise",
            Ctx::Withdraw => "Withdraw",
        }
    }

    fn sig_ctx(self) -> &'static str {
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

/// A request signed by the service whose key it carries.
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
    /// The voucher of a Register; else empty.
    pub voucher: Vec<u8>,
    /// The descriptor of an Advertise.
    pub descriptor: Option<Descriptor>,
    pub signature: Vec<u8>,
}

impl Signed {
    /// A `ctx` request by `id` to `registrar`, signed. `voucher` is for a Register and
    /// `descriptor` for an Advertise.
    pub fn new(
        id: &Identity,
        ctx: Ctx,
        registrar: [u8; 32],
        time: u64,
        revision: u64,
        expiry: u64,
        voucher: Vec<u8>,
        descriptor: Option<Descriptor>,
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
            descriptor,
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
        let voucher_ok = match self.ctx {
            Ctx::Register => self.voucher.len() == 32,
            _ => self.voucher.is_empty(),
        };
        if !voucher_ok || self.descriptor.is_some() != (self.ctx == Ctx::Advertise) || (self.ctx.leases() && self.expiry == 0) {
            return Err(Error::Decode(format!("malformed {}", self.ctx.name())));
        }
        if self.scheme.len() > size::MAX_SCHEME || self.public_key.len() > Scheme::PUBLIC_KEY {
            return Err(Error::Decode(format!("{}: scheme name or key too long", self.ctx.name())));
        }
        self.descriptor.as_ref().map_or(Ok(()), Descriptor::check)
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
        if self.ctx == Ctx::Register {
            fields.push(("Voucher", cbor::bytes(&self.voucher)));
        }
        if let Some(d) = &self.descriptor {
            fields.push(("Descriptor", d.to_value()));
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
            voucher: if ctx == Ctx::Register { f.bytes("Voucher")? } else { vec![] },
            descriptor: match ctx {
                Ctx::Advertise => Some(Descriptor::from_value(f.get("Descriptor").ok_or_else(|| Error::Decode("no descriptor".into()))?)?),
                _ => None,
            },
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
    Lookup(ServiceId),
    List,
}

impl Request {
    pub fn name(&self) -> &'static str {
        match self {
            Request::Signed(s) => s.ctx.name(),
            Request::Route { .. } => "Route",
            Request::Lookup(_) => "Lookup",
            Request::List => "List",
        }
    }

    /// The most the request or its reply can encode to.
    pub fn max(&self) -> usize {
        match self {
            Request::Signed(s) => s.ctx.max(),
            Request::Route { .. } => size::ROUTE_MAX,
            Request::Lookup(_) => size::reply_max::<Scheme>(),
            Request::List => size::LOOKUP_MAX,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let (name, body) = match self {
            Request::Signed(s) => (s.ctx.name(), s.to_value()),
            Request::Route { service_id, ciphertext } => {
                ("Route", cbor::map(vec![("ServiceID", cbor::bytes(&service_id.0)), ("Ciphertext", cbor::bytes(ciphertext))]))
            }
            Request::Lookup(id) => ("Lookup", cbor::map(vec![("ServiceID", cbor::bytes(&id.0))])),
            Request::List => ("List", cbor::map(vec![])),
        };
        cbor::encode(&cbor::map(vec![(FIELD, cbor::uint(V1 as u64)), (name, body)]))
    }

    /// Decodes a v1 request. A request in another version is [`Error::UnsupportedVersion`].
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        check_version(raw)?;
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
        if let Some(r) = f.get("Lookup") {
            return Ok(Request::Lookup(ServiceId(Fields::of(r)?.array32("ServiceID")?)));
        }
        if f.get("List").is_some() {
            return Ok(Request::List);
        }
        Err(Error::Decode("empty v1 request".into()))
    }
}

fn check_version(raw: &[u8]) -> Result<(), Error> {
    match crate::pigeonservice::version::of(raw)? {
        V1 => Ok(()),
        v => Err(Error::UnsupportedVersion { ours: vec![V1], theirs: vec![v] }),
    }
}

/// A v1 plugin's reply.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reply {
    pub status: u8,
    /// The lease granted.
    pub expiry: u64,
    /// A Lookup's answer: the service's signed Advertise.
    pub record: Option<Signed>,
    /// A List's answer: a one-time voucher for the directory's records.
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
        if let Some(r) = &self.record {
            fields.push(("Record", r.to_value()));
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
    /// [`Status::UnsupportedVersion`]; both are [`Error::UnsupportedVersion`].
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        check_version(raw)?;
        let v = cbor::decode(raw)?;
        let f = Fields::of(&v)?;
        let r = Reply {
            status: u8::try_from(f.uint("Status")?).map_err(|_| Error::Decode("Status: out of range".into()))?,
            expiry: f.uint("Expiry")?,
            record: f.get("Record").map(|r| Signed::from_value(Ctx::Advertise, r)).transpose()?,
            voucher: f.bytes("Voucher")?,
            versions: f.bytes("Versions")?,
        };
        if r.status == Status::UnsupportedVersion as u8 {
            return Err(Error::UnsupportedVersion { ours: vec![V1], theirs: r.versions });
        }
        Ok(r)
    }
}

/// The records on a List's connection: a 4-byte big-endian length, then this, over as many
/// messages as it takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub seq: u64,
    pub records: Vec<Signed>,
}

impl Snapshot {
    pub fn encode(&self) -> Vec<u8> {
        let body = cbor::encode(&cbor::map(vec![
            ("Seq", cbor::uint(self.seq)),
            ("Records", Value::Array(self.records.iter().map(Signed::to_value).collect())),
        ]));
        [&(body.len() as u32).to_be_bytes()[..], &body].concat()
    }

    /// Decodes the body after the length.
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let v = cbor::decode(raw)?;
        let f = Fields::of(&v)?;
        Ok(Snapshot {
            seq: f.uint("Seq")?,
            records: f.array("Records")?.iter().map(|r| Signed::from_value(Ctx::Advertise, r)).collect::<Result<_, _>>()?,
        })
    }
}
