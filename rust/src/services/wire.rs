//! The messages services exchange with voucher routers and the service
//! directory. Field names and encodings match the Go implementation in
//! katzenpost's `pigeonservice` package.

use blake2::{Blake2b, Digest, digest::consts::U32};

use crate::services::Error;
use crate::services::cbor::{self, Fields, Value};

/// The kaetzchen capability of the voucher router.
pub const ROUTER_CAPABILITY: &str = "voucher_router";
/// The kaetzchen capability of the service directory.
pub const DIRECTORY_CAPABILITY: &str = "service_directory";
/// The PKI parameter naming a plugin's NIKE scheme.
pub const PARAM_NIKE_SCHEME: &str = "nikeScheme";
/// The PKI parameter holding a plugin's public key.
pub const PARAM_PUBLIC_KEY: &str = "publicKey";

/// Reply status codes shared by the router and the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    InvalidRequest,
    BadMac,
    UnknownService,
    Stale,
    Busy,
    InternalError,
}

impl Status {
    pub fn from_u8(n: u8) -> Option<Self> {
        use Status::*;
        [Ok, InvalidRequest, BadMac, UnknownService, Stale, Busy, InternalError]
            .get(n as usize)
            .copied()
    }
}

/// Names a service: the BLAKE2b-256 hash of its public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceId(pub [u8; 32]);

impl ServiceId {
    pub fn from_public_key(public_key: &[u8]) -> Self {
        ServiceId(Blake2b::<U32>::digest(public_key).into())
    }
}

impl std::fmt::Display for ServiceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for ServiceId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let bad = || Error::Decode("service ID must be 64 hex digits".into());
        if s.len() != 64 {
            return Err(bad());
        }
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = u8::from_str_radix(s.get(2 * i..2 * i + 2).ok_or_else(bad)?, 16).map_err(|_| bad())?;
        }
        Ok(ServiceId(id))
    }
}

/// One voucher router: the service node it runs on and its endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterRef {
    pub node_id_hash: [u8; 32],
    pub endpoint: String,
}

impl RouterRef {
    fn to_value(&self) -> Value {
        cbor::map(vec![("NodeIDHash", cbor::bytes(&self.node_id_hash)), ("Endpoint", cbor::text(&self.endpoint))])
    }

    fn from_value(v: &Value) -> Result<Self, Error> {
        let f = Fields::of(v)?;
        Ok(RouterRef { node_id_hash: f.array32("NodeIDHash")?, endpoint: f.text("Endpoint")? })
    }
}

/// Everything a client needs to reach a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDescriptor {
    pub nike_scheme: String,
    pub public_key: Vec<u8>,
    pub routers: Vec<RouterRef>,
}

impl ServiceDescriptor {
    pub fn id(&self) -> ServiceId {
        ServiceId::from_public_key(&self.public_key)
    }

    pub(crate) fn to_value(&self) -> Value {
        let routers = if self.routers.is_empty() {
            Value::Null
        } else {
            Value::Array(self.routers.iter().map(RouterRef::to_value).collect())
        };
        cbor::map(vec![
            ("NIKEScheme", cbor::text(&self.nike_scheme)),
            ("PublicKey", cbor::bytes(&self.public_key)),
            ("Routers", routers),
        ])
    }

    pub(crate) fn from_value(v: &Value) -> Result<Self, Error> {
        let f = Fields::of(v)?;
        Ok(ServiceDescriptor {
            nike_scheme: f.text("NIKEScheme")?,
            public_key: f.bytes("PublicKey")?,
            routers: f.array("Routers")?.iter().map(RouterRef::from_value).collect::<Result<_, _>>()?,
        })
    }
}

/// Asks a router to open a link with a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterRequest {
    pub nike_scheme: String,
    pub public_key: Vec<u8>,
    pub voucher: Vec<u8>,
    pub mac: Option<Vec<u8>>,
}

impl RegisterRequest {
    /// The request as signed: with MAC null.
    pub fn clone_unsigned(&self) -> Value {
        RegisterRequest { mac: None, ..self.clone() }.to_value()
    }

    pub(crate) fn to_value(&self) -> Value {
        cbor::map(vec![
            ("NIKEScheme", cbor::text(&self.nike_scheme)),
            ("PublicKey", cbor::bytes(&self.public_key)),
            ("Voucher", cbor::bytes(&self.voucher)),
            ("MAC", cbor::opt_bytes(self.mac.as_deref())),
        ])
    }
}

/// Asks a router to forward a sealed voucher to a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRequest {
    pub service_id: ServiceId,
    pub ciphertext: Vec<u8>,
}

/// The payload of a query to a voucher router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterRequest {
    Route(RouteRequest),
    Register(RegisterRequest),
}

impl RouterRequest {
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&match self {
            RouterRequest::Route(r) => cbor::map(vec![(
                "Route",
                cbor::map(vec![("ServiceID", cbor::bytes(&r.service_id.0)), ("Ciphertext", cbor::bytes(&r.ciphertext))]),
            )]),
            RouterRequest::Register(r) => cbor::map(vec![("Register", r.to_value())]),
        })
    }
}

/// Encodes a router's reply.
pub fn encode_router_reply(status: Status) -> Vec<u8> {
    cbor::encode(&cbor::map(vec![("Status", cbor::uint(status as u64))]))
}

/// A router's or a directory's reply status.
pub fn decode_status(raw: &[u8]) -> Result<u8, Error> {
    status(&Fields::of(&cbor::decode(raw)?)?)
}

fn status(f: &Fields) -> Result<u8, Error> {
    u8::try_from(f.uint("Status")?).map_err(|_| Error::Decode("Status: out of range".into()))
}

/// Encodes one box on a router→service link.
pub fn encode_link_message(forward: &[u8]) -> Vec<u8> {
    cbor::encode(&cbor::map(vec![("Forward", cbor::bytes(forward))]))
}

/// One box on a router→service link: a client's sealed voucher.
pub fn decode_link_message(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let forward = Fields::of(&cbor::decode(raw)?)?.bytes("Forward")?;
    if forward.is_empty() {
        return Err(Error::Decode("empty link message".into()));
    }
    Ok(forward)
}

/// Publishes or replaces a service's descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertiseRequest {
    pub descriptor: ServiceDescriptor,
    pub seq: u64,
    pub mac: Option<Vec<u8>>,
}

impl AdvertiseRequest {
    pub(crate) fn to_value(&self) -> Value {
        cbor::map(vec![
            ("Descriptor", self.descriptor.to_value()),
            ("Seq", cbor::uint(self.seq)),
            ("MAC", cbor::opt_bytes(self.mac.as_deref())),
        ])
    }
}

/// Removes a service's descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawRequest {
    pub service_id: ServiceId,
    pub seq: u64,
    pub mac: Option<Vec<u8>>,
}

impl WithdrawRequest {
    pub(crate) fn to_value(&self) -> Value {
        cbor::map(vec![
            ("ServiceID", cbor::bytes(&self.service_id.0)),
            ("Seq", cbor::uint(self.seq)),
            ("MAC", cbor::opt_bytes(self.mac.as_deref())),
        ])
    }
}

/// The payload of a query to the service directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryRequest {
    Advertise(AdvertiseRequest),
    Withdraw(WithdrawRequest),
    Lookup(ServiceId),
    List,
}

impl RouterRequest {
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let v = cbor::decode(raw)?;
        let f = Fields::of(&v)?;
        if let Some(r) = f.get("Route") {
            let r = Fields::of(r)?;
            return Ok(RouterRequest::Route(RouteRequest { service_id: ServiceId(r.array32("ServiceID")?), ciphertext: r.bytes("Ciphertext")? }));
        }
        if let Some(r) = f.get("Register") {
            let r = Fields::of(r)?;
            return Ok(RouterRequest::Register(RegisterRequest {
                nike_scheme: r.text("NIKEScheme")?,
                public_key: r.bytes("PublicKey")?,
                voucher: r.bytes("Voucher")?,
                mac: r.opt_bytes("MAC")?,
            }));
        }
        Err(Error::Decode("empty router request".into()))
    }
}

impl DirectoryRequest {
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let v = cbor::decode(raw)?;
        let f = Fields::of(&v)?;
        if let Some(r) = f.get("Advertise") {
            let r = Fields::of(r)?;
            let descriptor = ServiceDescriptor::from_value(r.get("Descriptor").ok_or_else(|| Error::Decode("no descriptor".into()))?)?;
            return Ok(DirectoryRequest::Advertise(AdvertiseRequest { descriptor, seq: r.uint("Seq")?, mac: r.opt_bytes("MAC")? }));
        }
        if let Some(r) = f.get("Withdraw") {
            let r = Fields::of(r)?;
            return Ok(DirectoryRequest::Withdraw(WithdrawRequest { service_id: ServiceId(r.array32("ServiceID")?), seq: r.uint("Seq")?, mac: r.opt_bytes("MAC")? }));
        }
        if let Some(r) = f.get("Lookup") {
            return Ok(DirectoryRequest::Lookup(ServiceId(Fields::of(r)?.array32("ServiceID")?)));
        }
        if f.get("List").is_some() {
            return Ok(DirectoryRequest::List);
        }
        Err(Error::Decode("empty directory request".into()))
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&match self {
            DirectoryRequest::Advertise(r) => cbor::map(vec![("Advertise", r.to_value())]),
            DirectoryRequest::Withdraw(r) => cbor::map(vec![("Withdraw", r.to_value())]),
            DirectoryRequest::Lookup(id) => cbor::map(vec![("Lookup", cbor::map(vec![("ServiceID", cbor::bytes(&id.0))]))]),
            DirectoryRequest::List => cbor::map(vec![("List", cbor::map(vec![]))]),
        })
    }
}

/// The directory's answer to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryReply {
    pub status: u8,
    pub descriptor: Option<ServiceDescriptor>,
    pub read_cap: Vec<u8>,
    pub start_index: Vec<u8>,
}

impl DirectoryReply {
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = vec![("Status", cbor::uint(self.status as u64))];
        if let Some(d) = &self.descriptor {
            fields.push(("Descriptor", d.to_value()));
        }
        if !self.read_cap.is_empty() {
            fields.push(("ReadCap", cbor::bytes(&self.read_cap)));
        }
        if !self.start_index.is_empty() {
            fields.push(("StartIndex", cbor::bytes(&self.start_index)));
        }
        cbor::encode(&cbor::map(fields))
    }

    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let v = cbor::decode(raw)?;
        let f = Fields::of(&v)?;
        Ok(DirectoryReply {
            status: status(&f)?,
            descriptor: f.get("Descriptor").map(ServiceDescriptor::from_value).transpose()?,
            read_cap: f.bytes("ReadCap")?,
            start_index: f.bytes("StartIndex")?,
        })
    }
}

/// The content of the directory's snapshot stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub seq: u64,
    pub descriptors: Vec<ServiceDescriptor>,
}

impl Snapshot {
    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let v = cbor::decode(raw)?;
        let f = Fields::of(&v)?;
        Ok(Snapshot {
            seq: f.uint("Seq")?,
            descriptors: f.array("Descriptors")?.iter().map(ServiceDescriptor::from_value).collect::<Result<_, _>>()?,
        })
    }
}

/// The WhoReply an inductor seals for the joiner, in the shape of the group
/// chat ReplyWho: here with one member, the inductor.
pub(crate) fn encode_who_reply(display_name: &str, read_cap: &[u8]) -> Vec<u8> {
    cbor::encode(&cbor::map(vec![(
        "please_adds",
        Value::Array(vec![cbor::map(vec![
            ("display_name", cbor::text(display_name)),
            ("read_cap", cbor::bytes(read_cap)),
        ])]),
    )]))
}

/// Returns the one stream a WhoReply names.
pub(crate) fn decode_who_reply(raw: &[u8]) -> Result<Vec<u8>, Error> {
    let v = cbor::decode(raw)?;
    let adds = Fields::of(&v)?.array("please_adds")?;
    if adds.len() != 1 {
        return Err(Error::BadWhoReply);
    }
    let read_cap = Fields::of(&adds[0])?.bytes("read_cap")?;
    if read_cap.is_empty() {
        return Err(Error::BadWhoReply);
    }
    Ok(read_cap)
}
