//! Versions of the layer-0 protocol, the CBOR requests to voucher routers and service
//! directories.
//!
//! Every layer-0 message is a CBOR map. From version 1 on it carries the version in its `V`
//! field; a message without one is version 0, which predates the field. A plugin publishes each
//! version it serves as a service type of its own, `voucher_router/v1` and so on.
//!
//! There is no negotiation. A client speaks exactly the version it was built for and a plugin
//! accepts only the versions it implements. A plugin answers a message in another version with
//! the `UnsupportedVersion` status and the versions it does serve, and the client fails with
//! [`Error::VersionMismatch`], naming the service, the version it speaks, the versions the other
//! side supports and what to do about it. A client that finds only other versions in the PKI
//! fails the same way before sending anything.

use crate::pigeonservice::Error;
use crate::pigeonservice::cbor::{self, Fields};
use crate::transport::{Backend, ServiceNode};

pub const V0: u8 = 0;
pub const V1: u8 = 1;
/// The field naming a message's version.
pub const FIELD: &str = "V";
/// The highest version [`nodes`] looks for in the PKI.
const PROBE: u8 = 7;

/// A kind of layer-0 plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    VoucherRouter,
    Discovery,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::VoucherRouter => "voucher_router",
            Kind::Discovery => "discovery",
        }
    }

    /// The service type of version `v`: `voucher_router/v1`.
    pub fn service_type(self, v: u8) -> String {
        format!("{}/v{v}", self.name())
    }

    /// The capability version `v` is published under in the PKI. Version 0 keeps the names the
    /// plugins had before versions.
    pub fn capability(self, v: u8) -> String {
        match (self, v) {
            (Kind::VoucherRouter, V0) => "voucher_router".into(),
            (Kind::Discovery, V0) => "service_directory".into(),
            _ => self.service_type(v),
        }
    }
}

/// The version of a layer-0 message: its `V` field, or 0 when it has none.
pub fn of(raw: &[u8]) -> Result<u8, Error> {
    let v = cbor::decode(raw)?;
    let f = Fields::of(&v)?;
    match f.get(FIELD) {
        None => Ok(V0),
        Some(_) => u8::try_from(f.uint(FIELD)?).map_err(|_| Error::Decode("V: out of range".into())),
    }
}

/// `[0, 1]` as "v0, v1", or "no version it names" when empty.
pub fn list(vs: &[u8]) -> String {
    if vs.is_empty() {
        return "no version it names".into();
    }
    vs.iter().map(|v| format!("v{v}")).collect::<Vec<_>>().join(", ")
}

/// Every node in the PKI with a version `v` `kind` plugin. If there is none but there are
/// plugins of other versions, the error names them.
pub async fn nodes<B: Backend>(ph: &B, kind: Kind, v: u8) -> Result<Vec<ServiceNode>, Error> {
    let found = ph.services(&kind.capability(v)).await?;
    if !found.is_empty() {
        return Ok(found);
    }
    let mut others = Vec::new();
    for o in (0..=PROBE).filter(|o| *o != v) {
        if !ph.services(&kind.capability(o)).await?.is_empty() {
            others.push(o);
        }
    }
    if others.is_empty() {
        return Err(Error::Other(format!("no {} in the PKI", kind.name())));
    }
    Err(Error::VersionMismatch { service: kind.service_type(v), requested: v, supported: others })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatch_text() {
        let e = Error::VersionMismatch { service: "voucher_router/v1".into(), requested: 1, supported: vec![0] };
        assert_eq!(e.to_string(), "pigeonservice: version mismatch with voucher_router/v1: the client speaks v1, the service supports v0; upgrade the client or app, or use a service that offers v1");
        assert_eq!(list(&[]), "no version it names");
        assert_eq!(list(&[0, 2]), "v0, v2");
    }

    #[test]
    fn names() {
        assert_eq!(Kind::VoucherRouter.service_type(0), "voucher_router/v0");
        assert_eq!(Kind::Discovery.service_type(1), "discovery/v1");
        assert_eq!(Kind::VoucherRouter.capability(0), "voucher_router");
        assert_eq!(Kind::Discovery.capability(0), "service_directory");
        assert_eq!(Kind::VoucherRouter.capability(1), "voucher_router/v1");
    }

    #[test]
    fn version_field() {
        let v0 = cbor::encode(&cbor::map(vec![("List", cbor::map(vec![]))]));
        assert_eq!(of(&v0).unwrap(), 0);
        let v1 = cbor::encode(&cbor::map(vec![("V", cbor::uint(1)), ("List", cbor::map(vec![]))]));
        assert_eq!(of(&v1).unwrap(), 1);
        let bad = cbor::encode(&cbor::map(vec![("V", cbor::uint(256))]));
        assert!(of(&bad).is_err());
    }
}
