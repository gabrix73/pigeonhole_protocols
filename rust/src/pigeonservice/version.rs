//! Versions of the layer-0 protocol, the CBOR requests to voucher routers and service
//! directories.
//!
//! Every layer-0 message is a CBOR map. From version 1 on it carries the version in its `V`
//! field; a message without one is version 0, which predates the field. A plugin publishes each
//! version it serves as a service type of its own, `voucher_router/v1` and so on, and a client
//! talks to each node in the highest version both support. A plugin answers a message in a
//! version it does not serve with the versions it does, and the client fails with
//! [`Error::UnsupportedVersion`].

use std::collections::BTreeMap;

use crate::pigeonservice::Error;
use crate::pigeonservice::cbor::{self, Fields};
use crate::transport::{Backend, ServiceNode};

pub const V0: u8 = 0;
pub const V1: u8 = 1;
/// The versions this crate speaks, oldest first.
pub const SUPPORTED: &[u8] = &[V0, V1];
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

/// The highest version in both `ours` and `theirs`.
pub fn negotiate(ours: &[u8], theirs: &[u8]) -> Result<u8, Error> {
    ours.iter()
        .filter(|v| theirs.contains(v))
        .max()
        .copied()
        .ok_or_else(|| Error::UnsupportedVersion { ours: ours.to_vec(), theirs: theirs.to_vec() })
}

/// Every node in the PKI with a `kind` plugin, each with the highest version of it both the node
/// and `ours` speak. Nodes that speak none of `ours` are left out; if that leaves none the error
/// names the versions they do speak.
pub async fn nodes<B: Backend>(ph: &B, kind: Kind, ours: &[u8]) -> Result<Vec<(ServiceNode, u8)>, Error> {
    let mut by_node: BTreeMap<[u8; 32], Vec<(ServiceNode, u8)>> = BTreeMap::new();
    let mut seen = Vec::new();
    // Versions past ours are looked for too, so the error can name them.
    for v in 0..=PROBE {
        for n in ph.services(&kind.capability(v)).await? {
            seen.push(v);
            by_node.entry(n.node_id_hash).or_default().push((n, v));
        }
    }
    if by_node.is_empty() {
        return Err(Error::Other(format!("no {} in the PKI", kind.name())));
    }
    seen.sort();
    seen.dedup();
    let picked: Vec<_> = by_node
        .into_values()
        .filter_map(|offered| {
            let theirs: Vec<u8> = offered.iter().map(|(_, v)| *v).collect();
            let v = negotiate(ours, &theirs).ok()?;
            offered.into_iter().find(|(_, o)| *o == v)
        })
        .collect();
    if picked.is_empty() {
        return Err(Error::UnsupportedVersion { ours: ours.to_vec(), theirs: seen });
    }
    Ok(picked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_highest_common_version() {
        assert_eq!(negotiate(&[0, 1], &[0, 1]).unwrap(), 1);
        assert_eq!(negotiate(&[0, 1], &[0]).unwrap(), 0);
        assert_eq!(negotiate(&[0], &[0, 1]).unwrap(), 0);
        assert_eq!(negotiate(&[0, 1], &[1, 7]).unwrap(), 1);
        match negotiate(&[1], &[0, 2]) {
            Err(Error::UnsupportedVersion { ours, theirs }) => assert_eq!((ours, theirs), (vec![1], vec![0, 2])),
            other => panic!("{other:?}"),
        }
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
