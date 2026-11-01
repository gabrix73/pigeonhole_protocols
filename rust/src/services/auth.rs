//! Request MACs. A service's requests to a router or a directory carry a
//! MAC under a key both sides derive from a NIKE exchange between the
//! service's key and the plugin's published key:
//!
//! ```text
//! ss  = DH(servicePriv, pluginPub)
//! key = HKDF-BLAKE2b-256(ss, info = label || pluginPub || servicePub)
//! mac = BLAKE2b-256(key = key, msg = canonical CBOR of the request with MAC null)
//! ```

use blake2::Blake2b;
use blake2::Blake2bMac;
use blake2::digest::Mac;
use blake2::digest::consts::U32;
use zeroize::Zeroizing;

use crate::services::Error;
use crate::services::cbor::{self, Value};
use crate::services::nike;
use crate::services::wire::{AdvertiseRequest, RegisterRequest, ServiceId, WithdrawRequest};

const LABEL: &[u8] = b"katzenpost-pigeonservice-mac-v1";

type Hkdf = hkdf::SimpleHkdf<Blake2b<U32>>;

/// `ss` is the NIKE shared secret of the service's key and the plugin's,
/// from [`nike::PrivateKey::derive_secret`].
fn mac_key(ss: &[u8], plugin_pub: &[u8], service_pub: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut info = LABEL.to_vec();
    info.extend_from_slice(plugin_pub);
    info.extend_from_slice(service_pub);
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::new(None, ss).expand(&info, &mut out[..]).map_err(|_| Error::Crypto)?;
    Ok(out)
}

fn mac_of(key: &[u8; 32], unsigned: &Value) -> Vec<u8> {
    let mut m = <Blake2bMac<U32> as Mac>::new_from_slice(key).expect("32-byte BLAKE2b key");
    m.update(&cbor::encode(unsigned));
    m.finalize().into_bytes().to_vec()
}

/// Fills in a RegisterRequest's MAC for the router whose key is `router_pub`.
pub fn sign_register(ss: &[u8], router_pub: &[u8], r: &mut RegisterRequest) -> Result<(), Error> {
    r.mac = None;
    r.mac = Some(mac_of(&*mac_key(ss, router_pub, &r.public_key)?, &r.to_value()));
    Ok(())
}

/// Fills in an AdvertiseRequest's MAC for the directory whose key is `dir_pub`.
pub fn sign_advertise(ss: &[u8], dir_pub: &[u8], r: &mut AdvertiseRequest) -> Result<(), Error> {
    r.mac = None;
    r.mac = Some(mac_of(&*mac_key(ss, dir_pub, &r.descriptor.public_key)?, &r.to_value()));
    Ok(())
}

/// Fills in a WithdrawRequest's MAC for the directory whose key is
/// `dir_pub`, from the service whose public key is `service_pub`.
pub fn sign_withdraw(ss: &[u8], dir_pub: &[u8], service_pub: &[u8], r: &mut WithdrawRequest) -> Result<(), Error> {
    r.mac = None;
    r.mac = Some(mac_of(&*mac_key(ss, dir_pub, service_pub)?, &r.to_value()));
    Ok(())
}

/// Checks a request MAC as the plugin whose key is `plugin_pub`, for the
/// service whose public key is `service_pub`.
fn verify(ss: &[u8], plugin_pub: &[u8], service_pub: &[u8], unsigned: &Value, mac: Option<&[u8]>) -> Result<(), Error> {
    use subtle::ConstantTimeEq;
    let key = mac_key(ss, plugin_pub, service_pub).map_err(|_| Error::BadMac)?;
    let want = mac_of(&key, unsigned);
    match mac {
        Some(m) if bool::from(want.ct_eq(m)) => Ok(()),
        _ => Err(Error::BadMac),
    }
}

/// Checks a RegisterRequest's MAC as the router whose key is `router_pub`.
pub fn verify_register(ss: &[u8], router_pub: &[u8], r: &RegisterRequest) -> Result<(), Error> {
    if r.nike_scheme != nike::SCHEME {
        return Err(Error::BadMac);
    }
    let unsigned = RegisterRequest { mac: None, ..r.clone() };
    verify(ss, router_pub, &r.public_key, &unsigned.to_value(), r.mac.as_deref())
}

/// Checks an AdvertiseRequest's MAC as the directory whose key is `dir_pub`.
pub fn verify_advertise(ss: &[u8], dir_pub: &[u8], r: &AdvertiseRequest) -> Result<(), Error> {
    if r.descriptor.nike_scheme != nike::SCHEME {
        return Err(Error::BadMac);
    }
    let unsigned = AdvertiseRequest { mac: None, ..r.clone() };
    verify(ss, dir_pub, &r.descriptor.public_key, &unsigned.to_value(), r.mac.as_deref())
}

/// Checks a WithdrawRequest's MAC as the directory whose key is `dir_pub`,
/// for the service whose public key is `service_pub`.
pub fn verify_withdraw(ss: &[u8], dir_pub: &[u8], service_pub: &[u8], r: &WithdrawRequest) -> Result<(), Error> {
    if ServiceId::from_public_key(service_pub) != r.service_id {
        return Err(Error::BadMac);
    }
    let unsigned = WithdrawRequest { mac: None, ..r.clone() };
    verify(ss, dir_pub, service_pub, &unsigned.to_value(), r.mac.as_deref())
}
