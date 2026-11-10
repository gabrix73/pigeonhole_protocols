//! What a v1 router or directory checks of a signed request before acting on it, so a plugin in
//! Rust and the Go one in katzenpost agree.
//!
//! | check | what it stops |
//! |---|---|
//! | the signature, by the key the request carries, with the request type as context | a forged request, or one type passed as another |
//! | `Registrar` is this plugin's | a request made for one plugin used at another |
//! | `Time` within [`MAX_CLOCK_SKEW`] of the plugin's clock | a request replayed later |
//! | `Revision` above the last the plugin took from the service | a request replayed within that window, or an older one after a newer |
//! | `Expiry` within the plugin's longest lease | an unbounded lease |
//!
//! The same request again, byte for byte, is a retransmission: the client daemon resends until a
//! reply comes. It gets the same answer and changes nothing.

use std::collections::HashMap;
use std::time::Duration;

use blake2::{Blake2b, Digest, digest::consts::U32};

use crate::pigeonservice::lease::{MAX_CLOCK_SKEW, check_lease};
use crate::pigeonservice::v1::wire::{Request, ServiceId, Signed, Status};

/// How a request was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admitted {
    /// A new request, to act on.
    Fresh,
    /// The last request again: answer as before.
    Repeat,
}

struct Held {
    revision: u64,
    digest: [u8; 32],
    /// When the revision may be forgotten.
    keep: u64,
}

/// One plugin's record of the services it took requests from.
pub struct Registrar {
    pub id: [u8; 32],
    longest: Duration,
    held: HashMap<ServiceId, Held>,
}

impl Registrar {
    /// The registrar with ID `id` (see [`super::wire::registrar_id`]), granting leases of at most
    /// `longest`.
    pub fn new(id: [u8; 32], longest: Duration) -> Self {
        Registrar { id, longest, held: HashMap::new() }
    }

    /// Checks `s` at the plugin's time `now`, in Unix seconds, and records its revision.
    pub fn admit(&mut self, s: &Signed, now: u64) -> Result<Admitted, Status> {
        self.held.retain(|_, h| h.keep > now);
        s.verify().map_err(|_| Status::BadSignature)?;
        if s.registrar != self.id {
            return Err(Status::WrongRegistrar);
        }
        if s.time.abs_diff(now) > MAX_CLOCK_SKEW.as_secs() {
            return Err(Status::BadTime);
        }
        // A revision is kept while a request could still be fresh, and while its lease runs.
        let mut keep = now + 2 * MAX_CLOCK_SKEW.as_secs();
        if s.ctx.leases() {
            keep = keep.max(check_lease(now, s.expiry, self.longest).ok_or(Status::InvalidRequest)?);
        }
        let digest: [u8; 32] = Blake2b::<U32>::digest(Request::Signed(s.clone()).encode()).into();
        match self.held.get_mut(&s.id()) {
            Some(h) if h.revision == s.revision && h.digest == digest => Ok(Admitted::Repeat),
            Some(h) if h.revision >= s.revision => Err(Status::Stale),
            Some(h) => {
                *h = Held { revision: s.revision, digest, keep: keep.max(h.keep) };
                Ok(Admitted::Fresh)
            }
            None => {
                self.held.insert(s.id(), Held { revision: s.revision, digest, keep });
                Ok(Admitted::Fresh)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pigeonservice::lease::now;
    use crate::pigeonservice::v1::sign::Identity;
    use crate::pigeonservice::v1::wire::Ctx;

    const HOUR: u64 = 3600;

    fn renew(id: &Identity, registrar: [u8; 32], time: u64, revision: u64) -> Signed {
        Signed::new(id, Ctx::Renew, registrar, time, revision, time + HOUR, vec![], None).unwrap()
    }

    #[test]
    fn admits_and_rejects() {
        let t = now();
        let mut r = Registrar::new([1; 32], Duration::from_secs(24 * HOUR));
        let id = Identity::generate();
        let first = renew(&id, r.id, t, 10);
        assert_eq!(r.admit(&first, t), Ok(Admitted::Fresh));
        assert_eq!(r.admit(&first, t + 1), Ok(Admitted::Repeat), "a retransmission");

        assert_eq!(r.admit(&renew(&id, r.id, t, 10), t), Ok(Admitted::Repeat), "signing is deterministic");
        let mut other = renew(&id, r.id, t + 1, 10);
        assert_eq!(r.admit(&other, t), Err(Status::Stale), "same revision, other request");
        other = renew(&id, r.id, t, 9);
        assert_eq!(r.admit(&other, t), Err(Status::Stale), "an older revision");
        assert_eq!(r.admit(&renew(&id, r.id, t, 11), t), Ok(Admitted::Fresh));
        assert_eq!(r.admit(&first, t), Err(Status::Stale), "replayed after a newer one");

        let mut bad = renew(&id, r.id, t, 12);
        bad.signature[0] ^= 1;
        assert_eq!(r.admit(&bad, t), Err(Status::BadSignature));
        let mut swapped = renew(&id, r.id, t, 12);
        swapped.public_key = Identity::generate().public_key();
        assert_eq!(r.admit(&swapped, t), Err(Status::BadSignature), "another key");
        let mut as_unregister = renew(&id, r.id, t, 12);
        as_unregister.ctx = Ctx::Register;
        as_unregister.voucher = vec![0; 32];
        assert_eq!(r.admit(&as_unregister, t), Err(Status::BadSignature), "the context binds the request type");
        let mut later = renew(&id, r.id, t, 12);
        later.revision = 13;
        assert_eq!(r.admit(&later, t), Err(Status::BadSignature), "the revision is signed");

        assert_eq!(r.admit(&renew(&id, [2; 32], t, 12), t), Err(Status::WrongRegistrar));
        assert_eq!(r.admit(&renew(&id, r.id, t - HOUR, 12), t), Err(Status::BadTime));
        assert_eq!(r.admit(&renew(&id, r.id, t + HOUR, 12), t), Err(Status::BadTime));
        let long = Signed::new(&id, Ctx::Renew, r.id, t, 12, t + 30 * 24 * HOUR, vec![], None).unwrap();
        assert_eq!(r.admit(&long, t), Err(Status::InvalidRequest), "a lease past the longest");
        // None of the refused requests moved the revision.
        assert_eq!(r.admit(&renew(&id, r.id, t, 12), t), Ok(Admitted::Fresh));
    }

    #[test]
    fn a_replay_once_the_request_is_stale_is_refused_by_time() {
        let t = now();
        let mut r = Registrar::new([1; 32], Duration::from_secs(HOUR));
        let id = Identity::generate();
        let unregister = Signed::new(&id, Ctx::Unregister, r.id, t, 1, 0, vec![], None).unwrap();
        assert_eq!(r.admit(&unregister, t), Ok(Admitted::Fresh));
        // Past the window the revision is forgotten, and the time refuses the request.
        let later = t + 3 * MAX_CLOCK_SKEW.as_secs();
        assert_eq!(r.admit(&unregister, later), Err(Status::BadTime));
        assert!(r.held.is_empty());
    }
}
