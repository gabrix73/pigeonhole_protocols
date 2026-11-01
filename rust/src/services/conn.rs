//! Two-way Pigeonhole connections.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::services::Error;
use crate::services::cbor::{self, Fields, Value};
use crate::transport::Backend;
use crate::services::pigeonhole::{read_wait, write, write_retry};
use crate::transport::Secret;

type OnChange = Arc<dyn Fn(&ConnState) + Send + Sync>;

/// A two-way Pigeonhole connection: a stream this side writes and a stream
/// the peer writes. Send and recv may run concurrently.
///
/// Dropping a send before it finishes can leave its box written while the
/// connection still points at it; the next send to that box is then lost.
pub struct Conn<B: Backend> {
    ph: Arc<B>,
    poll: Duration,
    write_cap: Secret,
    read_cap: Secret,
    // send_lock and recv_lock serialize sends and receives for as long as
    // one takes; state is only held briefly.
    send_lock: tokio::sync::Mutex<()>,
    recv_lock: tokio::sync::Mutex<()>,
    state: Mutex<Indices>,
    on_change: Mutex<Option<OnChange>>,
}

struct Indices {
    write_idx: Vec<u8>,
    read_idx: Vec<u8>,
    sent: Vec<SentBox>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SentBox {
    index: Vec<u8>,
    plaintext: Vec<u8>,
    at: u64,
}

/// A connection's persistent state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnState {
    write_cap: Secret,
    write_idx: Vec<u8>,
    read_cap: Secret,
    read_idx: Vec<u8>,
    sent: Vec<SentBox>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl ConnState {
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&self.to_value())
    }

    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        Self::from_value(&cbor::decode(raw)?)
    }

    pub(crate) fn to_value(&self) -> Value {
        let sent = self
            .sent
            .iter()
            .map(|b| cbor::map(vec![("Index", cbor::bytes(&b.index)), ("Plaintext", cbor::bytes(&b.plaintext)), ("At", cbor::uint(b.at))]))
            .collect();
        cbor::map(vec![
            ("WriteCap", cbor::bytes(&self.write_cap)),
            ("WriteIdx", cbor::bytes(&self.write_idx)),
            ("ReadCap", cbor::bytes(&self.read_cap)),
            ("ReadIdx", cbor::bytes(&self.read_idx)),
            ("Sent", Value::Array(sent)),
        ])
    }

    pub(crate) fn from_value(v: &Value) -> Result<Self, Error> {
        let f = Fields::of(v)?;
        let sent = f
            .array("Sent")?
            .iter()
            .map(|b| {
                let b = Fields::of(b)?;
                Ok(SentBox { index: b.bytes("Index")?, plaintext: b.bytes("Plaintext")?, at: b.uint("At")? })
            })
            .collect::<Result<_, Error>>()?;
        Ok(ConnState {
            write_cap: f.bytes("WriteCap")?.into(),
            write_idx: f.bytes("WriteIdx")?,
            read_cap: f.bytes("ReadCap")?.into(),
            read_idx: f.bytes("ReadIdx")?,
            sent,
        })
    }
}

impl<B: Backend> Conn<B> {
    pub(crate) fn new(ph: Arc<B>, write_cap: Secret, write_idx: Vec<u8>, read_cap: Secret, read_idx: Vec<u8>, poll: Duration) -> Self {
        Conn {
            ph,
            poll,
            write_cap,
            read_cap,
            send_lock: tokio::sync::Mutex::new(()),
            recv_lock: tokio::sync::Mutex::new(()),
            state: Mutex::new(Indices { write_idx, read_idx, sent: Vec::new() }),
            on_change: Mutex::new(None),
        }
    }

    /// Rebuilds a connection from its persistent state.
    pub fn restore(ph: Arc<B>, s: &ConnState, poll: Duration) -> Self {
        let c = Conn::new(ph, s.write_cap.clone(), s.write_idx.clone(), s.read_cap.clone(), s.read_idx.clone(), poll);
        c.state.lock().unwrap().sent = s.sent.clone();
        c
    }

    /// Returns the connection's state for persistence.
    pub fn state(&self) -> ConnState {
        let st = self.state.lock().unwrap();
        ConnState {
            write_cap: self.write_cap.clone(),
            write_idx: st.write_idx.clone(),
            read_cap: self.read_cap.clone(),
            read_idx: st.read_idx.clone(),
            sent: st.sent.clone(),
        }
    }

    /// Sets a function called with the new state after every send, recv
    /// and refresh. A connection restored from state saved before a send
    /// would write that send's box again, where the write is a silent
    /// no-op, so state must be saved after each one.
    pub fn on_change(&self, f: Option<OnChange>) {
        *self.on_change.lock().unwrap() = f;
    }

    fn notify(&self) {
        let f = self.on_change.lock().unwrap().clone();
        if let Some(f) = f {
            f(&self.state());
        }
    }

    /// The Pigeonhole the connection runs over.
    pub fn pigeonhole(&self) -> &Arc<B> {
        &self.ph
    }

    /// How often a pending read is retried.
    pub fn poll_interval(&self) -> Duration {
        self.poll
    }

    /// The largest message one send carries.
    pub async fn max_message(&self) -> Result<usize, Error> {
        Ok(self.ph.max_plaintext().await?)
    }

    /// Writes `msg` to the next box of this side's stream.
    pub async fn send(&self, msg: &[u8]) -> Result<(), Error> {
        if msg.is_empty() {
            return Err(Error::Other("empty message".into()));
        }
        if msg.len() > self.ph.max_plaintext().await? {
            return Err(Error::MessageTooLarge);
        }
        let _guard = self.send_lock.lock().await;
        let idx = self.state.lock().unwrap().write_idx.clone();
        let next = write_retry(&*self.ph, &self.write_cap, &idx, msg).await?;
        {
            let mut st = self.state.lock().unwrap();
            st.sent.push(SentBox { index: idx, plaintext: msg.to_vec(), at: now() });
            st.write_idx = next;
        }
        self.notify();
        Ok(())
    }

    /// Waits for the peer's next message. Tombstoned boxes are skipped.
    pub async fn recv(&self) -> Result<Vec<u8>, Error> {
        let _guard = self.recv_lock.lock().await;
        loop {
            let idx = self.state.lock().unwrap().read_idx.clone();
            let (msg, next) = match read_wait(&*self.ph, &self.read_cap, &idx, self.poll).await {
                Ok((msg, next)) => (Some(msg), next),
                Err(Error::Tombstone(next)) => (None, next),
                Err(e) => return Err(e),
            };
            self.state.lock().unwrap().read_idx = next;
            self.notify();
            if let Some(msg) = msg {
                return Ok(msg);
            }
        }
    }

    /// Rewrites every box sent within `retention`, restoring any a replica
    /// has garbage-collected, and forgets older ones. Pigeonhole keeps a box
    /// for one to two replica epochs; refreshing once a replica epoch keeps
    /// a box readable for as long as retention allows.
    pub async fn refresh(&self, retention: Duration) -> Result<(), Error> {
        let cutoff = now().saturating_sub(retention.as_secs());
        let kept = {
            let mut st = self.state.lock().unwrap();
            st.sent.retain(|b| b.at >= cutoff);
            st.sent.clone()
        };
        self.notify();
        for b in kept {
            write(&*self.ph, &self.write_cap, &b.index, &b.plaintext).await?;
        }
        Ok(())
    }
}
