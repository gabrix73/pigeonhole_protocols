//! The contact voucher handshake. The joiner mints a voucher for its own
//! stream and publishes the voucher payload in box 0 of the voucher
//! stream. The inductor, holding the voucher, reads box 0, creates its own
//! stream and writes a sealed reply naming that stream in box 1. The joiner
//! opens box 1. Each side then writes its own stream and reads the other's.

use std::sync::Arc;
use std::time::Duration;

use crate::services::Error;
use crate::services::cbor::{self, Fields};
use crate::services::conn::Conn;
use crate::transport::Backend;
use crate::services::pigeonhole::{cap_index, read_wait, write, write_retry};
use crate::transport::Secret;
use crate::services::wire::{decode_who_reply, encode_who_reply};

/// A minted voucher waiting for its inductor's reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// What the joiner hands to the inductor.
    pub voucher: Vec<u8>,
    secret_key: Secret,
    write_cap: Secret,
    reply_cap: Secret,
    reply_index: Vec<u8>,
}

/// Creates the joiner's stream, mints a voucher for it, and publishes the
/// voucher payload.
pub async fn mint<B: Backend>(ph: &B, display_name: &str) -> Result<Pending, Error> {
    let stream = ph.new_keypair().await?;
    let m = ph.voucher_mint(&stream.write_cap, display_name).await?;
    let box0 = cap_index(&m.write_cap)?;
    let box1 = write_retry(ph, &m.write_cap, &box0, &m.payload).await?;
    Ok(Pending {
        voucher: m.voucher.to_vec(),
        secret_key: m.secret_key,
        write_cap: stream.write_cap,
        reply_cap: m.read_cap,
        reply_index: box1,
    })
}

impl Pending {
    /// Waits for the inductor's reply and returns the connection it opens.
    pub async fn wait<B: Backend>(&self, ph: Arc<B>, poll: Duration) -> Result<Conn<B>, Error> {
        let (sealed, _) = match read_wait(&*ph, &self.reply_cap, &self.reply_index, poll).await {
            Err(Error::Tombstone(_)) => return Err(Error::Other("voucher reply was withdrawn".into())),
            r => r?,
        };
        let opened = ph.voucher_open(&self.secret_key, &sealed, &self.write_cap).await?;
        let peer = decode_who_reply(&opened.who_reply)?;
        let write_idx = cap_index(&opened.mutated_write_cap)?;
        let read_idx = cap_index(&peer)?;
        Ok(Conn::new(ph, opened.mutated_write_cap, write_idx, peer.into(), read_idx, poll))
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&cbor::map(vec![
            ("Voucher", cbor::bytes(&self.voucher)),
            ("SecretKey", cbor::bytes(&self.secret_key)),
            ("WriteCap", cbor::bytes(&self.write_cap)),
            ("ReplyCap", cbor::bytes(&self.reply_cap)),
            ("ReplyIndex", cbor::bytes(&self.reply_index)),
        ]))
    }

    pub fn decode(raw: &[u8]) -> Result<Self, Error> {
        let v = cbor::decode(raw)?;
        let f = Fields::of(&v)?;
        Ok(Pending {
            voucher: f.bytes("Voucher")?,
            secret_key: f.bytes("SecretKey")?.into(),
            write_cap: f.bytes("WriteCap")?.into(),
            reply_cap: f.bytes("ReplyCap")?.into(),
            reply_index: f.bytes("ReplyIndex")?,
        })
    }
}

/// Reads the voucher payload, creates the inductor's stream, and writes the
/// sealed reply naming it. Returns the connection to the joiner.
pub async fn induct<B: Backend>(ph: Arc<B>, voucher: &[u8], display_name: &str, poll: Duration) -> Result<Conn<B>, Error> {
    let (vwc, vrc) = ph.voucher_derive_stream(voucher).await?;
    let box0 = cap_index(&vrc)?;
    let (payload, box1) = match read_wait(&*ph, &vrc, &box0, poll).await {
        Err(Error::Tombstone(_)) => return Err(Error::Other("voucher already used".into())),
        r => r?,
    };
    let stream = ph.new_keypair().await?;
    let who = encode_who_reply(display_name, &stream.read_cap);
    let inducted = ph.voucher_induct(voucher, &payload, &who).await?;
    write_retry(&*ph, &vwc, &box1, &inducted.sealed_reply).await?;
    // Box 0 is spent: tombstone it so the voucher cannot be inducted again.
    let _ = write(&*ph, &vwc, &box0, &[]).await;
    let read_idx = cap_index(&inducted.mutated_read_cap)?;
    Ok(Conn::new(ph, stream.write_cap, stream.first, inducted.mutated_read_cap, read_idx, poll))
}
