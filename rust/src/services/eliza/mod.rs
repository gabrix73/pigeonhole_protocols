//! An ELIZA chatbot katzenqt users can talk to. It writes and reads katzenqt's chat framing, and
//! hands out vouchers a katzenqt user pastes into a new conversation.

pub mod engine;

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::protocols::katzenqt1::wire::{Chunk, Gcm, MSG_TEXT, SENTINEL, frame, text_content, unframe};
use crate::services::pigeonhole::{cap_index, read_wait};
use crate::services::{Conn, Error, Service, Session};
use crate::transport::Backend;

/// Bounds a message reassembled from a substream.
const MAX_MESSAGE: usize = 1 << 20;

/// The box for a text message.
pub fn text_box(text: &str) -> Vec<u8> {
    frame(&text_content(&SENTINEL, text))
}

/// Splits `text` into messages that each fit in a box of `max` bytes, breaking between words
/// where it can.
pub fn text_boxes(text: &str, max: usize) -> Vec<Vec<u8>> {
    let room = max.saturating_sub(text_box("").len() + 8).max(1);
    let mut out = Vec::new();
    let mut rest = text;
    while rest.len() > room {
        let mut cut = room;
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        if let Some(space) = rest[..cut].rfind(' ').filter(|&s| s > 0) {
            cut = space;
        }
        out.push(text_box(rest[..cut].trim_end()));
        rest = rest[cut..].trim_start();
    }
    if !rest.is_empty() || out.is_empty() {
        out.push(text_box(rest));
    }
    out
}

/// Receives the peer's next box and returns its text, if it is a text message. Control messages,
/// introductions and the like yield none.
pub async fn recv_text<B: Backend>(conn: &Conn<B>) -> Result<Option<String>, Error> {
    let cbor = match unframe(&conn.recv().await?) {
        Chunk::Final(cbor) => cbor,
        Chunk::Indirection { read_cap, .. } => read_substream(conn, &read_cap).await?,
        Chunk::Continued(_) | Chunk::Unknown => return Ok(None),
    };
    Ok(Gcm::from_bytes(&cbor).filter(|g| g.msg_type == MSG_TEXT).and_then(|g| g.text).filter(|t| !t.is_empty()))
}

/// Reads a long message's substream: continued chunks, then the final one.
async fn read_substream<B: Backend>(conn: &Conn<B>, read_cap: &[u8]) -> Result<Vec<u8>, Error> {
    let mut idx = cap_index(read_cap)?;
    let mut body = Vec::new();
    loop {
        let (chunk, next) = read_wait(&**conn.pigeonhole(), read_cap, &idx, conn.poll_interval()).await?;
        idx = next;
        match unframe(&chunk) {
            Chunk::Continued(c) => body.extend_from_slice(&c),
            Chunk::Final(c) => {
                body.extend_from_slice(&c);
                return Ok(body);
            }
            _ => return Err(Error::Decode("bad substream chunk".into())),
        }
        if body.len() > MAX_MESSAGE {
            return Err(Error::Decode("substream message too large".into()));
        }
    }
}

/// Talks with one client until the connection ends.
pub async fn chat<B: Backend>(session: Session<B>) {
    let Ok(max) = session.max_message().await else { return };
    if !session.restored() && send(&session, engine::GREETING, max).await.is_err() {
        return;
    }
    let mut doctor = engine::Conversation::new();
    loop {
        match recv_text(&session).await {
            Ok(Some(text)) => {
                if send(&session, &doctor.reply(&text), max).await.is_err() {
                    return;
                }
            }
            Ok(None) => {}
            Err(Error::Decode(e)) => log::warn!("skipping a message that does not decode: {e}"),
            Err(e) => return log::warn!("a session ended: {e}"),
        }
    }
}

async fn send<B: Backend>(session: &Session<B>, text: &str, max: usize) -> Result<(), Error> {
    for b in text_boxes(text, max) {
        session.send(&b).await?;
    }
    Ok(())
}

/// Keeps `size` vouchers from [`Service::offer`] outstanding and writes each as base64, the form
/// katzenqt takes, to a file in `dir`. A voucher's file goes once a client uses it.
pub async fn keep_vouchers<B: Backend>(svc: Service<B>, dir: PathBuf, size: usize) -> std::io::Result<()> {
    std::fs::create_dir_all(&dir)?;
    loop {
        let mut offers = svc.offers();
        while offers.len() < size {
            match svc.offer().await {
                Ok(v) => offers.push(v),
                Err(e) => {
                    log::warn!("minting a voucher: {e}");
                    break;
                }
            }
        }
        let codes: HashSet<String> = offers.iter().map(|v| STANDARD.encode(v)).collect();
        for code in &codes {
            let name: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect();
            let path = dir.join(format!("{name}.txt"));
            if !path.exists() {
                std::fs::write(&path, format!("{code}\n"))?;
                log::info!("new voucher {}", path.display());
            }
        }
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if std::fs::read_to_string(&path).is_ok_and(|c| !codes.contains(c.trim())) {
                std::fs::remove_file(&path)?;
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
