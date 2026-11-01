//! Carrying out the engine's actions over a transport.

use std::future::Future;

use crate::protocols::katzenqt1::engine::{Action, Input, Outcome as ReadOutcome};
use crate::protocols::katzenqt1::member::{Index, derive_with, next_index, walk_with};
use crate::protocols::katzenqt1::wire as wire;
use crate::transport::{Backend, Error, Read};

/// How long to wait, in milliseconds, before trying a failed write or read again.
pub const RETRY_MS: u64 = 5000;

/// The files kept under the state directory.
pub trait Files: Send + Sync {
    fn read(&self, name: &str) -> std::io::Result<Vec<u8>>;
    fn remove(&self, name: &str) -> std::io::Result<()>;
}

impl Files for Box<dyn Files> {
    fn read(&self, name: &str) -> std::io::Result<Vec<u8>> {
        (**self).read(name)
    }

    fn remove(&self, name: &str) -> std::io::Result<()> {
        (**self).remove(name)
    }
}

/// What came of an action: an input for the engine now, the action to try again later, or an
/// input to hand the engine later.
#[derive(Debug)]
pub enum Outcome {
    Done(Input),
    Retry(Action, u64),
    Later(Input, u64),
    Nothing,
}

fn next(i: &[u8]) -> Index {
    next_index(i).expect("an index has one after it")
}

fn step(i: &[u8]) -> Result<Index, Error> {
    next_index(i).ok_or_else(|| Error::Other("no index after".into()))
}

fn outcome(r: Read, index: &[u8]) -> ReadOutcome {
    match r {
        Read::NotFound => ReadOutcome::NotFound,
        Read::Tombstone => ReadOutcome::Tombstone { next: next(index) },
        Read::Data(plaintext) => ReadOutcome::Data {
            plaintext,
            next: next(index),
        },
    }
}

fn describe(a: &Action) -> &'static str {
    match a {
        Action::Create { .. } => "new stream",
        Action::Mint { .. } => "mint a voucher",
        Action::AwaitReply { .. } => "wait for the voucher's reply",
        Action::ReadVoucher { .. } => "read a voucher's box 0",
        Action::Seal { .. } => "seal the reply to a voucher",
        Action::Publish { .. } => "publish the reply to a voucher",
        _ => "an action",
    }
}

fn chat_of(a: &Action) -> String {
    match a {
        Action::Create { chat, .. }
        | Action::Mint { chat, .. }
        | Action::AwaitReply { chat, .. }
        | Action::ReadVoucher { chat, .. }
        | Action::Seal { chat, .. }
        | Action::Publish { chat, .. } => chat.clone(),
        _ => String::new(),
    }
}

pub struct Executor<B, F> {
    pub backend: B,
    pub files: F,
}

impl<B: Backend, F: Files> Executor<B, F> {
    /// Write a box until it is written, sleeping between attempts.
    async fn publish<S: Future<Output = ()>>(
        &self,
        write_cap: &[u8],
        index: &[u8],
        b: &[u8],
        sleep: impl Fn(u64) -> S,
    ) -> Result<(), Error> {
        loop {
            match self.backend.write_box(write_cap, index, b).await {
                Ok(()) => return Ok(()),
                Err(Error::BoxAlreadyExists) => return Err(Error::BoxAlreadyExists),
                Err(_) => sleep(RETRY_MS).await,
            }
        }
    }

    /// Carry out one action. It never waits to try again, except within a write that must
    /// succeed before the action can go on; the caller does.
    pub async fn perform<S: Future<Output = ()>>(
        &self,
        a: Action,
        sleep: impl Fn(u64) -> S,
    ) -> Outcome {
        match self.perform_or(a.clone(), sleep).await {
            Ok(o) => o,
            Err(e) => match a {
                Action::Read { .. }
                | Action::ScanRead { .. }
                | Action::ReadChunk { .. }
                | Action::Substream { .. }
                | Action::ChunkIndexes { .. }
                | Action::Write { .. }
                | Action::WriteChunk { .. }
                | Action::Derive { .. }
                | Action::Walk { .. } => Outcome::Retry(a, RETRY_MS),
                Action::Delete { .. } => Outcome::Nothing,
                _ => Outcome::Done(Input::Failed {
                    chat: chat_of(&a),
                    what: format!("{} failed: {e}", describe(&a)),
                }),
            },
        }
    }

    async fn perform_or<S: Future<Output = ()>>(
        &self,
        a: Action,
        sleep: impl Fn(u64) -> S,
    ) -> Result<Outcome, Error> {
        let b = &self.backend;
        Ok(Outcome::Done(match a {
            Action::Create { chat, joining } => Input::Created {
                chat,
                joining,
                keypair: b.new_keypair().await?,
            },
            Action::Write {
                chat,
                job,
                write_cap,
                index,
                box_,
            } => match b.write_box(&write_cap, &index, &box_).await {
                Err(Error::BoxAlreadyExists) => Input::Refused { chat, job },
                Err(e) => return Err(e),
                Ok(()) => Input::Wrote {
                    chat,
                    job,
                    next: next(&index),
                    index,
                },
            },
            Action::Read {
                chat,
                stream,
                read_cap,
                index,
            } => {
                let r = b.read_box(&read_cap, &index).await?;
                Input::Read {
                    chat,
                    stream,
                    outcome: outcome(r, &index),
                    index,
                }
            }
            Action::Wake { chat, stream, ms } => {
                return Ok(Outcome::Later(Input::Wake { chat, stream }, ms));
            }
            Action::ScanRead {
                chat,
                stream,
                read_cap,
                index,
            } => {
                let r = b.read_box(&read_cap, &index).await?;
                Input::ScanRead {
                    chat,
                    stream,
                    outcome: outcome(r, &index),
                    index,
                }
            }
            Action::Walk {
                chat,
                stream,
                start,
                targets,
                keep,
            } => {
                let (target, skipped, steps) = walk_with(step, &start, &targets, keep)?;
                Input::Walked {
                    chat,
                    stream,
                    target,
                    skipped,
                    steps,
                }
            }
            Action::Derive {
                chat,
                stream,
                start,
                count,
            } => Input::Derived {
                chat,
                stream,
                indexes: derive_with(step, &start, count)?,
            },
            Action::Mint {
                chat,
                write_cap,
                name,
            } => {
                let m = b.voucher_mint(&write_cap, &name).await?;
                let box0 = m.write_cap[m.write_cap.len() - wire::INDEX_SIZE..].to_vec();
                self.publish(&m.write_cap, &box0, &m.payload, sleep).await?;
                Input::Minted {
                    chat,
                    minted: m,
                    box1: next(&box0),
                }
            }
            Action::AwaitReply {
                chat,
                secret_key,
                voucher_read_cap,
                box1,
                write_cap,
            } => match b.read_box(&voucher_read_cap, &box1).await {
                // A read that fails is tried again, as a box not yet written is: the reply may
                // come at any time, and only reading it lets the joiner in.
                Ok(Read::NotFound) | Err(_) => {
                    return Ok(Outcome::Retry(
                        Action::AwaitReply {
                            chat,
                            secret_key,
                            voucher_read_cap,
                            box1,
                            write_cap,
                        },
                        RETRY_MS,
                    ));
                }
                Ok(Read::Tombstone) => Input::Failed {
                    chat,
                    what: "the voucher's reply was withdrawn".into(),
                },
                Ok(Read::Data(sealed)) => Input::Opened {
                    chat,
                    opened: b.voucher_open(&secret_key, &sealed, &write_cap).await?,
                },
            },
            Action::ReadVoucher { chat, voucher } => {
                let retry = Outcome::Retry(
                    Action::ReadVoucher {
                        chat: chat.clone(),
                        voucher: voucher.clone(),
                    },
                    RETRY_MS,
                );
                let Ok((wc, rc)) = b.voucher_derive_stream(&voucher).await else {
                    return Ok(retry);
                };
                let box0 = wire::start_of(&rc).to_vec();
                match b.read_box(&rc, &box0).await {
                    Ok(Read::NotFound) | Err(_) => return Ok(retry),
                    Ok(Read::Tombstone) => Input::Failed {
                        chat,
                        what: "that voucher was withdrawn".into(),
                    },
                    Ok(Read::Data(payload)) => Input::JoinerPayload {
                        chat,
                        voucher,
                        voucher_write_cap: wc,
                        payload: payload.into(),
                        box1: next(&box0),
                    },
                }
            }
            Action::Seal {
                chat,
                voucher,
                payload,
                who_reply,
            } => Input::SealedReply {
                chat,
                inducted: b.voucher_induct(&voucher, &payload, &who_reply).await?,
            },
            Action::Publish {
                chat,
                voucher_write_cap,
                box1,
                reply,
            } => {
                self.publish(&voucher_write_cap, &box1, &reply, sleep)
                    .await?;
                Input::Published { chat }
            }
            Action::Delete { file } => {
                self.files
                    .remove(&file)
                    .map_err(|e| Error::Other(e.to_string()))?;
                return Ok(Outcome::Nothing);
            }
            Action::Load { chat, job, file } => Input::Loaded {
                chat,
                job,
                bytes: self.files.read(&file).ok(),
            },
            Action::Substream { chat, job } => Input::Substream {
                chat,
                job,
                keypair: b.new_keypair().await?,
            },
            Action::WriteChunk {
                chat,
                job,
                n,
                write_cap,
                index,
                box_,
            } => match b.write_box(&write_cap, &index, &box_).await {
                Err(Error::BoxAlreadyExists) => Input::Refused { chat, job },
                Err(e) => return Err(e),
                Ok(()) => Input::WroteChunk {
                    chat,
                    job,
                    n,
                    next: next(&index),
                },
            },
            Action::ChunkIndexes {
                chat,
                job,
                start,
                count,
            } => {
                let indexes = derive_with(step, &start, count)?;
                Input::ChunkIndexes {
                    chat,
                    job,
                    start,
                    indexes,
                }
            }
            Action::ReadChunk {
                chat,
                stream,
                read_cap,
                index,
            } => {
                let r = b.read_box(&read_cap, &index).await?;
                Input::ReadChunk {
                    chat,
                    stream,
                    outcome: outcome(r, &index),
                    index,
                }
            }
        }))
    }
}
