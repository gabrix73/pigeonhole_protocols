//! Carrying out the engine's actions over a transport.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;

use crate::protocols::katzenqt1::engine::{Action, ChatId, Input, Outcome as ReadOutcome};
use crate::protocols::katzenqt1::member::{Index, Key, derive_with, next_index, walk_with};
use crate::protocols::katzenqt1::wire as wire;
use crate::transport::{Backend, Error, Pushed, Read};

/// How long to wait, in milliseconds, before trying a failed write or read again.
pub const RETRY_MS: u64 = 5000;
/// How long a stream waiting for a box the transport will push reads again anyway, in case the
/// push was lost.
pub const PUSHED_POLL_MS: u64 = 300_000;

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
/// input to hand the engine later, or, for `Pushed`, as soon as the box is pushed.
#[derive(Debug)]
pub enum Outcome {
    Done(Input),
    Retry(Action, u64),
    Later(Input, u64),
    Pushed(Input, u64, Pushed),
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
    /// Per chat and stream, the push of the box it last missed.
    watched: Mutex<HashMap<(ChatId, Key), Pushed>>,
}

impl<B: Backend, F: Files> Executor<B, F> {
    pub fn new(backend: B, files: F) -> Self {
        Executor { backend, files, watched: Mutex::default() }
    }

    /// After a miss, asks the transport to push the box, for the wake that follows.
    async fn watch(&self, chat: &ChatId, stream: &Key, read_cap: &[u8], index: &[u8], r: &Read) {
        if *r != Read::NotFound {
            return;
        }
        let p = self.backend.watch(read_cap, index).await;
        let mut w = self.watched.lock().unwrap();
        match p {
            Some(p) => w.insert((chat.clone(), stream.clone()), p),
            None => w.remove(&(chat.clone(), stream.clone())),
        };
    }

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
                self.watch(&chat, &stream, &read_cap, &index, &r).await;
                Input::Read {
                    chat,
                    stream,
                    outcome: outcome(r, &index),
                    index,
                }
            }
            Action::Wake { chat, stream, ms } => {
                let pushed = self.watched.lock().unwrap().remove(&(chat.clone(), stream.clone()));
                return Ok(match pushed {
                    Some(p) => Outcome::Pushed(Input::Wake { chat, stream }, PUSHED_POLL_MS, p),
                    None => Outcome::Later(Input::Wake { chat, stream }, ms),
                });
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
                form,
            } => {
                let m = b.voucher_mint(&write_cap, &name, form).await?;
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
                version,
            } => {
                // A read that fails is tried again, as a box not yet written is: the reply may
                // come at any time, and only reading it lets the joiner in. A version 2 reply is
                // framed over boxes 1 on, C pieces then an F piece; version 1 is box 1 alone.
                let mut sealed = Vec::new();
                let mut index = box1.clone();
                loop {
                    let piece = match b.read_box(&voucher_read_cap, &index).await {
                        Ok(Read::NotFound) | Err(_) => {
                            return Ok(Outcome::Retry(
                                Action::AwaitReply {
                                    chat,
                                    secret_key,
                                    voucher_read_cap,
                                    box1,
                                    write_cap,
                                    version,
                                },
                                RETRY_MS,
                            ));
                        }
                        Ok(Read::Tombstone) => {
                            break Input::Failed {
                                chat,
                                what: "the voucher's reply was withdrawn".into(),
                            };
                        }
                        Ok(Read::Data(piece)) => piece,
                    };
                    if version < 2 {
                        sealed = piece;
                    } else {
                        match piece.first() {
                            Some(b'C') | Some(b'F') => sealed.extend_from_slice(&piece[1..]),
                            _ => {
                                break Input::Failed {
                                    chat,
                                    what: "the voucher's reply is not framed".into(),
                                };
                            }
                        }
                        if piece[0] == b'C' {
                            index = step(&index)?;
                            continue;
                        }
                    }
                    break Input::Opened {
                        chat,
                        opened: b.voucher_open(&secret_key, &sealed, &write_cap).await?,
                    };
                }
            }
            Action::ReadVoucher { chat, voucher } => {
                let retry = Outcome::Retry(
                    Action::ReadVoucher {
                        chat: chat.clone(),
                        voucher: voucher.clone(),
                    },
                    RETRY_MS,
                );
                // Deriving can only fail for good on a voucher of the wrong size; other errors are the transport's.
                if voucher.len() != 32 {
                    return Ok(Outcome::Done(Input::Failed {
                        chat,
                        what: "that voucher is not 32 bytes".into(),
                    }));
                }
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
                version,
            } => {
                if version < 2 {
                    self.publish(&voucher_write_cap, &box1, &reply, sleep)
                        .await?;
                    return Ok(Outcome::Done(Input::Published { chat }));
                }
                let piece = b.max_plaintext().await?.saturating_sub(1).max(1);
                let mut index = box1;
                let mut rest: &[u8] = &reply;
                let mut n = 0;
                loop {
                    let (tag, chunk) = if rest.len() <= piece {
                        (b'F', rest)
                    } else {
                        (b'C', &rest[..piece])
                    };
                    rest = &rest[chunk.len()..];
                    let box_ = [&[tag][..], chunk].concat();
                    match self.publish(&voucher_write_cap, &index, &box_, &sleep).await {
                        // A piece written before a restart is fine; box 1 taken by another's
                        // reply is not.
                        Err(Error::BoxAlreadyExists) if n > 0 => {}
                        r => r?,
                    }
                    if tag == b'F' {
                        break Input::Published { chat };
                    }
                    index = step(&index)?;
                    n += 1;
                }
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
                self.watch(&chat, &stream, &read_cap, &index, &r).await;
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
