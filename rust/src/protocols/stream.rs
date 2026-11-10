//! A byte stream between two peers over a pair of Pigeonhole streams, one per direction.
//!
//! Each box holds one flags byte then up to a box less one of the stream's bytes; bit 0 of the
//! flags ends the stream. Bytes go out once a box is full or the input has been idle for
//! [`Tuning::flush`]. Up to [`Tuning::window`] boxes are written at once and read ahead at once,
//! and delivered in index order. Reads poll fast while bytes move and back off while idle.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, sleep_until, timeout};

use crate::protocols::katzenqt1::member::next_index;
use crate::transport::{Backend, Error, Read, Result};

const EOF: u8 = 1;

/// One end of a link: the stream it writes and the stream it reads, each at the next box.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    pub write_cap: Vec<u8>,
    pub write_index: Vec<u8>,
    pub read_cap: Vec<u8>,
    pub read_index: Vec<u8>,
}

impl Link {
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "write_cap": hex::encode(&self.write_cap),
            "write_index": hex::encode(&self.write_index),
            "read_cap": hex::encode(&self.read_cap),
            "read_index": hex::encode(&self.read_index),
        })
        .to_string()
    }

    pub fn from_json(s: &str) -> Result<Link> {
        let v: serde_json::Value = serde_json::from_str(s).map_err(|e| Error::Other(e.to_string()))?;
        let f = |k: &str| {
            v[k].as_str()
                .and_then(|h| hex::decode(h).ok())
                .ok_or_else(|| Error::Other(format!("link: no {k}")))
        };
        Ok(Link { write_cap: f("write_cap")?, write_index: f("write_index")?, read_cap: f("read_cap")?, read_index: f("read_index")? })
    }
}

/// The two ends of a new link.
pub async fn new_link<B: Backend>(b: &B) -> Result<(Link, Link)> {
    let (x, y) = (b.new_keypair().await?, b.new_keypair().await?);
    let a = Link { write_cap: x.write_cap.to_vec(), write_index: x.first.clone(), read_cap: y.read_cap.to_vec(), read_index: y.first.clone() };
    let b = Link { write_cap: y.write_cap.to_vec(), write_index: y.first, read_cap: x.read_cap.to_vec(), read_index: x.first };
    Ok((a, b))
}

#[derive(Clone, Debug)]
pub struct Tuning {
    /// Boxes written at once.
    pub window: usize,
    /// Reads in flight at once, over the next `window` boxes.
    pub reads: usize,
    /// Idle input this long sends what is buffered.
    pub flush: Duration,
    /// Poll intervals while active and at most while idle.
    pub poll_min: Duration,
    pub poll_max: Duration,
    /// How long after bytes last moved polls stay at `poll_min` before backing off.
    pub hot: Duration,
}

impl Tuning {
    /// For the mixnet, where a box takes tens of seconds.
    pub fn mixnet() -> Tuning {
        Tuning { window: 8, reads: 12, flush: Duration::from_millis(20), poll_min: Duration::from_secs(2), poll_max: Duration::from_secs(20), hot: Duration::from_secs(120) }
    }

    /// For Reticulum, where a box takes tens of milliseconds and queries go one at a time.
    pub fn reticulum() -> Tuning {
        Tuning { window: 2, reads: 2, flush: Duration::from_millis(5), poll_min: Duration::from_millis(20), poll_max: Duration::from_secs(1), hot: Duration::from_secs(5) }
    }
}

/// A box: the flags byte, then the bytes.
pub fn encode(data: &[u8], eof: bool) -> Vec<u8> {
    [&[eof as u8][..], data].concat()
}

/// The bytes a box holds and whether the stream ends with them.
pub fn decode(b: &[u8]) -> Result<(&[u8], bool)> {
    match b.split_first() {
        Some((&f, d)) if f & !EOF == 0 => Ok((d, f & EOF != 0)),
        _ => Err(Error::Other("stream: not a stream box".into())),
    }
}

fn step(i: &[u8]) -> Result<Vec<u8>> {
    next_index(i).ok_or_else(|| Error::Other("stream: no index after".into()))
}

/// Waits, backing off to `poll_max`, for the first box of a session, and returns it.
pub async fn accept<B: Backend>(b: &B, link: &Link, t: &Tuning) -> Result<Vec<u8>> {
    let mut delay = t.poll_min;
    loop {
        match b.read_box(&link.read_cap, &link.read_index).await {
            Ok(Read::Data(d)) => return Ok(d),
            Ok(Read::NotFound) => {}
            Ok(Read::Tombstone) => return Err(Error::Other("stream: tombstone".into())),
            Err(Error::Closed) => return Err(Error::Closed),
            Err(e) => log::warn!("read: {e}"),
        }
        sleep(delay).await;
        delay = (delay * 2).min(t.poll_max);
    }
}

/// Carries `input` to the peer and the peer's bytes to `output` until both directions have
/// ended, advancing `link` past them. `first` is the read index's box, if already read.
pub async fn run<B, R, W>(b: Arc<B>, link: &mut Link, input: R, output: W, t: &Tuning, first: Option<Vec<u8>>) -> Result<()>
where
    B: Backend,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let active = Notify::new();
    let Link { write_cap, write_index, read_cap, read_index } = link;
    tokio::try_join!(
        send(b.clone(), write_cap, write_index, input, t, &active),
        recv(b, read_cap, read_index, output, t, &active, first),
    )?;
    Ok(())
}

async fn send<B: Backend, R: AsyncRead + Unpin>(b: Arc<B>, cap: &[u8], index: &mut Vec<u8>, mut input: R, t: &Tuning, active: &Notify) -> Result<()> {
    let room = b.max_plaintext().await? - 1;
    let cap: Arc<[u8]> = cap.into();
    let slots = Arc::new(Semaphore::new(t.window));
    let mut writes = JoinSet::new();
    let (mut buf, mut tmp) = (Vec::with_capacity(room), vec![0u8; room]);
    loop {
        let want = room - buf.len();
        let r = if buf.is_empty() {
            Some(input.read(&mut tmp[..want]).await)
        } else {
            timeout(t.flush, input.read(&mut tmp[..want])).await.ok()
        };
        let idle = r.is_none();
        let eof = match r {
            Some(Ok(0)) => true,
            Some(Ok(n)) => {
                buf.extend_from_slice(&tmp[..n]);
                false
            }
            Some(Err(e)) => {
                log::warn!("input: {e}");
                true
            }
            None => false,
        };
        if eof || idle || buf.len() == room {
            let permit = slots.clone().acquire_owned().await.unwrap();
            let (b, cap, i, data) = (b.clone(), cap.clone(), index.clone(), encode(&buf, eof));
            writes.spawn(async move {
                let _permit = permit;
                loop {
                    match b.write_box(&cap, &i, &data).await {
                        Ok(()) => return Ok(()),
                        Err(e @ (Error::BoxAlreadyExists | Error::Closed)) => return Err(e),
                        Err(e) => log::warn!("write: {e}"),
                    }
                    sleep(Duration::from_secs(1)).await;
                }
            });
            *index = step(index)?;
            buf.clear();
            active.notify_one();
            if eof {
                break;
            }
        }
        while let Some(w) = writes.try_join_next() {
            w.map_err(|e| Error::Other(e.to_string()))??;
        }
    }
    while let Some(w) = writes.join_next().await {
        w.map_err(|e| Error::Other(e.to_string()))??;
    }
    Ok(())
}

async fn recv<B: Backend, W: AsyncWrite + Unpin>(
    b: Arc<B>,
    cap: &[u8],
    index: &mut Vec<u8>,
    mut output: W,
    t: &Tuning,
    active: &Notify,
    first: Option<Vec<u8>>,
) -> Result<()> {
    let cap: Arc<[u8]> = cap.into();
    // The indexes of boxes next..next+window.
    let mut ahead = VecDeque::from([index.clone()]);
    while ahead.len() < t.window.max(1) {
        ahead.push_back(step(ahead.back().unwrap())?);
    }
    let mut next = 0u64;
    let mut got: HashMap<u64, Vec<u8>> = first.into_iter().map(|d| (0, d)).collect();
    let mut reads: JoinSet<(u64, Result<Read>)> = JoinSet::new();
    let (mut delay, mut tick, mut moved) = (t.poll_min, Instant::now(), Instant::now());
    let mut out_ok = true;
    loop {
        while let Some(d) = got.remove(&next) {
            let (data, eof) = decode(&d)?;
            if out_ok && let Err(e) = output.write_all(data).await.and(output.flush().await) {
                log::warn!("output: {e}");
                out_ok = false;
            }
            next += 1;
            ahead.pop_front();
            ahead.push_back(step(ahead.back().unwrap())?);
            if eof {
                *index = ahead.pop_front().unwrap();
                reads.abort_all();
                let _ = output.shutdown().await;
                return Ok(());
            }
            (delay, tick, moved) = (t.poll_min, Instant::now(), Instant::now());
        }
        tokio::select! {
            r = reads.join_next(), if !reads.is_empty() => match r.unwrap() {
                Ok((s, Ok(Read::Data(d)))) if s >= next => { got.insert(s, d); }
                Ok((_, Ok(Read::Tombstone))) => return Err(Error::Other("stream: tombstone".into())),
                Ok((_, Err(Error::Closed))) => return Err(Error::Closed),
                Ok((_, Err(e))) => log::warn!("read: {e}"),
                _ => {}
            },
            _ = sleep_until(tick) => {
                for (k, i) in ahead.iter().enumerate() {
                    let s = next + k as u64;
                    if reads.len() >= t.reads {
                        break;
                    }
                    if !got.contains_key(&s) {
                        let (b, cap, i) = (b.clone(), cap.clone(), i.clone());
                        reads.spawn(async move { (s, b.read_box(&cap, &i).await) });
                    }
                }
                tick = Instant::now() + delay;
                if moved.elapsed() > t.hot {
                    delay = (delay * 2).min(t.poll_max);
                }
            },
            _ = active.notified() => {
                (delay, moved) = (t.poll_min, Instant::now());
                tick = tick.min(Instant::now() + delay);
            },
        }
    }
}
