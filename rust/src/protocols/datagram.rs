//! Datagrams between two UDP sockets over a [`stream`](super::stream) link, e.g. for mosh.
//!
//! Each datagram travels as a record, a big-endian u16 length then the datagram, and records are
//! batched into boxes by the stream. While the link is behind, at most [`QUEUE`] datagrams wait
//! and the oldest go first: a protocol that tolerates loss, as mosh does, wants the newest.
//! Empty records are not passed on.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, oneshot};

use super::stream::{self, Link, Tuning};
use crate::transport::{Backend, Result};

/// Datagrams waiting at most for the link.
pub const QUEUE: usize = 8;

#[derive(Default)]
struct Queue {
    items: VecDeque<Vec<u8>>,
    closed: bool,
    waker: Option<Waker>,
}

/// One end of a datagram tunnel: a UDP socket and the datagrams waiting to go over the link.
pub struct Tunnel {
    sock: UdpSocket,
    /// Where datagrams from the link go; if not given, whoever last sent to the socket.
    peer: Mutex<Option<SocketAddr>>,
    fixed: bool,
    q: Mutex<Queue>,
    /// The last datagram from the link.
    last: Mutex<Vec<u8>>,
    /// Notified as datagrams come from the socket, and as they go to it from the link.
    pub from_socket: Notify,
    pub to_socket: Notify,
}

impl Tunnel {
    pub fn new(sock: UdpSocket, peer: Option<SocketAddr>) -> Tunnel {
        Tunnel { sock, fixed: peer.is_some(), peer: Mutex::new(peer), q: Mutex::default(), last: Mutex::default(), from_socket: Notify::new(), to_socket: Notify::new() }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.sock.local_addr()
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        *self.peer.lock().unwrap()
    }

    /// Sends the last datagram from the link to the peer again.
    pub fn redeliver(&self) {
        if let Some(p) = self.peer() {
            let _ = self.sock.try_send_to(&self.last.lock().unwrap(), p);
        }
    }

    /// Queues a record for the peer, dropping the oldest waiting if there are [`QUEUE`].
    pub fn push(&self, d: Vec<u8>) {
        let mut q = self.q.lock().unwrap();
        if q.closed || d.len() > u16::MAX as usize {
            log::warn!("datagram: dropped {} bytes, closed or too long", d.len());
            return;
        }
        if q.items.len() == QUEUE {
            q.items.pop_front();
            log::debug!("datagram: link behind, dropped one");
        }
        q.items.push_back(d);
        if let Some(w) = q.waker.take() {
            w.wake();
        }
    }

    /// Ends this side of the session once what is queued has gone; later datagrams are dropped.
    pub fn close(&self) {
        let mut q = self.q.lock().unwrap();
        q.closed = true;
        if let Some(w) = q.waker.take() {
            w.wake();
        }
    }

    /// Carries datagrams both ways until both sides have closed. The first record from the
    /// peer goes to `tap` instead, if given. `first` is as for [`stream::run`].
    pub async fn run<B: Backend>(&self, b: Arc<B>, link: &mut Link, t: &Tuning, first: Option<Vec<u8>>, tap: Option<oneshot::Sender<Vec<u8>>>) -> Result<()> {
        let rd = Reader { t: self, cur: Vec::new(), pos: 0 };
        let wr = Writer { t: self, buf: Vec::new(), tap };
        tokio::select! {
            r = stream::run(b, link, rd, wr, t, first) => r,
            _ = self.pump() => unreachable!(),
        }
    }

    async fn pump(&self) {
        let mut buf = vec![0u8; 65536];
        loop {
            match self.sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    if !self.fixed {
                        *self.peer.lock().unwrap() = Some(from);
                    }
                    self.push(buf[..n].to_vec());
                    self.from_socket.notify_one();
                }
                Err(e) => {
                    log::warn!("udp: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }
}

struct Reader<'a> {
    t: &'a Tunnel,
    cur: Vec<u8>,
    pos: usize,
}

impl AsyncRead for Reader<'_> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if me.pos == me.cur.len() {
            let mut q = me.t.q.lock().unwrap();
            match q.items.pop_front() {
                Some(d) => {
                    me.cur = [&(d.len() as u16).to_be_bytes()[..], &d].concat();
                    me.pos = 0;
                }
                None if q.closed => return Poll::Ready(Ok(())),
                None => {
                    q.waker = Some(cx.waker().clone());
                    return Poll::Pending;
                }
            }
        }
        let n = buf.remaining().min(me.cur.len() - me.pos);
        buf.put_slice(&me.cur[me.pos..me.pos + n]);
        me.pos += n;
        Poll::Ready(Ok(()))
    }
}

struct Writer<'a> {
    t: &'a Tunnel,
    buf: Vec<u8>,
    tap: Option<oneshot::Sender<Vec<u8>>>,
}

impl AsyncWrite for Writer<'_> {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        me.buf.extend_from_slice(data);
        let mut at = 0;
        while let Some(h) = me.buf.get(at..at + 2) {
            let end = at + 2 + u16::from_be_bytes([h[0], h[1]]) as usize;
            let Some(rec) = me.buf.get(at + 2..end) else { break };
            if let Some(tap) = me.tap.take() {
                let _ = tap.send(rec.to_vec());
            } else if let (false, Some(p)) = (rec.is_empty(), *me.t.peer.lock().unwrap()) {
                // A full socket buffer loses the datagram, as the network would.
                match me.t.sock.try_send_to(rec, p) {
                    Ok(_) => {
                        *me.t.last.lock().unwrap() = rec.to_vec();
                        me.t.to_socket.notify_one()
                    }
                    Err(e) => log::debug!("udp: {e}"),
                }
            }
            at = end;
        }
        me.buf.drain(..at);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// The peer has closed its side, so close ours.
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.t.close();
        Poll::Ready(Ok(()))
    }
}
