//! `ph`: a byte stream over Pigeonhole, on the mixnet or on Reticulum.
//!
//! ```text
//! ph link new STATE            # prints a code for the peer
//! ph link accept STATE CODE
//! ph pipe STATE                # stdin and stdout, e.g. ssh -o ProxyCommand="ph pipe STATE" host
//! ph serve --to HOST:PORT STATE
//! ph udp --listen 127.0.0.1:PORT STATE   # datagrams to this port reach the server's --to
//! ph udp --to HOST:PORT STATE
//! ph mosh STATE                # mosh-client here, to a mosh-server the other end starts
//! ph mosh --serve STATE
//! ```
//!
//! A link's state file holds its caps and where each stream is; one session runs on it at a
//! time, and a session ends once both sides have ended theirs.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use clap::{Parser, Subcommand};
use pigeonhole_protocols::protocols::datagram::Tunnel;
use pigeonhole_protocols::protocols::stream::{self, Link, Tuning};
use pigeonhole_protocols::transport::Backend;
use pigeonhole_protocols::transport::thinclient::ThinClientBackend;

#[derive(Parser)]
struct Args {
    /// The client daemon to reach the mixnet through.
    #[arg(long, default_value = "@katzenpost")]
    daemon: String,
    /// Reticulum instead: a Reticulum TCP server interface, HOST:PORT.
    #[arg(long)]
    rns: Option<String>,
    /// The box size on Reticulum.
    #[arg(long, default_value_t = 1549)]
    box_size: usize,
    #[arg(long)]
    window: Option<usize>,
    #[arg(long)]
    reads: Option<usize>,
    #[arg(long)]
    flush_ms: Option<u64>,
    #[arg(long)]
    poll_min_ms: Option<u64>,
    #[arg(long)]
    poll_max_ms: Option<u64>,
    #[arg(long)]
    hot_ms: Option<u64>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(subcommand)]
    Link(LinkCmd),
    /// Carry stdin to the link's peer and its bytes to stdout.
    Pipe { state: PathBuf },
    /// Carry each session on the link to a new TCP connection.
    Serve {
        #[arg(long)]
        to: String,
        state: PathBuf,
    },
    /// Carry datagrams: from a local UDP port until interrupted, or with --to, to one for each session.
    Udp {
        #[arg(long, required_unless_present = "to", conflicts_with = "to")]
        listen: Option<String>,
        #[arg(long)]
        to: Option<String>,
        state: PathBuf,
    },
    /// Run mosh-client over the link, or with --serve, start a mosh-server for each session.
    Mosh {
        #[arg(long)]
        serve: bool,
        state: PathBuf,
    },
}

#[derive(Subcommand)]
enum LinkCmd {
    New { state: PathBuf },
    Accept { state: PathBuf, code: String },
}

fn fail(e: impl std::fmt::Display) -> ! {
    eprintln!("ph: {e}");
    std::process::exit(1)
}

/// Locks the link at `path` for this process, so that one session runs on it at a time.
fn lock(path: &Path) -> File {
    let f = File::create(path.with_extension("lock")).unwrap_or_else(|e| fail(e));
    f.lock().unwrap_or_else(|e| fail(e));
    f
}

fn load(path: &Path) -> Link {
    let s = std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())));
    Link::from_json(&s).unwrap_or_else(|e| fail(e))
}

fn save(path: &Path, l: &Link) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, l.to_json())
        .and_then(|_| std::fs::rename(&tmp, path))
        .unwrap_or_else(|e| fail(e));
}

async fn bind(addr: &str) -> tokio::net::UdpSocket {
    tokio::net::UdpSocket::bind(addr).await.unwrap_or_else(|e| fail(format!("{addr}: {e}")))
}

/// Runs `run`; a first interrupt closes the tunnel's side of the session, a second quits.
async fn closing<R>(tun: &Tunnel, run: impl Future<Output = R>) -> R {
    tokio::pin!(run);
    tokio::select! {
        r = &mut run => return r,
        _ = tokio::signal::ctrl_c() => {}
    }
    eprintln!("ph: ending the session; interrupt again to quit without saving the link");
    tun.close();
    tokio::select! {
        r = run => r,
        _ = tokio::signal::ctrl_c() => fail("quit mid-session"),
    }
}

/// Holds the mosh-server at `pid` stopped until the client's first datagram reaches it: it gives
/// up on a client silent for 60 s, well under a round trip of boxes, and it reads the waiting
/// datagram before it checks the time once continued.
async fn hold(tun: &Tunnel, pid: u32) {
    // SAFETY: kill(2) on a pid of ours.
    unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
    tun.to_socket.notified().await;
    unsafe { libc::kill(pid as i32, libc::SIGCONT) };
}

/// Runs mosh-client over `tun`. It gives up on a server silent for 15 s, so a first one only
/// sends the server its first datagram, and the one kept starts once the server's reply is here
/// and is handed that reply.
async fn mosh_client(tun: &Tunnel, key: &str) {
    let port = tun.local_addr().unwrap().port().to_string();
    let mosh = || tokio::process::Command::new("mosh-client").env("MOSH_KEY", key).args(["127.0.0.1", &port]).spawn();
    // SAFETY: termios of stdin, restored as the first mosh-client is killed in raw mode.
    let mut tty: libc::termios = unsafe { std::mem::zeroed() };
    let tty = (unsafe { libc::tcgetattr(0, &mut tty) } == 0).then_some(tty);
    let mut first = match mosh() {
        Ok(c) => c,
        Err(e) => return eprintln!("ph: mosh-client: {e}"),
    };
    tokio::select! {
        _ = first.wait() => return,
        _ = tun.from_socket.notified() => {}
    }
    let _ = first.kill().await;
    if let Some(t) = tty {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };
    }
    eprint!("\r\nph: waiting for the mosh-server's reply\r\n");
    tokio::select! {
        _ = tun.to_socket.notified() => {}
        _ = tokio::signal::ctrl_c() => return,
    }
    let old = tun.peer();
    let mut c = match mosh() {
        Ok(c) => c,
        Err(e) => return eprintln!("ph: mosh-client: {e}"),
    };
    let hello = async {
        while tun.peer() == old {
            tun.from_socket.notified().await;
        }
        tun.redeliver();
        std::future::pending::<()>().await
    };
    tokio::select! {
        _ = c.wait() => {}
        _ = hello => {}
    }
}

/// Starts a mosh-server on localhost: its pid, port and `MOSH CONNECT PORT KEY` line.
async fn mosh_server() -> Result<(u32, u16, String), String> {
    let o = tokio::process::Command::new("mosh-server")
        .args(["new", "-i", "127.0.0.1"])
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| format!("mosh-server: {e}"))?;
    let out = String::from_utf8_lossy(&o.stdout);
    let line = out.lines().find(|l| l.starts_with("MOSH CONNECT ")).ok_or_else(|| String::from_utf8_lossy(&o.stderr).trim().to_string())?;
    let port = line.split(' ').nth(2).and_then(|p| p.parse().ok()).ok_or("mosh-server: no port")?;
    let err = String::from_utf8_lossy(&o.stderr);
    let pid = err.split("[mosh-server detached, pid = ").nth(1).and_then(|r| r.split(']').next()?.parse().ok()).ok_or("mosh-server: no pid")?;
    Ok((pid, port, line.to_string()))
}

async fn go<B: Backend>(b: Arc<B>, cmd: Cmd, t: Tuning) {
    match cmd {
        Cmd::Link(LinkCmd::New { state }) => {
            let (mine, theirs) = stream::new_link(&*b).await.unwrap_or_else(|e| fail(e));
            save(&state, &mine);
            println!("{}", B64.encode(theirs.to_json()));
        }
        Cmd::Link(LinkCmd::Accept { .. }) => unreachable!(),
        Cmd::Pipe { state } => {
            // ssh sends its ProxyCommand SIGHUP on exit; carry on to end the session.
            let _hup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup());
            let _lock = lock(&state);
            let mut l = load(&state);
            let r = stream::run(b, &mut l, tokio::io::stdin(), tokio::io::stdout(), &t, None).await;
            save(&state, &l);
            r.unwrap_or_else(|e| fail(e));
        }
        Cmd::Serve { to, state } => {
            let _lock = lock(&state);
            let mut l = load(&state);
            loop {
                let first = stream::accept(&*b, &l, &t).await.unwrap_or_else(|e| fail(e));
                eprintln!("ph: session, to {to}");
                // shortcut: a refused connection ends the server, not just the session; answer
                // the peer with an end of stream once sessions need to outlive the target.
                let c = tokio::net::TcpStream::connect(&to).await.unwrap_or_else(|e| fail(e));
                let (rd, wr) = c.into_split();
                let r = stream::run(b.clone(), &mut l, rd, wr, &t, Some(first)).await;
                save(&state, &l);
                r.unwrap_or_else(|e| fail(e));
                eprintln!("ph: session ended");
            }
        }
        Cmd::Udp { listen: Some(addr), state, .. } => {
            let _lock = lock(&state);
            let mut l = load(&state);
            let tun = Tunnel::new(bind(&addr).await, None);
            let r = closing(&tun, tun.run(b, &mut l, &t, None, None)).await;
            save(&state, &l);
            r.unwrap_or_else(|e| fail(e));
        }
        Cmd::Udp { to, state, .. } => {
            let to = to.unwrap();
            let _lock = lock(&state);
            let mut l = load(&state);
            let addr = tokio::net::lookup_host(&to).await.ok().and_then(|mut a| a.next()).unwrap_or_else(|| fail(format!("{to}: no address")));
            loop {
                let first = stream::accept(&*b, &l, &t).await.unwrap_or_else(|e| fail(e));
                eprintln!("ph: session, to {to}");
                let tun = Tunnel::new(bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await, Some(addr));
                let r = tun.run(b.clone(), &mut l, &t, Some(first), None).await;
                save(&state, &l);
                r.unwrap_or_else(|e| fail(e));
                eprintln!("ph: session ended");
            }
        }
        Cmd::Mosh { serve: false, state } => {
            let _lock = lock(&state);
            let mut l = load(&state);
            let tun = Tunnel::new(bind("127.0.0.1:0").await, None);
            // Starts the session; the server answers with its mosh-server's line.
            tun.push(Vec::new());
            let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
            let client = async {
                eprintln!("ph: waiting for the mosh-server");
                let line = tokio::select! {
                    r = rx => r.map(|l| String::from_utf8_lossy(&l).into_owned()).unwrap_or_default(),
                    _ = tokio::signal::ctrl_c() => String::new(),
                };
                match line.strip_prefix("MOSH CONNECT ").and_then(|r| r.split(' ').nth(1)) {
                    Some(key) => mosh_client(&tun, key.trim()).await,
                    None if !line.is_empty() => eprintln!("ph: {line}"),
                    None => {}
                }
                tun.close();
            };
            let (r, _) = closing(&tun, async { tokio::join!(tun.run(b, &mut l, &t, None, Some(tx)), client) }).await;
            save(&state, &l);
            r.unwrap_or_else(|e| fail(e));
        }
        Cmd::Mosh { serve: true, state } => {
            let _lock = lock(&state);
            let mut l = load(&state);
            loop {
                let first = stream::accept(&*b, &l, &t).await.unwrap_or_else(|e| fail(e));
                eprintln!("ph: session, starting a mosh-server");
                let sock = bind("127.0.0.1:0").await;
                let (tun, pid) = match mosh_server().await {
                    Ok((pid, port, line)) => {
                        let tun = Tunnel::new(sock, Some(([127, 0, 0, 1], port).into()));
                        tun.push(line.into_bytes());
                        (tun, Some(pid))
                    }
                    Err(e) => {
                        eprintln!("ph: {e}");
                        let tun = Tunnel::new(sock, None);
                        tun.push(e.into_bytes());
                        tun.close();
                        (tun, None)
                    }
                };
                let held = async {
                    match pid {
                        Some(pid) => hold(&tun, pid).await,
                        None => std::future::pending().await,
                    }
                };
                let r = {
                    let run = tun.run(b.clone(), &mut l, &t, Some(first), None);
                    tokio::pin!(run);
                    tokio::select! {
                        r = &mut run => r,
                        _ = held => run.await,
                    }
                };
                save(&state, &l);
                r.unwrap_or_else(|e| fail(e));
                eprintln!("ph: session ended");
            }
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let a = Args::parse();
    let mut t = if a.rns.is_some() { Tuning::reticulum() } else { Tuning::mixnet() };
    let ms = Duration::from_millis;
    t.window = a.window.unwrap_or(t.window);
    t.reads = a.reads.unwrap_or(t.reads);
    t.flush = a.flush_ms.map(ms).unwrap_or(t.flush);
    t.poll_min = a.poll_min_ms.map(ms).unwrap_or(t.poll_min);
    t.poll_max = a.poll_max_ms.map(ms).unwrap_or(t.poll_max);
    t.hot = a.hot_ms.map(ms).unwrap_or(t.hot);
    if let Cmd::Link(LinkCmd::Accept { state, code }) = a.cmd {
        let j = B64.decode(code.trim()).unwrap_or_else(|e| fail(e));
        let l = Link::from_json(&String::from_utf8_lossy(&j)).unwrap_or_else(|e| fail(e));
        return save(&state, &l);
    }
    match a.rns {
        Some(addr) => rns(&addr, a.box_size, a.cmd, t).await,
        None => {
            let b = ThinClientBackend::dial(&a.daemon).await.unwrap_or_else(|e| fail(format!("connecting to the client daemon: {e}")));
            go(Arc::new(b), a.cmd, t).await
        }
    }
}

#[cfg(feature = "reticulum-rs")]
async fn rns(addr: &str, box_size: usize, cmd: Cmd, t: Tuning) {
    use pigeonhole_protocols::transport::reticulum_rs::ReticulumRsBackend;
    let b = ReticulumRsBackend::connect(addr, box_size, Duration::from_secs(60)).await.unwrap_or_else(|e| fail(e));
    go(Arc::new(b), cmd, t).await
}

#[cfg(not(feature = "reticulum-rs"))]
async fn rns(_: &str, _: usize, _: Cmd, _: Tuning) {
    fail("--rns needs the reticulum-rs feature")
}
