//! `ph`: a byte stream over Pigeonhole, on the mixnet or on Reticulum.
//!
//! ```text
//! ph link new STATE            # prints a code for the peer
//! ph link accept STATE CODE
//! ph pipe STATE                # stdin and stdout, e.g. ssh -o ProxyCommand="ph pipe STATE" host
//! ph serve --to HOST:PORT STATE
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
