//! A katzenqt1 group chat client without a user interface: it takes commands one per line on its
//! input and prints what happens, as the Go module's cmd/katzenqt1 does.
//!
//! ```text
//! create G | join G | invite G CODE | send G TEXT... | sendfile G PATH | scan G
//! remove G WHO | leave G | rename G TO | chats | show G | members G
//! wait G TEXT... (until a line says it, for up to --wait seconds) | quit
//! ```
//!
//! It prints READY once started, VOUCHER=code when a voucher to join with is minted, JOINED G
//! when a group is joined, LINE G FROM: TEXT for each line that arrives, and OK and the command
//! once a command is done: saved, so that it survives the process stopping.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pigeonhole_protocols::protocols::katzenqt1::client::{Client, ClientError, Config, LineView};
use pigeonhole_protocols::protocols::katzenqt1::engine::{Status, plain};
use pigeonhole_protocols::transport::Backend;
use pigeonhole_protocols::transport::remote::Remote;
use pigeonhole_protocols::transport::thinclient::ThinClientBackend;
use tokio::io::{AsyncBufReadExt, BufReader};

struct Args {
    state: String,
    name: String,
    daemon: String,
    sim: Option<String>,
    wait: u64,
}

fn args() -> Args {
    let mut a = Args {
        state: "katzenqt1-state".into(),
        name: std::env::var("USER").unwrap_or_default(),
        daemon: "@katzenpost".into(),
        sim: None,
        wait: 1800,
    };
    let mut it = std::env::args().skip(1);
    while let Some(f) = it.next() {
        let v = it.next().unwrap_or_default();
        match f.trim_start_matches('-') {
            "state" => a.state = v,
            "name" => a.name = v,
            "daemon" => a.daemon = v,
            "sim" => a.sim = Some(v),
            "wait" => a.wait = v.trim_end_matches('s').parse().unwrap_or(1800),
            _ => {
                eprintln!("unknown flag {f}");
                std::process::exit(2);
            }
        }
    }
    a
}

fn show(l: &LineView) -> String {
    if let Some(n) = &l.line.notice {
        return format!("— {}", plain(n));
    }
    let mark = match (l.mine, l.line.status, l.acked) {
        (true, Status::Pending, _) => " …",
        (true, _, true) => " ✓✓",
        (true, _, false) => " ✓",
        _ => "",
    };
    format!("{}{mark}: {}", l.from, l.line.text)
}

async fn chat_named(c: &Client, name: &str) -> Result<String, ClientError> {
    c.chats()
        .await?
        .into_iter()
        .find(|ch| ch.name == name)
        .map(|ch| ch.id)
        .ok_or(ClientError::NoSuchChat)
}

async fn command(c: &Client, f: &[&str], wait: u64) -> Result<(), String> {
    let e = |x: ClientError| x.to_string();
    if f[0] == "chats" {
        for ch in c.chats().await.map_err(e)? {
            println!(
                "CHAT {} joined={} members={} unsent={}",
                ch.name,
                ch.joined,
                ch.members.len(),
                ch.unsent
            );
        }
        return Ok(());
    }
    if f.len() < 2 {
        return Err("needs an argument".into());
    }
    match f[0] {
        "create" => return c.create(f[1]).await.map(|_| ()).map_err(e),
        "join" => return c.join(f[1]).await.map(|_| ()).map_err(e),
        _ => {}
    }
    let id = chat_named(c, f[1]).await.map_err(e)?;
    let need = |n: usize| {
        if f.len() < n {
            Err(format!("needs {} arguments", n - 1))
        } else {
            Ok(())
        }
    };
    match f[0] {
        "invite" => {
            need(3)?;
            c.invite(&id, f[2]).await.map_err(e)
        }
        "send" => c.send(&id, &f[2..].join(" ")).await.map_err(e),
        "sendfile" => {
            need(3)?;
            let b = std::fs::read(f[2]).map_err(|x| x.to_string())?;
            c.send_file(&id, f[2], b).await.map_err(e)
        }
        "scan" => c.scan(&id).await.map_err(e),
        "remove" => {
            need(3)?;
            let k = c.member_named(&id, f[2]).await.map_err(e)?;
            c.remove(&id, k).await.map_err(e)
        }
        "leave" => c.leave(&id).await.map_err(e),
        "rename" => {
            need(3)?;
            c.rename(&id, f[2]).await.map_err(e)
        }
        "show" => {
            for l in c.lines(&id, None).await.map_err(e)? {
                println!("{}", show(&l));
            }
            Ok(())
        }
        "members" => {
            let v = c.chat(&id).await.map_err(e)?;
            let names: Vec<String> = v.members.iter().map(|m| m.name.clone()).collect();
            println!("MEMBERS {}", names.join(" "));
            Ok(())
        }
        "wait" => {
            let text = f[2..].join(" ");
            let deadline = Instant::now() + Duration::from_secs(wait);
            while Instant::now() < deadline {
                if c.lines(&id, None)
                    .await
                    .map_err(e)?
                    .iter()
                    .any(|l| l.line.notice.is_none() && !l.mine && l.line.text == text)
                {
                    println!("FOUND {text}");
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            println!("TIMEOUT {text}");
            Ok(())
        }
        _ => Err("unknown command".into()),
    }
}

/// Print what arrives.
async fn watch(c: Arc<Client>) {
    let mut events = c.subscribe();
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut joined: HashMap<String, bool> = HashMap::new();
    let mut code: HashMap<String, String> = HashMap::new();
    while let Some(ev) = events.recv().await {
        if let Some(err) = ev.error {
            println!("STOPPED {err}");
            return;
        }
        if ev.removed {
            continue;
        }
        let Ok(v) = c.chat(&ev.chat).await else {
            continue;
        };
        if !v.code.is_empty() && code.get(&ev.chat) != Some(&v.code) {
            code.insert(ev.chat.clone(), v.code.clone());
            println!("VOUCHER={}", v.code);
        }
        if v.joined && !joined.get(&ev.chat).copied().unwrap_or(false) {
            joined.insert(ev.chat.clone(), true);
            println!("JOINED {}", v.name);
        }
        let Ok(ls) = c.lines(&ev.chat, seen.get(&ev.chat).copied()).await else {
            continue;
        };
        for l in ls {
            seen.insert(ev.chat.clone(), l.line.id);
            if l.line.notice.is_none() && !l.mine {
                println!("LINE {} {}: {}", v.name, l.from, l.line.text);
            }
        }
    }
}

async fn run<B: Backend>(a: Args, backend: B) {
    let cfg = Config {
        state_dir: a.state.into(),
        name: a.name,
        epoch_poll: Duration::from_secs(60),
        no_sync: false,
        key: None,
    };
    let c = Arc::new(Client::open(cfg, backend).await.unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1)
    }));
    tokio::spawn(watch(c.clone()));
    println!("READY");
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        if f[0] == "quit" {
            break;
        }
        match command(&c, &f, a.wait).await {
            Ok(()) => println!("OK {}", f.join(" ")),
            Err(e) => println!("ERROR {}: {e}", f[0]),
        }
    }
    c.close().await;
}

#[tokio::main]
async fn main() {
    let a = args();
    match a.sim.clone() {
        Some(sock) => {
            run(
                a,
                Remote {
                    socket: sock.into(),
                },
            )
            .await
        }
        None => {
            let b = ThinClientBackend::dial(&a.daemon)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("connecting to the client daemon: {e}");
                    std::process::exit(1)
                });
            run(a, b).await
        }
    }
}
