//! A minimal katzenqt1 group chat: one member, talking to a Katzenpost client daemon, or to
//! pigeonhole-sim for trying it on one machine.
//!
//! ```text
//! cargo run --release -p pigeonhole-examples --example chat -- -name alice -state alice
//! cargo run --release -p pigeonhole-examples --example chat -- -name alice -state alice -sim pigeonhole.sock
//! ```
//!
//! Anything typed is said in the current group. Commands:
//!
//! ```text
//! /create GROUP   found a group
//! /join GROUP     ask to join a group: prints a voucher code to give one of its members
//! /invite CODE    add the member whose voucher code this is to the current group
//! /file PATH      send a file to the current group
//! /to GROUP       make GROUP the current group
//! /groups         list the groups
//! /quit
//! ```

use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::path::Path;
use std::time::Duration;

use pigeonhole_protocols::protocols::katzenqt1::client::{Client, ClientError, Config, LineView};
use pigeonhole_protocols::protocols::katzenqt1::engine::plain;
use pigeonhole_protocols::transport::Backend;
use pigeonhole_protocols::transport::remote::Remote;
use pigeonhole_protocols::transport::thinclient::ThinClientBackend;
use tokio::io::{AsyncBufReadExt, BufReader};

struct Args {
    name: String,
    state: String,
    daemon: String,
    sim: Option<String>,
}

fn args() -> Args {
    let mut a = Args {
        name: std::env::var("USER").unwrap_or_default(),
        state: "chat-state".into(),
        daemon: "@katzenpost".into(),
        sim: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let v = it.next().unwrap_or_default();
        match flag.trim_start_matches('-') {
            "name" => a.name = v,
            "state" => a.state = v,
            "daemon" => a.daemon = v,
            "sim" => a.sim = Some(v),
            _ => {
                eprintln!("unknown flag {flag}");
                std::process::exit(2);
            }
        }
    }
    a
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let a = args();
    // The backend is Pigeonhole: the mixnet through the client daemon, or an imitation of it.
    match &a.sim {
        Some(socket) => {
            let backend = Remote {
                socket: socket.into(),
            };
            run(&a, backend).await
        }
        None => {
            let backend = ThinClientBackend::dial(&a.daemon).await?;
            let client = backend.client.clone();
            let r = run(&a, backend).await;
            client.stop().await;
            r
        }
    }
}

async fn run<B: Backend>(a: &Args, backend: B) -> Result<(), Box<dyn Error>> {
    // Open loads what is in the state directory and carries on with anything left under way.
    let cfg = Config {
        state_dir: a.state.clone().into(),
        name: a.name.clone(),
        epoch_poll: Duration::from_secs(60),
        no_sync: false,
        key: None,
    };
    let c = Client::open(cfg, backend).await?;

    // Subscribe before showing anything, so that no change falls between the two.
    let mut events = c.subscribe();
    let mut view = View::default();
    let chats = c.chats().await?;
    for ch in &chats {
        view.update(&c, &ch.id).await;
    }
    // The current group is the one last made, to begin with.
    let mut current = chats.last().map(|ch| ch.id.clone()).unwrap_or_default();

    let mut input = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            line = input.next_line() => {
                let Some(line) = line? else { break };
                if !command(&c, &mut current, line.trim()).await {
                    break;
                }
            }
            Some(e) = events.recv() => {
                if let Some(err) = e.error {
                    // The client stops rather than send anything it could not save first.
                    return Err(format!("the client stopped: {err}").into());
                }
                if !e.removed {
                    view.update(&c, &e.chat).await;
                }
            }
        }
    }
    c.close().await;
    Ok(())
}

/// Carry out one line of input; `false` to stop.
async fn command(c: &Client, current: &mut String, line: &str) -> bool {
    if line.is_empty() {
        return true;
    }
    let Some(cmd) = line.strip_prefix('/') else {
        if current.is_empty() {
            println!("no group yet: /create one, or /join one");
        } else {
            report(c.send(current, line).await);
        }
        return true;
    };
    let (cmd, arg) = cmd.split_once(' ').unwrap_or((cmd, ""));
    match cmd {
        "create" => report(c.create(arg).await.map(|id| *current = id)),
        "join" => report(c.join(arg).await.map(|id| *current = id)),
        "invite" => report(c.invite(current, arg).await),
        "file" => match std::fs::read(arg) {
            Ok(b) => {
                let name = Path::new(arg).file_name().unwrap_or_default();
                report(c.send_file(current, &name.to_string_lossy(), b).await)
            }
            Err(e) => println!("error: {e}"),
        },
        "to" => match c
            .chats()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|ch| ch.name == arg)
        {
            Some(ch) => *current = ch.id,
            None => println!("no group called {arg}"),
        },
        "groups" => {
            for ch in c.chats().await.unwrap_or_default() {
                let names: Vec<String> = ch.members.into_iter().map(|m| m.name).collect();
                println!(
                    "{}: joined {}, with {}",
                    ch.name,
                    ch.joined,
                    names.join(", ")
                );
            }
        }
        "quit" => return false,
        _ => println!("unknown command {cmd}"),
    }
    true
}

/// Print what went wrong with a command. A command that returns `Ok` has been saved to disk; it
/// goes out over the network after, in the background.
fn report<T>(r: Result<T, ClientError>) {
    if let Err(e) = r {
        println!("error: {e}");
    }
}

/// Prints each group's lines as they arrive.
#[derive(Default)]
struct View {
    /// The last line printed, for each group.
    shown: HashMap<String, usize>,
    /// Our messages not yet acknowledged, for each group.
    unread: HashMap<String, BTreeSet<usize>>,
    /// The groups whose voucher code has been printed.
    codes: HashSet<String>,
}

impl View {
    /// Print a group's new lines, and which of our messages have come to be read.
    async fn update(&mut self, c: &Client, id: &str) {
        let Ok(ch) = c.chat(id).await else { return };
        // While joining, the group's view holds the voucher code to hand to a member.
        if !ch.code.is_empty() && self.codes.insert(id.to_string()) {
            println!(
                "[{0}] give this voucher code to a member of {0}: {1}",
                ch.name, ch.code
            );
        }
        // Read from the oldest line that can have changed: the first new one, or the first of
        // ours still unread. A member acknowledges what it read in the next message it sends.
        let shown = self.shown.get(id).copied();
        let unread = self.unread.entry(id.to_string()).or_default();
        let after = match unread.first() {
            Some(&first) => first.checked_sub(1),
            None => shown,
        };
        let Ok(lines) = c.lines(id, after).await else {
            return;
        };
        for l in lines {
            if shown.is_none_or(|s| l.line.id > s) {
                self.shown.insert(id.to_string(), l.line.id);
                println!("[{}] {}", ch.name, show(c, &l));
                if l.mine && !l.acked {
                    unread.insert(l.line.id);
                }
            } else if l.acked && unread.remove(&l.line.id) {
                println!("[{}] ✓✓ read: {}", ch.name, l.line.text);
            }
        }
    }
}

fn show(c: &Client, l: &LineView) -> String {
    if let Some(n) = &l.line.notice {
        return format!("— {}", plain(n));
    }
    let mark = if l.mine && l.acked { " ✓✓" } else { "" };
    let mut s = format!("{}{mark}: {}", l.from, l.line.text);
    if let Some(a) = l.line.attachment.as_ref().filter(|_| !l.mine) {
        s += &format!(" → {}", c.file_path(a).display());
    }
    s
}
