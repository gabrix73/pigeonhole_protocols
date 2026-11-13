#![cfg(feature = "std")]

#![cfg(feature = "zulip")]
//! The Zulip bridge against a Zulip played by a small HTTP server, with a katzenqt1 member who
//! joins through the bot's voucher.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pigeonhole_protocols::protocols::katzenqt1::client::{self, Client};
use pigeonhole_protocols::services::status::join_group;
use pigeonhole_protocols::pigeonservice::testkit::*;
use pigeonhole_protocols::services::zulip::{Bridge, Zulip, open_group};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use pigeonhole_protocols::pigeonservice::{Config, Keypair, Service, route};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Notify;

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(60), f).await.expect("timed out")
}

async fn wait_for<F: Future<Output = bool>>(what: &str, mut f: impl FnMut() -> F) {
    tokio::time::timeout(Duration::from_secs(60), async {
        while !f().await {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

fn cfg(dir: &std::path::Path, name: &str) -> client::Config {
    client::Config {
        state_dir: dir.into(),
        name: name.into(),
        epoch_poll: Duration::from_millis(50),
        no_sync: true,
        key: None,
        wire_version: 4,
    }
}

/// What the fake Zulip saw and holds.
#[derive(Default)]
struct Fake {
    posts: Vec<(String, String, String)>,
    registers: usize,
    /// Fail the next events call as an expired queue.
    expire: bool,
    pending: Vec<Value>,
    next_id: i64,
}

struct Server {
    state: Arc<Mutex<Fake>>,
    wake: Arc<Notify>,
}

impl Server {
    fn push(&self, from: &str, email: &str, topic: &str, content: &str) {
        let mut s = self.state.lock().unwrap();
        s.next_id += 1;
        let id = s.next_id;
        s.pending.push(json!({"type": "message", "id": id, "message": {
            "type": "stream", "display_recipient": "general", "subject": topic,
            "sender_full_name": from, "sender_email": email, "content": content}}));
        self.wake.notify_one();
    }
}

fn form_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                out.push(u8::from_str_radix(&s[i + 1..i + 3], 16).unwrap());
                i += 2;
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

fn field(form: &str, name: &str) -> Option<String> {
    form.split('&').filter_map(|kv| kv.split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| form_decode(v))
}

/// Serves enough of Zulip's API for the bridge, on a port of its own.
async fn start_fake() -> (String, Server) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(Mutex::new(Fake::default()));
    let wake = Arc::new(Notify::new());
    let (st, wk) = (state.clone(), wake.clone());
    tokio::spawn(async move {
        loop {
            let (sock, _) = listener.accept().await.unwrap();
            let (st, wk) = (st.clone(), wk.clone());
            tokio::spawn(async move {
                let (r, mut w) = sock.into_split();
                let mut r = BufReader::new(r);
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let mut parts = line.split_whitespace();
                    let (method, target) = (parts.next().unwrap().to_string(), parts.next().unwrap().to_string());
                    let mut len = 0;
                    loop {
                        let mut h = String::new();
                        r.read_line(&mut h).await.unwrap();
                        if h.trim().is_empty() {
                            break;
                        }
                        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                            len = v.trim().parse().unwrap();
                        }
                    }
                    let mut body = vec![0; len];
                    r.read_exact(&mut body).await.unwrap();
                    let body = String::from_utf8(body).unwrap();
                    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
                    let form = if method == "GET" { query } else { &body };
                    let resp = match path {
                        "/api/v1/users/me/subscriptions" => json!({"result": "success"}),
                        "/api/v1/messages" => {
                            assert_eq!(field(form, "type").as_deref(), Some("stream"));
                            st.lock().unwrap().posts.push((
                                field(form, "to").unwrap(),
                                field(form, "topic").unwrap(),
                                field(form, "content").unwrap(),
                            ));
                            json!({"result": "success", "id": 1})
                        }
                        "/api/v1/register" => {
                            assert_eq!(field(form, "narrow").as_deref(), Some(r#"[["stream","general"]]"#));
                            assert_eq!(field(form, "apply_markdown").as_deref(), Some("false"));
                            let mut s = st.lock().unwrap();
                            s.registers += 1;
                            json!({"result": "success", "queue_id": format!("q{}", s.registers), "last_event_id": -1})
                        }
                        "/api/v1/events" => {
                            let expired = {
                                let mut s = st.lock().unwrap();
                                std::mem::take(&mut s.expire)
                            };
                            if expired {
                                json!({"result": "error", "code": "BAD_EVENT_QUEUE_ID", "msg": "Bad event queue ID"})
                            } else {
                                let events = loop {
                                    let pending = std::mem::take(&mut st.lock().unwrap().pending);
                                    if !pending.is_empty() {
                                        break pending;
                                    }
                                    if tokio::time::timeout(Duration::from_millis(300), wk.notified()).await.is_err() {
                                        let mut s = st.lock().unwrap();
                                        s.next_id += 1;
                                        break vec![json!({"type": "heartbeat", "id": s.next_id})];
                                    }
                                };
                                json!({"result": "success", "events": events})
                            }
                        }
                        p => panic!("unexpected request {method} {p}"),
                    }
                    .to_string();
                    let head = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", resp.len());
                    w.write_all(head.as_bytes()).await.unwrap();
                    w.write_all(resp.as_bytes()).await.unwrap();
                }
            });
        }
    });
    (url, Server { state, wake })
}

async fn said(c: &Client, chat: &str, text: &str) -> bool {
    c.lines(chat, None).await.unwrap().iter().any(|l| l.line.text == text)
}

#[tokio::test(flavor = "multi_thread")]
async fn group_and_stream_hear_each_other() {
    let net = world();
    let data = tempfile::tempdir().unwrap();
    let (url, fake) = start_fake().await;
    let zulip = Zulip::new(&url, "bot@localhost", "key");
    zulip.subscribe("general").await.unwrap();

    let bot = Arc::new(Client::open(cfg(&data.path().join("group"), "zulip"), net.clone()).await.unwrap());
    let chat = open_group(&bot, "general").await.unwrap();
    assert_eq!(open_group(&bot, "general").await.unwrap(), chat, "the group is found, not founded again");

    let mut cfg_svc = Config::new(Keypair::generate(&net).await.unwrap(), data.path().join("state"));
    cfg_svc.display_name = "zulip".into();
    cfg_svc.poll_interval = POLL;
    let svc = Service::new(cfg_svc, Arc::new(net.clone())).unwrap();
    let bridge = Arc::new(Bridge {
        client: bot.clone(),
        chat: chat.clone(),
        zulip,
        stream: "general".into(),
        topic: "pigeonhole".into(),
        data_dir: data.path().to_path_buf(),
        idle: Duration::from_secs(3600),
    });
    let (s, b) = (svc.clone(), bridge.clone());
    tokio::spawn(async move { b.admit(&s).await.unwrap() });
    let b = bridge.clone();
    tokio::spawn(async move { b.to_zulip().await.unwrap() });
    let b = bridge.clone();
    tokio::spawn(async move { b.from_zulip().await.unwrap() });

    // Alice asks to join a group, and routes the code her app shows to the bot.
    let alice_dir = tempfile::tempdir().unwrap();
    let alice = Client::open(cfg(alice_dir.path(), "alice"), net.clone()).await.unwrap();
    let ag = alice.join("general").await.unwrap();
    wait_for("alice's join code", || async { !alice.chat(&ag).await.unwrap().code.is_empty() }).await;
    let code = alice.chat(&ag).await.unwrap().code;

    let d = lookup_linked(&net, svc.id(), 2).await;
    within(route(&net, &d, &STANDARD.decode(&code).unwrap())).await.unwrap();
    wait_for("alice to join", || async { alice.chat(&ag).await.unwrap().joined }).await;

    // What the group says reaches the stream, once, with its sender.
    alice.send(&ag, "hello from pigeonhole").await.unwrap();
    wait_for("the post", || async { !fake.state.lock().unwrap().posts.is_empty() }).await;
    assert_eq!(
        fake.state.lock().unwrap().posts,
        vec![("general".to_string(), "pigeonhole".to_string(), "**alice**: hello from pigeonhole".to_string())]
    );
    let posted = bot.lines(&chat, None).await.unwrap().into_iter().find(|l| l.line.text == "hello from pigeonhole").unwrap().line.id;
    wait_for("the mark", || async { std::fs::read_to_string(data.path().join("last-line")).unwrap() == posted.to_string() }).await;

    // What the stream says reaches the group, but not the bot's own posts or other topics, and
    // the bridge carries on when Zulip forgets its queue.
    fake.push("Bob", "bob@localhost", "pigeonhole", "hello from zulip");
    wait_for("bob's message", || said(&alice, &ag, "Bob: hello from zulip")).await;
    fake.push("zulip", "bot@localhost", "pigeonhole", "**alice**: echo");
    fake.push("Carol", "carol@localhost", "elsewhere", "off topic");
    fake.state.lock().unwrap().expire = true;
    wait_for("a new queue", || async { fake.state.lock().unwrap().registers >= 2 }).await;
    fake.push("Carol", "carol@localhost", "pigeonhole", "after the queue expired");
    wait_for("carol's message", || said(&alice, &ag, "Carol: after the queue expired")).await;
    let texts: Vec<String> = alice.lines(&ag, None).await.unwrap().into_iter().map(|l| l.line.text).collect();
    assert!(!texts.iter().any(|t| t.contains("echo") || t.contains("off topic")), "{texts:?}");
    assert_eq!(fake.state.lock().unwrap().posts.len(), 1, "the bot's own lines are not posted back");

    // A member who wrote within the idle time stays; one who did not is told, then dropped.
    bridge.sweep().await.unwrap();
    assert_eq!(bot.chat(&chat).await.unwrap().members.len(), 1);
    let akey = hex::encode(bot.chat(&chat).await.unwrap().members[0].key.clone());
    assert!(std::fs::read_to_string(data.path().join("active")).unwrap().starts_with(&akey));
    let strict = Bridge { client: bot.clone(), chat: chat.clone(), zulip: bridge.zulip.clone(), stream: "general".into(), topic: "pigeonhole".into(), data_dir: data.path().to_path_buf(), idle: Duration::ZERO };
    strict.sweep().await.unwrap();
    assert!(bot.chat(&chat).await.unwrap().members.is_empty());
    assert_eq!(std::fs::read_to_string(data.path().join("active")).unwrap(), "");
    wait_for("the drop notice", || async { alice.lines(&ag, None).await.unwrap().iter().any(|l| l.line.text.starts_with("alice: nothing was read from you")) }).await;
    assert_eq!(fake.state.lock().unwrap().posts.len(), 1, "the drop notice is not posted");

    // Bob joins with the helper a bot uses.
    let bob_dir = tempfile::tempdir().unwrap();
    let bob = Client::open(cfg(bob_dir.path(), "bob"), net.clone()).await.unwrap();
    let bg = join_group(&bob, Arc::new(net.clone()), "general", svc.id(), POLL).await.unwrap();
    assert!(bob.chat(&bg).await.unwrap().joined);
    bob.close().await;

    svc.close().await;
    alice.close().await;
    bot.close().await;
}
