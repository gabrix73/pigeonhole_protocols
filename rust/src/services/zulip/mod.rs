//! A bridge between one katzenqt1 group and one Zulip stream. The bot is a member of the group,
//! through the [`Client`]; it posts what the group says to the stream and says in the group what
//! the stream's members write. Someone joins the group by contacting the bot through the service
//! directory and sending it the join code their chat app shows.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::protocols::katzenqt1::client::{Client, ClientError};
use crate::protocols::katzenqt1::engine::ChatId;
use crate::protocols::katzenqt1::member::Key;
use crate::services::eliza::{recv_text, text_boxes};
use crate::pigeonservice::{Error, Session};
use crate::transport::Backend;

/// Zulip's REST API, as a bot.
#[derive(Clone)]
pub struct Zulip {
    http: reqwest::Client,
    pub site: String,
    pub email: String,
    key: String,
}

/// An event queue registered with [`Zulip::register`].
pub struct Queue {
    pub id: String,
    pub last_event_id: i64,
}

/// A message read from the stream.
#[derive(Debug)]
pub struct Message {
    pub sender_email: String,
    pub sender_name: String,
    pub topic: String,
    pub content: String,
}

/// Where a bridge keeps the id of the last line it posted to Zulip.
const MARK: &str = "last-line";
/// Where a bridge keeps when it last read each member: a hex key and milliseconds per line.
const ACTIVE: &str = "active";
/// How long to wait after Zulip or the group fails before trying again.
const RETRY: Duration = Duration::from_secs(5);
/// How often idle members are looked for, at most.
const SWEEP: Duration = Duration::from_secs(3600);

impl Zulip {
    pub fn new(site: &str, email: &str, key: &str) -> Self {
        Zulip {
            http: reqwest::Client::new(),
            site: site.trim_end_matches('/').to_string(),
            email: email.into(),
            key: key.into(),
        }
    }

    /// Reads the `[api]` section of a zuliprc file: `email`, `key` and `site`.
    pub fn from_zuliprc(path: &Path) -> Result<Self, Error> {
        let text = std::fs::read_to_string(path)?;
        let get = |name: &str| {
            text.lines()
                .filter_map(|l| l.split_once('='))
                .find(|(k, _)| k.trim() == name)
                .map(|(_, v)| v.trim().to_string())
                .ok_or_else(|| Error::Other(format!("{}: no {name}", path.display())))
        };
        Ok(Zulip::new(&get("site")?, &get("email")?, &get("key")?))
    }

    async fn call(&self, post: bool, path: &str, form: &[(&str, String)]) -> Result<Value, Error> {
        let url = format!("{}/api/v1/{path}", self.site);
        let req = if post { self.http.post(&url).form(form) } else { self.http.get(&url).query(form) };
        let text = req
            .basic_auth(&self.email, Some(&self.key))
            .send()
            .await
            .map_err(|e| Error::Other(format!("zulip: {e}")))?
            .text()
            .await
            .map_err(|e| Error::Other(format!("zulip: {e}")))?;
        let v: Value = serde_json::from_str(&text).map_err(|e| Error::Decode(format!("zulip: {e}: {text}")))?;
        if v["result"] != "success" {
            return Err(Error::Other(format!("zulip {path}: {}", v["code"].as_str().or(v["msg"].as_str()).unwrap_or(&text))));
        }
        Ok(v)
    }

    /// Subscribes the bot to `stream`, which it must be to read it.
    pub async fn subscribe(&self, stream: &str) -> Result<(), Error> {
        self.call(true, "users/me/subscriptions", &[("subscriptions", json!([{ "name": stream }]).to_string())]).await?;
        Ok(())
    }

    pub async fn send(&self, stream: &str, topic: &str, content: &str) -> Result<(), Error> {
        let form = [("type", "stream".into()), ("to", stream.into()), ("topic", topic.into()), ("content", content.into())];
        self.call(true, "messages", &form).await?;
        Ok(())
    }

    /// Registers a queue of the messages in `stream`, with their content as written rather than
    /// rendered.
    pub async fn register(&self, stream: &str) -> Result<Queue, Error> {
        let form = [
            ("event_types", json!(["message"]).to_string()),
            ("narrow", json!([["stream", stream]]).to_string()),
            ("apply_markdown", "false".into()),
        ];
        let v = self.call(true, "register", &form).await?;
        Ok(Queue {
            id: v["queue_id"].as_str().ok_or_else(|| Error::Decode("zulip: no queue_id".into()))?.to_string(),
            last_event_id: v["last_event_id"].as_i64().unwrap_or(-1),
        })
    }

    /// Waits for the queue's next events and returns the messages among them. Zulip answers
    /// within about a minute, with a heartbeat if nothing was said. A queue Zulip has forgotten,
    /// as it does one unread for ten minutes, fails with `BAD_EVENT_QUEUE_ID`.
    pub async fn events(&self, q: &mut Queue) -> Result<Vec<Message>, Error> {
        let form = [("queue_id", q.id.clone()), ("last_event_id", q.last_event_id.to_string())];
        let v = self.call(false, "events", &form).await?;
        let mut out = Vec::new();
        for e in v["events"].as_array().into_iter().flatten() {
            q.last_event_id = q.last_event_id.max(e["id"].as_i64().unwrap_or(-1));
            let m = &e["message"];
            if e["type"] == "message" && m["type"] == "stream" {
                let s = |k: &str| m[k].as_str().unwrap_or_default().to_string();
                out.push(Message {
                    sender_email: s("sender_email"),
                    sender_name: s("sender_full_name"),
                    topic: s("subject"),
                    content: s("content"),
                });
            }
        }
        Ok(out)
    }
}

/// The bridge's end of things: its group, and the Zulip stream and topic.
pub struct Bridge {
    pub client: Arc<Client>,
    pub chat: ChatId,
    pub zulip: Zulip,
    pub stream: String,
    pub topic: String,
    /// Holds [`MARK`] and [`ACTIVE`].
    pub data_dir: PathBuf,
    /// A member nothing is read from for this long is dropped: see [`Bridge::sweep`].
    pub idle: Duration,
}

/// The bot's group called `name`: found, or founded.
pub async fn open_group(client: &Client, name: &str) -> Result<ChatId, ClientError> {
    match client.chats().await?.into_iter().find(|c| c.name == name) {
        Some(c) => Ok(c.id),
        None => client.create(name).await,
    }
}

impl Bridge {
    /// Posts each line said in the group to the stream, from where it left off; what was said
    /// before the bridge first ran stays in the group.
    pub async fn to_zulip(&self) -> Result<(), ClientError> {
        let mark = self.data_dir.join(MARK);
        let mut events = self.client.subscribe();
        let mut last = match std::fs::read_to_string(&mark).ok().and_then(|s| s.trim().parse().ok()) {
            Some(n) => n,
            None => self.client.lines(&self.chat, None).await?.last().map(|l| l.line.id).unwrap_or(0),
        };
        loop {
            for l in self.client.lines(&self.chat, Some(last)).await? {
                if !l.mine && l.line.notice.is_none() && !l.line.text.is_empty() {
                    let content = format!("**{}**: {}", l.from, l.line.text);
                    while let Err(e) = self.zulip.send(&self.stream, &self.topic, &content).await {
                        log::warn!("posting to zulip: {e}");
                        tokio::time::sleep(RETRY).await;
                    }
                }
                last = l.line.id;
                std::fs::write(&mark, last.to_string()).map_err(|e| ClientError::Store(e.to_string()))?;
            }
            match events.recv().await {
                Some(e) if e.error.is_some() => return Err(ClientError::Closed),
                Some(_) => {}
                None => return Ok(()),
            }
        }
    }

    /// Says in the group what others write in the stream's topic.
    pub async fn from_zulip(&self) -> Result<(), ClientError> {
        loop {
            let mut q = match self.zulip.register(&self.stream).await {
                Ok(q) => q,
                Err(e) => {
                    log::warn!("registering with zulip: {e}");
                    tokio::time::sleep(RETRY).await;
                    continue;
                }
            };
            loop {
                let msgs = match self.zulip.events(&mut q).await {
                    Ok(m) => m,
                    Err(e) => {
                        log::warn!("reading zulip events: {e}");
                        tokio::time::sleep(RETRY).await;
                        break;
                    }
                };
                for m in msgs {
                    if m.sender_email == self.zulip.email || m.topic != self.topic {
                        continue;
                    }
                    match self.client.send(&self.chat, &format!("{}: {}", m.sender_name, m.content)).await {
                        Ok(()) | Err(ClientError::EmptyMessage) => {}
                        Err(e) => return Err(e),
                    }
                }
            }
        }
    }

    /// Drops each member nothing was read from for `idle`, since they joined or last wrote: says
    /// so in the group, which they still read, then stops reading their stream. Writing is the
    /// only sign of life a member gives; one who only reads is dropped too, and rejoins through
    /// the bot. Keeps everyone else's last time in [`ACTIVE`], as lines expire.
    pub async fn sweep(&self) -> Result<(), ClientError> {
        let path = self.data_dir.join(ACTIVE);
        let mut active: HashMap<Key, i64> = std::fs::read_to_string(&path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_once(' '))
            .filter_map(|(k, t)| Some((hex::decode(k).ok()?, t.parse().ok()?)))
            .collect();
        for l in self.client.lines(&self.chat, None).await? {
            if l.line.notice.is_none() {
                let t = active.entry(l.line.sender).or_default();
                *t = (*t).max(l.line.time);
            }
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
        let members = self.client.chat(&self.chat).await?.members;
        active.retain(|k, _| members.iter().any(|m| &m.key == k));
        for m in members {
            if now - *active.entry(m.key.clone()).or_insert(now) < self.idle.as_millis() as i64 {
                continue;
            }
            let days = self.idle.as_secs() / 86400;
            let text = format!("{}: nothing was read from you for {days} days, so the bridge stops reading you. To rejoin, contact the bot again.", m.name);
            match self.client.send(&self.chat, &text).await {
                Ok(()) | Err(ClientError::EmptyMessage) => {}
                Err(e) => return Err(e),
            }
            self.client.remove(&self.chat, m.key.clone()).await?;
            active.remove(&m.key);
            log::info!("dropped {} after {days} days idle", m.name);
        }
        let text: String = active.iter().map(|(k, t)| format!("{} {t}\n", hex::encode(k))).collect();
        std::fs::write(&path, text).map_err(|e| ClientError::Store(e.to_string()))
    }

    /// Sweeps now and then.
    pub async fn expire(&self) -> Result<(), ClientError> {
        loop {
            self.sweep().await?;
            tokio::time::sleep(SWEEP.min(self.idle)).await;
        }
    }

    /// Talks with one client: tells it how to join, and invites each join code it sends.
    pub async fn join<B: Backend>(&self, session: Session<B>) {
        let Ok(max) = session.max_message().await else { return };
        let name = self.client.chat(&self.chat).await.map(|c| c.name).unwrap_or_default();
        let how = format!(
            "This bot bridges the group \"{name}\" with the Zulip stream \"{}\". To join: in your chat app, ask to join a group, and paste the voucher code it shows here.",
            self.stream
        );
        if !session.restored() && send(&session, &how, max).await.is_err() {
            return;
        }
        loop {
            let reply = match recv_text(&session).await {
                Ok(Some(code)) => match self.client.invite(&self.chat, code.trim()).await {
                    Ok(()) => "Inviting you; the group appears in your app once the invitation is read.".to_string(),
                    Err(ClientError::NotAVoucher) => format!("That is not a voucher code. {how}"),
                    Err(ClientError::AlreadyAdding) => "Someone else is being added; send your code again in a minute.".to_string(),
                    Err(e) => e.to_string(),
                },
                Ok(None) => continue,
                Err(Error::Decode(e)) => {
                    log::warn!("skipping a message that does not decode: {e}");
                    continue;
                }
                Err(e) => return log::warn!("a session ended: {e}"),
            };
            if send(&session, &reply, max).await.is_err() {
                return;
            }
        }
    }
}

async fn send<B: Backend>(session: &Session<B>, text: &str, max: usize) -> Result<(), Error> {
    for b in text_boxes(text, max) {
        session.send(&b).await?;
    }
    Ok(())
}
