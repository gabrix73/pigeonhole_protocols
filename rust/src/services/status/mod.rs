// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only
//! A status bot for the mixnet its client daemon is on. Each epoch it tells every conversation
//! it is in what changed in the PKI document, which pigeonhole services the directory lists and
//! whether each answered a probe, and how many routers it is itself linked with. `status` asks
//! for that at any time; anything else is answered by ELIZA, which it keeps as a joke. It is
//! reached only through the directory and a voucher router: it hands out no vouchers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_cbor::Value;
use tokio::sync::mpsc;

use crate::pigeonservice::wire::{ServiceDescriptor, ServiceId};
use crate::pigeonservice::{Directory, Error, Service, Session, dial};
use crate::services::eliza::{self, engine};
use crate::transport::Backend;

pub const GREETING: &str = "This is the status bot. Say status for the state of the mixnet; it also arrives on its own each epoch. Anything else, and Eliza answers.";

/// How long a probe waits for a service's reply through a router.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Directories larger than this are listed but not probed.
pub const PROBE_LIMIT: usize = 8;

/// What the report tracks of a PKI document: who is in it, by role.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub epoch: u64,
    /// Mix names by topology layer.
    pub layers: Vec<BTreeSet<String>>,
    pub gateways: BTreeSet<String>,
    /// Service node name to the capabilities it advertises.
    pub services: BTreeMap<String, BTreeSet<String>>,
    pub replicas: BTreeSet<String>,
}

fn text(k: &str) -> Value {
    Value::Text(k.into())
}

fn descriptor(v: &Value) -> Option<BTreeMap<Value, Value>> {
    match v {
        Value::Bytes(b) => serde_cbor::from_slice(b).ok(),
        Value::Map(m) => Some(m.clone()),
        _ => None,
    }
}

fn name_of(d: &BTreeMap<Value, Value>) -> Option<String> {
    match d.get(&text("Name")) {
        Some(Value::Text(n)) => Some(n.clone()),
        _ => None,
    }
}

fn names(doc: &BTreeMap<Value, Value>, key: &str) -> Vec<BTreeMap<Value, Value>> {
    match doc.get(&text(key)) {
        Some(Value::Array(a)) => a.iter().filter_map(descriptor).collect(),
        _ => Vec::new(),
    }
}

impl Summary {
    /// Reads a PKI document as the thin client hands it over.
    pub fn from_doc(doc: &BTreeMap<Value, Value>) -> Option<Summary> {
        let epoch = match doc.get(&text("Epoch")) {
            Some(Value::Integer(e)) => u64::try_from(*e).ok()?,
            _ => return None,
        };
        let layers = match doc.get(&text("Topology")) {
            Some(Value::Array(layers)) => layers
                .iter()
                .map(|l| match l {
                    Value::Array(nodes) => nodes
                        .iter()
                        .filter_map(descriptor)
                        .filter_map(|d| name_of(&d))
                        .collect(),
                    _ => BTreeSet::new(),
                })
                .collect(),
            _ => Vec::new(),
        };
        let services = names(doc, "ServiceNodes")
            .into_iter()
            .filter_map(|d| {
                let caps = match d.get(&text("Kaetzchen")) {
                    Some(Value::Map(k)) => k
                        .keys()
                        .filter_map(|c| {
                            if let Value::Text(c) = c {
                                Some(c.clone())
                            } else {
                                None
                            }
                        })
                        .collect(),
                    _ => BTreeSet::new(),
                };
                Some((name_of(&d)?, caps))
            })
            .collect();
        Some(Summary {
            epoch,
            layers,
            gateways: names(doc, "GatewayNodes")
                .iter()
                .filter_map(name_of)
                .collect(),
            services,
            replicas: names(doc, "StorageReplicas")
                .iter()
                .filter_map(name_of)
                .collect(),
        })
    }

    fn mixes(&self) -> BTreeSet<String> {
        self.layers.iter().flatten().cloned().collect()
    }
}

fn joined(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join(", ")
}

/// One line for a role: the count, the names, `detail`, and against `prev` who came and went.
fn role_line(
    role: &str,
    now: &BTreeSet<String>,
    detail: &str,
    prev: Option<&BTreeSet<String>>,
) -> String {
    let mut line = format!("{role}: {} ({}){detail}", now.len(), joined(now));
    if let Some(prev) = prev {
        let came: Vec<_> = now.difference(prev).cloned().collect();
        let went: Vec<_> = prev.difference(now).cloned().collect();
        if !came.is_empty() {
            line.push_str(&format!("; joined: {}", came.join(", ")));
        }
        if !went.is_empty() {
            line.push_str(&format!("; gone: {}", went.join(", ")));
        }
    }
    line
}

/// The document part of a report: the epoch and, per role, who is there and what changed
/// since `prev`.
pub fn changes(prev: Option<&Summary>, cur: &Summary) -> String {
    let mut out = vec![match prev {
        Some(p) if p.epoch + 1 != cur.epoch => format!("epoch {} (after {})", cur.epoch, p.epoch),
        _ => format!("epoch {}", cur.epoch),
    }];
    let mixes = cur.mixes();
    let mut line = role_line(
        "mixes",
        &mixes,
        &format!(" in {} layers", cur.layers.len()),
        prev.map(Summary::mixes).as_ref(),
    );
    if let Some(p) = prev
        && p.layers != cur.layers
        && p.mixes() == mixes
    {
        line.push_str("; the topology changed");
    }
    out.push(line);
    out.push(role_line(
        "gateways",
        &cur.gateways,
        "",
        prev.map(|p| &p.gateways),
    ));
    let names: BTreeSet<String> = cur.services.keys().cloned().collect();
    let mut line = role_line(
        "service nodes",
        &names,
        "",
        prev.map(|p| p.services.keys().cloned().collect()).as_ref(),
    );
    for (n, caps) in &cur.services {
        line.push_str(&format!("; {n}: {}", joined(caps)));
    }
    out.push(line);
    out.push(role_line(
        "replicas",
        &cur.replicas,
        "",
        prev.map(|p| &p.replicas),
    ));
    out.join("\n")
}

/// A directory entry and what its probe found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    pub id: ServiceId,
    pub routers: usize,
    /// None when not probed; else how long the service took to answer, if it did.
    pub answered: Option<Option<Duration>>,
}

/// The directory part of a report.
pub fn listing(entries: &[Listed], me: ServiceId) -> String {
    let mut out = vec![format!(
        "pigeonhole services in the directory: {}",
        entries.len()
    )];
    for e in entries {
        let id = hex::encode(&e.id.0[..4]);
        let routers = if e.routers == 1 {
            "1 router".into()
        } else {
            format!("{} routers", e.routers)
        };
        let probe = match e.answered {
            _ if e.id == me => ", this bot".into(),
            None => String::new(),
            Some(Some(t)) => format!(", answered in {}s", t.as_secs()),
            Some(None) => ", did not answer".into(),
        };
        out.push(format!("  {id}… {routers}{probe}"));
    }
    out.join("\n")
}

/// The bot's own standing: how many routers it can be reached through.
pub fn own_line(links: usize) -> String {
    match links {
        0 => "this bot: linked with no router; it cannot be reached until it is".into(),
        1 => "this bot: linked with 1 router".into(),
        n => format!("this bot: linked with {n} routers"),
    }
}

/// Whether a line asks for the report.
pub fn asks_status(text: &str) -> bool {
    let t = text
        .trim()
        .trim_end_matches(['?', '!', '.'])
        .to_ascii_lowercase();
    t == "status" || t == "/status"
}

/// The bot: the service, the conversations open with it, and the last report.
pub struct Bot<B: Backend> {
    pub svc: Service<B>,
    last: Mutex<Option<Summary>>,
    report: Mutex<Option<String>>,
    listeners: Mutex<Vec<mpsc::Sender<String>>>,
    probe_limit: usize,
}

impl<B: Backend + 'static> Bot<B> {
    pub fn new(svc: Service<B>, probe_limit: usize) -> Arc<Self> {
        Arc::new(Bot {
            svc,
            last: Mutex::new(None),
            report: Mutex::new(None),
            listeners: Mutex::new(Vec::new()),
            probe_limit,
        })
    }

    /// Lists the directory and probes each entry but this bot, up to the limit, through a
    /// router: a reply within [`PROBE_TIMEOUT`] means the service is up.
    pub async fn list(&self) -> Vec<Listed> {
        let ph = self.svc_ph();
        let poll = self.svc.poll_interval();
        let dirs = match Directory::all(ph.clone(), None, poll).await {
            Ok(d) => d,
            Err(e) => {
                log::warn!("directories: {e}");
                return Vec::new();
            }
        };
        let mut seen: BTreeMap<ServiceId, ServiceDescriptor> = BTreeMap::new();
        for d in dirs {
            match d.list().await {
                Ok(descs) => {
                    for s in descs {
                        seen.entry(s.id()).or_insert(s);
                    }
                }
                Err(e) => log::warn!("listing a directory: {e}"),
            }
        }
        let me = self.svc.id();
        let probe = seen.len() <= self.probe_limit;
        let mut tasks = Vec::new();
        for (id, d) in seen {
            let ph = ph.clone();
            tasks.push(tokio::spawn(async move {
                let answered = if !probe || id == me {
                    None
                } else {
                    let t0 = Instant::now();
                    let res =
                        tokio::time::timeout(PROBE_TIMEOUT, dial(ph, &d, "status bot", poll)).await;
                    Some(match res {
                        Ok(Ok(_conn)) => Some(t0.elapsed()),
                        Ok(Err(e)) => {
                            log::info!("probing {}: {e}", hex::encode(&id.0[..4]));
                            None
                        }
                        Err(_) => None,
                    })
                };
                Listed {
                    id,
                    routers: d.routers.len(),
                    answered,
                }
            }));
        }
        let mut out = Vec::new();
        for t in tasks {
            if let Ok(l) = t.await {
                out.push(l);
            }
        }
        out.sort_by_key(|l| l.id);
        out
    }

    fn svc_ph(&self) -> Arc<B> {
        self.svc.pigeonhole().clone()
    }

    /// Builds the report for `doc` and remembers it; the document part says what changed since
    /// the last one. That part is available to `status` at once; the directory part follows
    /// once the probes are in, which can take a while.
    pub async fn refresh(&self, doc: &BTreeMap<Value, Value>) -> Option<String> {
        let cur = Summary::from_doc(doc)?;
        let prev = self.last.lock().unwrap().clone();
        if prev.as_ref().is_some_and(|p| p.epoch == cur.epoch) {
            return None;
        }
        let document = changes(prev.as_ref(), &cur);
        *self.last.lock().unwrap() = Some(cur);
        let links = self.svc.descriptor().routers.len();
        *self.report.lock().unwrap() = Some(
            [
                document.clone(),
                "pigeonhole services in the directory: being probed".into(),
                own_line(links),
            ]
            .join("\n"),
        );
        let entries = self.list().await;
        let links = self.svc.descriptor().routers.len();
        let report = [document, listing(&entries, self.svc.id()), own_line(links)].join("\n");
        *self.report.lock().unwrap() = Some(report.clone());
        Some(report)
    }

    /// Sends `text` to every open conversation.
    pub fn broadcast(&self, text: &str) {
        let mut ls = self.listeners.lock().unwrap();
        ls.retain(|tx| tx.try_send(text.to_string()).is_ok());
    }

    /// Fetches the document with `doc` every `every`, and on a new epoch sends the report to
    /// every conversation.
    pub async fn watch<F, Fut>(self: Arc<Self>, doc: F, every: Duration)
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Option<BTreeMap<Value, Value>>>,
    {
        loop {
            if let Some(d) = doc().await
                && let Some(report) = self.refresh(&d).await
            {
                log::info!("new report:\n{report}");
                self.broadcast(&report);
            }
            tokio::time::sleep(every).await;
        }
    }

    /// Talks with one client until the conversation ends: the greeting, then the report on
    /// `status` and each new epoch, and Eliza for the rest.
    pub async fn chat(self: Arc<Self>, session: Session<B>) {
        let Ok(max) = session.max_message().await else {
            return;
        };
        if !session.restored() && send(&session, GREETING, max).await.is_err() {
            return;
        }
        let (tx, mut rx) = mpsc::channel(4);
        self.listeners.lock().unwrap().push(tx);
        let mut doctor = engine::Conversation::new();
        loop {
            let reply = tokio::select! {
                r = eliza::recv_text(&session) => match r {
                    Ok(Some(text)) if asks_status(&text) => {
                        self.report.lock().unwrap().clone().unwrap_or_else(|| "no PKI document yet".into())
                    }
                    Ok(Some(text)) => doctor.reply(&text),
                    Ok(None) => continue,
                    Err(Error::Decode(e)) => {
                        log::warn!("skipping a message that does not decode: {e}");
                        continue;
                    }
                    Err(e) => return log::warn!("a session ended: {e}"),
                },
                Some(report) = rx.recv() => report,
            };
            if send(&session, &reply, max).await.is_err() {
                return;
            }
        }
    }
}

async fn send<B: Backend>(session: &Session<B>, text: &str, max: usize) -> Result<(), Error> {
    for b in eliza::text_boxes(text, max) {
        session.send(&b).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, caps: &[&str]) -> Value {
        let mut m = BTreeMap::new();
        m.insert(text("Name"), text(name));
        if !caps.is_empty() {
            let k: BTreeMap<Value, Value> = caps
                .iter()
                .map(|c| (text(c), Value::Map(BTreeMap::new())))
                .collect();
            m.insert(text("Kaetzchen"), Value::Map(k));
        }
        Value::Bytes(serde_cbor::to_vec(&Value::Map(m)).unwrap())
    }

    fn doc(
        epoch: u64,
        layers: &[&[&str]],
        gateways: &[&str],
        services: &[(&str, &[&str])],
        replicas: &[&str],
    ) -> BTreeMap<Value, Value> {
        let mut d = BTreeMap::new();
        d.insert(text("Epoch"), Value::Integer(epoch as i128));
        d.insert(
            text("Topology"),
            Value::Array(
                layers
                    .iter()
                    .map(|l| Value::Array(l.iter().map(|n| node(n, &[])).collect()))
                    .collect(),
            ),
        );
        d.insert(
            text("GatewayNodes"),
            Value::Array(gateways.iter().map(|n| node(n, &[])).collect()),
        );
        d.insert(
            text("ServiceNodes"),
            Value::Array(services.iter().map(|(n, c)| node(n, c)).collect()),
        );
        d.insert(
            text("StorageReplicas"),
            Value::Array(replicas.iter().map(|n| node(n, &[])).collect()),
        );
        d
    }

    #[test]
    fn summary_reads_the_document() {
        let s = Summary::from_doc(&doc(
            7,
            &[&["m1", "m2"], &["m3"]],
            &["g1"],
            &[("s1", &["courier", "voucher_router"])],
            &["r1", "r2"],
        ))
        .unwrap();
        assert_eq!(s.epoch, 7);
        assert_eq!(s.layers.len(), 2);
        assert_eq!(s.mixes().len(), 3);
        assert_eq!(s.gateways.len(), 1);
        assert_eq!(s.services["s1"].len(), 2);
        assert_eq!(s.replicas.len(), 2);
        assert!(Summary::from_doc(&BTreeMap::new()).is_none());
    }

    #[test]
    fn changes_say_who_came_and_went() {
        let a = Summary::from_doc(&doc(
            7,
            &[&["m1", "m2"]],
            &["g1"],
            &[("s1", &["courier"])],
            &["r1"],
        ))
        .unwrap();
        let b = Summary::from_doc(&doc(
            8,
            &[&["m1", "m3"]],
            &["g1", "g2"],
            &[("s1", &["courier"])],
            &[],
        ))
        .unwrap();
        let first = changes(None, &a);
        assert!(first.starts_with("epoch 7\n"));
        assert!(!first.contains("joined") && !first.contains("gone"));
        let c = changes(Some(&a), &b);
        assert!(c.starts_with("epoch 8\n"));
        assert!(c.contains("mixes: 2 (m1, m3) in 1 layers; joined: m3; gone: m2"));
        assert!(c.contains("gateways: 2 (g1, g2); joined: g2"));
        assert!(c.contains("s1: courier"));
        assert!(c.contains("replicas: 0 (); gone: r1"));
        let skipped = changes(
            Some(&a),
            &Summary {
                epoch: 10,
                ..b.clone()
            },
        );
        assert!(skipped.starts_with("epoch 10 (after 7)\n"));
    }

    #[test]
    fn topology_change_without_membership_change_is_said() {
        let a = Summary::from_doc(&doc(1, &[&["m1", "m2"]], &[], &[], &[])).unwrap();
        let b = Summary::from_doc(&doc(2, &[&["m1"], &["m2"]], &[], &[], &[])).unwrap();
        assert!(changes(Some(&a), &b).contains("in 2 layers; the topology changed"));
    }

    #[test]
    fn listing_and_own_line() {
        let me = ServiceId::from_public_key(&[1u8; 32]);
        let other = ServiceId::from_public_key(&[2u8; 32]);
        let l = listing(
            &[
                Listed {
                    id: me,
                    routers: 1,
                    answered: None,
                },
                Listed {
                    id: other,
                    routers: 2,
                    answered: Some(Some(Duration::from_secs(95))),
                },
                Listed {
                    id: ServiceId::from_public_key(&[3u8; 32]),
                    routers: 0,
                    answered: Some(None),
                },
            ],
            me,
        );
        assert!(l.starts_with("pigeonhole services in the directory: 3\n"));
        assert!(l.contains("1 router, this bot"));
        assert!(l.contains("2 routers, answered in 95s"));
        assert!(l.contains("0 routers, did not answer"));
        assert!(own_line(0).contains("cannot be reached"));
        assert_eq!(own_line(2), "this bot: linked with 2 routers");
    }

    #[test]
    fn status_is_asked_for_in_a_few_ways() {
        assert!(asks_status("status"));
        assert!(asks_status(" Status? "));
        assert!(asks_status("/status"));
        assert!(!asks_status("what is the status of my therapy"));
    }
}
