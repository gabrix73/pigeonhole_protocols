//! katzenqt's group chat trace format: call arguments read, and results and member state written,
//! as JSON. Bytes are hex; a map is a list of pairs in order. [`replay`] makes each recorded call
//! on a [`Group`] and requires the same result and state, and checks the trace's BACAP steps.

use indexmap::IndexMap;
use crate::protocols::katzenqt1::wire::{
    Ack, IntroAt, IntroRef, Introduction, JoinReply, Member, Number, RosterEntry,
};
use serde_json::{Value, json};

use crate::protocols::katzenqt1::member::*;

fn h(b: &[u8]) -> Value {
    Value::String(hex::encode(b))
}

/// Bytes as hex.
pub fn h_pub(b: &[u8]) -> Value {
    h(b)
}

fn oh(b: &Option<Vec<u8>>) -> Value {
    b.as_ref().map_or(Value::Null, |b| h(b))
}

fn n(x: impl Into<u64>) -> Value {
    json!(x.into())
}

fn nu(x: usize) -> Value {
    json!(x as u64)
}

fn on(x: Option<usize>) -> Value {
    x.map_or(Value::Null, nu)
}

fn pairs<K, V>(m: &IndexMap<K, V>, fk: impl Fn(&K) -> Value, fv: impl Fn(&V) -> Value) -> Value {
    Value::Array(m.iter().map(|(k, v)| json!([fk(k), fv(v)])).collect())
}

fn key(k: &Key) -> Value {
    h(k)
}

pub fn message(m: &Message) -> Value {
    json!({
        "content": oh(&m.content),
        "introduction": m.introduction.as_ref().map(|i| json!({"name": i.name, "read_cap": h(&i.read_cap)})),
        "numbers": m.numbers.iter().map(|x| json!([nu(x.index), oh(&x.prefix)])).collect::<Vec<_>>(),
        "introduced_at": m.introduced_at.as_ref().map(|r| json!([nu(r.introducer), h(&r.index)])),
        "acks": m.acks.iter().map(|a| json!([nu(a.member), n(a.idx64)])).collect::<Vec<_>>(),
        "membership_hash": oh(&m.membership_hash),
    })
}

pub fn payload(p: &Payload) -> Value {
    match p {
        Payload::Message(m) => message(m),
        Payload::Bytes(b) => json!({"bytes": h(b)}),
    }
}

pub fn join_reply(r: &JoinReply) -> Value {
    json!({
        "type": "JoinReply",
        "members": r.members.iter().map(|m| m.as_ref().map(|m| json!([h(&m.read_cap), h(&m.start)]))).collect::<Vec<_>>(),
        "rosters": r.rosters.iter().map(|ro| ro.as_ref().map(|ro| ro.iter().map(|e| json!([nu(e.index), on(e.place)])).collect::<Vec<_>>())).collect::<Vec<_>>(),
        "introductions": r.introductions.iter().map(|i| json!([nu(i.by), h(&i.index), nu(i.member)])).collect::<Vec<_>>(),
        "introducer": nu(r.introducer),
        "newcomer": nu(r.newcomer),
    })
}

pub fn effect(e: &Effect) -> Value {
    match e {
        Effect::WriteBox { index, payload: p } => {
            json!({"type": "WriteBox", "index": h(index), "payload": payload(p)})
        }
        Effect::WriteTombstone { index } => json!({"type": "WriteTombstone", "index": h(index)}),
        Effect::ReadBox {
            stream,
            read_cap,
            index,
            recheck,
        } => {
            json!({"type": "ReadBox", "stream": h(stream), "read_cap": h(read_cap), "index": h(index), "recheck": recheck})
        }
        Effect::DeriveIndexes {
            stream,
            start,
            count,
        } => {
            json!({"type": "DeriveIndexes", "stream": h(stream), "start": h(start), "count": nu(*count)})
        }
        Effect::Walk {
            stream,
            start,
            targets,
            keep,
        } => json!({"type": "Walk", "stream": h(stream), "start": h(start),
            "targets": targets.iter().map(|t| n(*t)).collect::<Vec<_>>(), "keep": nu(*keep)}),
        Effect::Deliver {
            sender,
            index,
            content,
        } => {
            json!({"type": "Deliver", "sender": h(sender), "index": h(index), "content": h(content)})
        }
        Effect::Expire { sender, index } => {
            json!({"type": "Expire", "sender": h(sender), "index": h(index)})
        }
        Effect::SendJoinReply { to, reply } => {
            json!({"type": "SendJoinReply", "to": h(to), "reply": join_reply(reply)})
        }
    }
}

pub fn effects(es: &[Effect]) -> Value {
    Value::Array(es.iter().map(effect).collect())
}

pub fn outgoing(o: &Outgoing) -> Value {
    json!({"type": "Outgoing", "token": nu(o.token), "message": message(&o.message)})
}

pub fn outgoings(os: &[Outgoing]) -> Value {
    Value::Array(os.iter().map(outgoing).collect())
}

fn mode(m: Mode) -> &'static str {
    match m {
        Mode::Idle => "idle",
        Mode::Reading => "reading",
        Mode::Scanning => "scanning",
    }
}

fn induction(i: Induction) -> &'static str {
    match i {
        Induction::Idle => "idle",
        Induction::CatchingUp => "catching up",
        Induction::Inducting => "inducting",
    }
}

fn at(a: &At) -> Value {
    json!([h(&a.introducer), h(&a.index)])
}

fn reader(r: &Reader) -> Value {
    json!({
        "stream": h(&r.stream), "read_cap": h(&r.read_cap), "next": h(&r.next), "last": oh(&r.last), "passed": nu(r.passed),
        "kept": r.kept.iter().map(|k| json!([h(&k.index), nu(k.passed), oh(&k.before)])).collect::<Vec<_>>(),
        "lost": r.lost.as_ref().map(|l| json!([nu(l.passed), oh(&l.before)])),
        "mode": mode(r.mode), "tried": r.tried.iter().map(|t| n(*t)).collect::<Vec<_>>(),
    })
}

pub fn retention(p: &Retention) -> Value {
    json!({"window": on(p.window), "discard_acked": p.discard_acked, "keep_sent": on(p.keep_sent), "keep_received": on(p.keep_received)})
}

/// A member's whole state.
pub fn group(g: &Group) -> Value {
    let r = &g.rosters;
    let l = &g.ledger;
    json!({
        "read_cap": h(&g.read_cap), "policy": retention(&g.policy), "recheck": nu(g.recheck),
        "rosters": {
            "entries": pairs(&r.entries, key, |ro| pairs(ro, |i| nu(*i), |e| json!({"key": oh(&e.key), "prefix": oh(&e.prefix)}))),
            "started": pairs(&r.started, key, |s| json!([h(&s.introducer), nu(s.top)])),
            "introductions": pairs(&r.introductions, at, key),
            "keys": r.keys.iter().map(|k| h(k)).collect::<Vec<_>>(),
        },
        "readers": pairs(&g.readers, key, reader),
        "sent": {
            "records": pairs(&g.sent.records, |k| n(*k), |r| json!({"index": h(&r.index), "plaintext": r.plaintext.as_ref().map(payload),
                "control": r.control, "written": nu(r.written), "settled": r.settled})),
            "backfilled": g.sent.backfilled.map_or(json!(-1), nu),
        },
        "ledger": {
            "published": pairs(&l.published, key, |i| h(i)), "acked_by": pairs(&l.acked_by, key, |x| n(*x)),
            "heard": pairs(&l.heard, key, |m| pairs(m, key, |x| n(*x))), "induction": induction(l.induction),
            "invitee": l.invitee.as_ref().map(|i| json!([i.name, h(&i.read_cap)])), "commit": l.commit,
            "starts": pairs(&l.starts, key, |i| h(i)),
        },
        "epoch": nu(g.epoch), "pool": g.pool.iter().map(|i| h(i)).collect::<Vec<_>>(), "tip": h(&g.tip), "deriving": g.deriving,
        "outbox": g.outbox.iter().map(|b| h(b)).collect::<Vec<_>>(),
        "pending": pairs(&g.pending, |t| nu(*t), |p| json!({
            "numbers": p.numbers.iter().map(|x| json!([nu(x.index), x.at.as_ref().map(at)])).collect::<Vec<_>>(),
            "introduced": oh(&p.introduced),
            "acks": pairs(&p.acks, key, |a| json!([oh(&a.before), h(&a.now)])),
            "control": p.control,
        })),
        "tokens": nu(g.tokens), "unnumbered": g.unnumbered.iter().map(at).collect::<Vec<_>>(),
        "introduced_at": g.introduced_at.as_ref().map(|r| json!({"introducer": nu(r.introducer), "index": h(&r.index)})),
        "joined_through": oh(&g.joined_through),
        "awaiting_start": pairs(&g.awaiting_start, key, |i| h(i)),
        "allocates": g.allocates,
        "received": pairs(&g.received, |r| json!([h(&r.sender), h(&r.index)]), |e| nu(*e)),
    })
}

fn read_result(r: &ReadResult) -> Value {
    match r {
        ReadResult::NotFound => json!("not found"),
        ReadResult::Tombstone => json!("tombstone"),
        ReadResult::Data(m) => json!({"data": m.as_ref().map(message)}),
    }
}

pub fn event(e: &Event) -> Value {
    let hs = |is: &[Index]| is.iter().map(|i| h(i)).collect::<Vec<_>>();
    match e {
        Event::Send { content } => json!({"type": "Send", "content": h(content)}),
        Event::Read { stream } => json!({"type": "Read", "stream": h(stream)}),
        Event::Scan { stream } => json!({"type": "Scan", "stream": h(stream)}),
        Event::BoxRead {
            stream,
            index,
            result,
            next,
        } => {
            json!({"type": "BoxRead", "stream": h(stream), "index": h(index), "result": read_result(result), "next_index": oh(next)})
        }
        Event::IndexesDerived { stream, indexes } => {
            json!({"type": "IndexesDerived", "stream": h(stream), "indexes": hs(indexes)})
        }
        Event::Walked {
            stream,
            target,
            skipped,
            steps,
        } => {
            json!({"type": "Walked", "stream": h(stream), "target": oh(target), "skipped": hs(skipped), "steps": nu(*steps)})
        }
        Event::Invite { name, read_cap } => {
            json!({"type": "Invite", "name": name, "read_cap": h(read_cap)})
        }
        Event::Introduce { name, read_cap } => {
            json!({"type": "Introduce", "name": name, "read_cap": h(read_cap)})
        }
        Event::Remove { member } => json!({"type": "Remove", "member": h(member)}),
        Event::EpochChanged { epoch } => json!({"type": "EpochChanged", "epoch": nu(*epoch)}),
    }
}

/// A call's arguments: the policy and recheck in force, and what the call takes.
pub fn args(g: &Group, more: Value) -> Value {
    let mut p = retention(&g.policy);
    p["type"] = json!("Retention");
    let mut a = json!({"policy": p, "recheck": nu(g.recheck)});
    if let Value::Object(m) = more {
        for (k, v) in m {
            a[k] = v;
        }
    }
    a
}

/// One trace line.
pub fn line(call: &str, me: &Key, name: &str, args: Value, result: Value, g: &Group) -> Value {
    json!({"call": call, "me": h(me), "member": name, "args": args, "result": result, "state": group(g)})
}

// Reading

type R<T> = Result<T, String>;

fn get<'a>(j: &'a Value, k: &str) -> R<&'a Value> {
    j.get(k).ok_or_else(|| format!("no field {k}"))
}

fn s(j: &Value) -> R<String> {
    j.as_str()
        .map(String::from)
        .ok_or_else(|| format!("not a string: {j}"))
}

fn b(j: &Value) -> R<Vec<u8>> {
    hex::decode(s(j)?).map_err(|e| e.to_string())
}

fn ob(j: &Value) -> R<Option<Vec<u8>>> {
    if j.is_null() {
        Ok(None)
    } else {
        b(j).map(Some)
    }
}

fn u(j: &Value) -> R<u64> {
    j.to_string()
        .parse()
        .map_err(|_| format!("not a natural number: {j}"))
}

fn us(j: &Value) -> R<usize> {
    u(j).map(|x| x as usize)
}

fn ous(j: &Value) -> R<Option<usize>> {
    if j.is_null() {
        Ok(None)
    } else {
        us(j).map(Some)
    }
}

fn arr(j: &Value) -> R<&Vec<Value>> {
    j.as_array().ok_or_else(|| format!("not a list: {j}"))
}

fn tup(j: &Value, len: usize) -> R<&Vec<Value>> {
    let a = arr(j)?;
    if a.len() != len {
        return Err(format!("not {len} items: {j}"));
    }
    Ok(a)
}

fn bo(j: &Value) -> R<bool> {
    j.as_bool().ok_or_else(|| format!("not a bool: {j}"))
}

pub fn read_message(j: &Value) -> R<Message> {
    let intro = get(j, "introduction")?;
    let ia = get(j, "introduced_at")?;
    Ok(Message {
        content: ob(get(j, "content")?)?,
        introduction: if intro.is_null() {
            None
        } else {
            Some(Introduction {
                name: s(get(intro, "name")?)?,
                read_cap: b(get(intro, "read_cap")?)?,
            })
        },
        numbers: arr(get(j, "numbers")?)?
            .iter()
            .map(|x| {
                let p = tup(x, 2)?;
                Ok(Number {
                    index: us(&p[0])?,
                    prefix: ob(&p[1])?,
                })
            })
            .collect::<R<_>>()?,
        introduced_at: if ia.is_null() {
            None
        } else {
            let p = tup(ia, 2)?;
            Some(IntroRef {
                introducer: us(&p[0])?,
                index: b(&p[1])?,
            })
        },
        acks: arr(get(j, "acks")?)?
            .iter()
            .map(|x| {
                let p = tup(x, 2)?;
                Ok(Ack {
                    member: us(&p[0])?,
                    idx64: u(&p[1])?,
                })
            })
            .collect::<R<_>>()?,
        membership_hash: ob(j.get("membership_hash").unwrap_or(&Value::Null))?,
    })
}

fn read_opt_message(j: &Value) -> R<Option<Message>> {
    if j.is_null() {
        Ok(None)
    } else {
        read_message(j).map(Some)
    }
}

pub fn read_payload(j: &Value) -> R<Payload> {
    match j.get("bytes") {
        Some(x) => Ok(Payload::Bytes(b(x)?)),
        None => Ok(Payload::Message(read_message(j)?)),
    }
}

pub fn read_join_reply(j: &Value) -> R<JoinReply> {
    Ok(JoinReply {
        members: arr(get(j, "members")?)?
            .iter()
            .map(|m| {
                if m.is_null() {
                    Ok(None)
                } else {
                    let p = tup(m, 2)?;
                    Ok(Some(Member {
                        read_cap: b(&p[0])?,
                        start: b(&p[1])?,
                    }))
                }
            })
            .collect::<R<_>>()?,
        rosters: arr(get(j, "rosters")?)?
            .iter()
            .map(|ro| {
                if ro.is_null() {
                    Ok(None)
                } else {
                    Ok(Some(
                        arr(ro)?
                            .iter()
                            .map(|e| {
                                let p = tup(e, 2)?;
                                Ok(RosterEntry {
                                    index: us(&p[0])?,
                                    place: ous(&p[1])?,
                                })
                            })
                            .collect::<R<_>>()?,
                    ))
                }
            })
            .collect::<R<_>>()?,
        introductions: arr(get(j, "introductions")?)?
            .iter()
            .map(|i| {
                let p = tup(i, 3)?;
                Ok(IntroAt {
                    by: us(&p[0])?,
                    index: b(&p[1])?,
                    member: us(&p[2])?,
                })
            })
            .collect::<R<_>>()?,
        introducer: us(get(j, "introducer")?)?,
        newcomer: us(get(j, "newcomer")?)?,
    })
}

pub fn read_retention(j: &Value) -> R<Retention> {
    Ok(Retention {
        window: ous(get(j, "window")?)?,
        discard_acked: bo(get(j, "discard_acked")?)?,
        keep_sent: ous(get(j, "keep_sent")?)?,
        keep_received: ous(get(j, "keep_received")?)?,
    })
}

fn read_result_j(j: &Value) -> R<ReadResult> {
    match j.as_str() {
        Some("not found") => Ok(ReadResult::NotFound),
        Some("tombstone") => Ok(ReadResult::Tombstone),
        _ => Ok(ReadResult::Data(read_opt_message(get(j, "data")?)?)),
    }
}

fn indexes(j: &Value) -> R<Vec<Index>> {
    arr(j)?.iter().map(b).collect()
}

pub fn read_event(j: &Value) -> R<Event> {
    let f = |k: &str| get(j, k);
    Ok(match s(f("type")?)?.as_str() {
        "Send" => Event::Send {
            content: b(f("content")?)?,
        },
        "Read" => Event::Read {
            stream: b(f("stream")?)?,
        },
        "Scan" => Event::Scan {
            stream: b(f("stream")?)?,
        },
        "BoxRead" => Event::BoxRead {
            stream: b(f("stream")?)?,
            index: b(f("index")?)?,
            result: read_result_j(f("result")?)?,
            next: ob(f("next_index")?)?,
        },
        "IndexesDerived" => Event::IndexesDerived {
            stream: b(f("stream")?)?,
            indexes: indexes(f("indexes")?)?,
        },
        "Walked" => Event::Walked {
            stream: b(f("stream")?)?,
            target: ob(f("target")?)?,
            skipped: indexes(f("skipped")?)?,
            steps: us(f("steps")?)?,
        },
        "Invite" => Event::Invite {
            name: s(f("name")?)?,
            read_cap: b(f("read_cap")?)?.into(),
        },
        "Introduce" => Event::Introduce {
            name: s(f("name")?)?,
            read_cap: b(f("read_cap")?)?.into(),
        },
        "Remove" => Event::Remove {
            member: b(f("member")?)?,
        },
        "EpochChanged" => Event::EpochChanged {
            epoch: us(f("epoch")?)?,
        },
        t => return Err(format!("unknown event {t}")),
    })
}

/// Where two values first differ, if they do. An object's missing field counts as null, as
/// Lean's replay reads it.
pub fn diff(path: &str, ours: &Value, theirs: &Value) -> Option<String> {
    match (ours, theirs) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a
                .keys()
                .chain(b.keys().filter(|k| !a.contains_key(*k)))
                .collect();
            keys.sort();
            keys.into_iter().find_map(|k| {
                diff(
                    &format!("{path}.{k}"),
                    a.get(k).unwrap_or(&Value::Null),
                    b.get(k).unwrap_or(&Value::Null),
                )
            })
        }
        (Value::Array(a), Value::Array(b)) => {
            if a.len() != b.len() {
                return Some(format!(
                    "{path}: {} items here, {} in the trace\n  here  {ours}\n  trace {theirs}",
                    a.len(),
                    b.len()
                ));
            }
            a.iter()
                .zip(b)
                .enumerate()
                .find_map(|(i, (x, y))| diff(&format!("{path}[{i}]"), x, y))
        }
        _ if ours == theirs => None,
        _ => Some(format!("{path}: here {ours}, in the trace {theirs}")),
    }
}

/// Make one recorded call on `g` (`None` before the member starts): what it returned, the effects
/// it asked for, and the member after.
pub fn call(g: Option<Group>, line: &Value) -> R<(Value, Vec<Effect>, Group)> {
    let a = get(line, "args")?;
    let arg = |k: &str| get(a, k);
    let policy = read_retention(arg("policy")?)?;
    let recheck = us(arg("recheck")?)?;
    let name = s(get(line, "call")?)?;
    let g = g.map(|mut g| {
        g.policy = policy.clone();
        g
    });
    match name.as_str() {
        "found" => {
            let founders: Vec<Vec<u8>> = arr(arg("founders")?)?.iter().map(b).collect::<R<_>>()?;
            return Ok((
                Value::Null,
                Vec::new(),
                Group::found(&b(arg("read_cap")?)?, &founders, policy, recheck),
            ));
        }
        "joined" => {
            return Ok((
                Value::Null,
                Vec::new(),
                Group::joined(
                    &b(arg("read_cap")?)?,
                    &read_join_reply(arg("reply")?)?,
                    policy,
                    recheck,
                ),
            ));
        }
        _ => {}
    }
    let mut g = g.ok_or_else(|| format!("{name} before the member started"))?;
    let result = match name.as_str() {
        "handle" => {
            let es = g.handle(read_event(arg("event")?)?);
            return Ok((effects(&es), es, g));
        }
        "observe" => {
            let es = g.observe(
                &b(arg("stream")?)?,
                &b(arg("index")?)?,
                read_opt_message(arg("message")?)?,
                &b(arg("next")?)?,
            );
            return Ok((effects(&es), es, g));
        }
        "compose" => outgoings(&g.compose(ob(arg("content")?)?)),
        "written" => {
            let p = arg("payload")?;
            g.written(
                us(arg("token")?)?,
                &b(arg("index")?)?,
                if p.is_null() {
                    None
                } else {
                    Some(read_payload(p)?)
                },
            );
            Value::Null
        }
        "abandoned" => {
            g.abandoned(us(arg("token")?)?);
            Value::Null
        }
        "begin_induction" => outgoings(&g.begin_induction()),
        "introduce_now" => outgoing(&g.introduce_now(&s(arg("name")?)?, &b(arg("read_cap")?)?)),
        "cancel_induction" => {
            g.cancel_induction();
            Value::Null
        }
        "reply" => join_reply(&g.reply(&b(arg("own_start")?)?)),
        "remove" => {
            g.remove(&b(arg("member")?)?);
            Value::Null
        }
        other => return Err(format!("unknown call {other}")),
    };
    Ok((result, Vec::new(), g))
}

#[derive(Default)]
struct Asked {
    derives: Vec<(Index, usize)>,
    walks: Vec<(Key, Index, Vec<u64>, usize)>,
}

fn step(i: &[u8]) -> Result<Index, String> {
    next_index(i).ok_or_else(|| "no index after".to_string())
}

fn check_bacap(asked: &mut Asked, line: &Value, es: &[Effect]) -> R<usize> {
    let a = get(line, "args")?;
    let mut checks = 0;
    match s(get(line, "call")?)?.as_str() {
        "handle" => match read_event(get(a, "event")?)? {
            Event::BoxRead {
                index,
                next: Some(next),
                ..
            } => {
                checks += 1;
                if step(&index)? != next {
                    return Err("the index after a box read is not BACAP's".into());
                }
            }
            Event::IndexesDerived { indexes, .. } => {
                if asked.derives.is_empty() {
                    return Err("indexes derived that were not asked for".into());
                }
                let (start, count) = asked.derives.remove(0);
                checks += 1;
                if derive_with(step, &start, count)? != indexes {
                    return Err("the indexes derived are not BACAP's".into());
                }
            }
            Event::Walked {
                stream,
                target,
                skipped,
                steps,
            } => {
                let i = asked
                    .walks
                    .iter()
                    .position(|w| w.0 == stream)
                    .ok_or("a walk that was not asked for")?;
                let (_, start, targets, keep) = asked.walks.remove(i);
                checks += 1;
                if start.len() != 104
                    || walk_with(step, &start, &targets, keep)? != (target, skipped, steps)
                {
                    return Err("the walk's result is not BACAP's".into());
                }
            }
            _ => {}
        },
        "observe" => {
            checks += 1;
            if step(&b(get(a, "index")?)?)? != b(get(a, "next")?)? {
                return Err("the index after an observed box is not BACAP's".into());
            }
        }
        _ => {}
    }
    for e in es {
        match e {
            Effect::DeriveIndexes { start, count, .. } => {
                asked.derives.push((start.clone(), *count))
            }
            Effect::Walk {
                stream,
                start,
                targets,
                keep,
            } => asked
                .walks
                .push((stream.clone(), start.clone(), targets.clone(), *keep)),
            _ => {}
        }
    }
    Ok(checks)
}

/// Replay one trace: the number of calls replayed and of BACAP checks made, or where it first
/// differs.
pub fn replay(text: &str) -> Result<(usize, usize), String> {
    let mut members: IndexMap<String, (Option<Group>, Asked)> = IndexMap::new();
    let (mut calls, mut checks) = (0, 0);
    for l in text.lines().filter(|l| !l.is_empty()) {
        calls += 1;
        let line: Value =
            serde_json::from_str(l).map_err(|e| format!("line {calls}: not JSON: {e}"))?;
        let me = line
            .get("me")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let who = line
            .get("member")
            .and_then(Value::as_str)
            .unwrap_or(&me)
            .to_string();
        let call_name = line
            .get("call")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();
        let fail = |e: String| format!("line {calls}: {who} {call_name}: {e}");
        let (g, asked) = members
            .entry(me)
            .or_insert_with(|| (None, Asked::default()));
        let (result, es, ng) = call(g.take(), &line).map_err(fail)?;
        if let Some(d) = diff(
            "result",
            &result,
            line.get("result").unwrap_or(&Value::Null),
        ) {
            return Err(fail(d));
        }
        if let Some(d) = diff(
            "state",
            &group(&ng),
            line.get("state").unwrap_or(&Value::Null),
        ) {
            return Err(fail(d));
        }
        checks += check_bacap(asked, &line, &es).map_err(fail)?;
        *g = Some(ng);
    }
    Ok((calls, checks))
}

// Reading a member's state back from what [`group`] writes, so that the state can be saved in
// this form.

fn each_pair(j: &Value, mut f: impl FnMut(&Value, &Value) -> R<()>) -> R<()> {
    for p in arr(j)? {
        let kv = tup(p, 2)?;
        f(&kv[0], &kv[1])?;
    }
    Ok(())
}

fn read_at(j: &Value) -> R<At> {
    let p = tup(j, 2)?;
    Ok(At {
        introducer: b(&p[0])?,
        index: b(&p[1])?,
    })
}

fn read_reader(j: &Value) -> R<Reader> {
    Ok(Reader {
        stream: b(get(j, "stream")?)?,
        read_cap: b(get(j, "read_cap")?)?.into(),
        next: b(get(j, "next")?)?,
        last: ob(get(j, "last")?)?,
        passed: us(get(j, "passed")?)?,
        kept: arr(get(j, "kept")?)?
            .iter()
            .map(|k| {
                let p = tup(k, 3)?;
                Ok(Kept {
                    index: b(&p[0])?,
                    passed: us(&p[1])?,
                    before: ob(&p[2])?,
                })
            })
            .collect::<R<_>>()?,
        lost: {
            let l = get(j, "lost")?;
            if l.is_null() {
                None
            } else {
                let p = tup(l, 2)?;
                Some(Lost {
                    passed: us(&p[0])?,
                    before: ob(&p[1])?,
                })
            }
        },
        mode: match s(get(j, "mode")?)?.as_str() {
            "reading" => Mode::Reading,
            "scanning" => Mode::Scanning,
            _ => Mode::Idle,
        },
        tried: arr(get(j, "tried")?)?.iter().map(u).collect::<R<_>>()?,
    })
}

fn index_pairs(j: &Value) -> R<IndexMap<Key, Index>> {
    let mut m = IndexMap::new();
    each_pair(j, |k, v| {
        m.insert(b(k)?, b(v)?);
        Ok(())
    })?;
    Ok(m)
}

fn nat_pairs(j: &Value) -> R<IndexMap<Key, u64>> {
    let mut m = IndexMap::new();
    each_pair(j, |k, v| {
        m.insert(b(k)?, u(v)?);
        Ok(())
    })?;
    Ok(m)
}

/// A member's state, as [`group`] writes it.
pub fn read_group(j: &Value) -> R<Group> {
    let r = get(j, "rosters")?;
    let mut rosters = Rosters::default();
    each_pair(get(r, "entries")?, |k, v| {
        let mut ro = Roster::new();
        each_pair(v, |i, e| {
            ro.insert(
                us(i)?,
                Entry {
                    key: ob(get(e, "key")?)?,
                    prefix: ob(get(e, "prefix")?)?,
                },
            );
            Ok(())
        })?;
        rosters.entries.insert(b(k)?, ro);
        Ok(())
    })?;
    each_pair(get(r, "started")?, |k, v| {
        let p = tup(v, 2)?;
        rosters.started.insert(
            b(k)?,
            Started {
                introducer: b(&p[0])?,
                top: us(&p[1])?,
            },
        );
        Ok(())
    })?;
    each_pair(get(r, "introductions")?, |k, v| {
        rosters.introductions.insert(read_at(k)?, b(v)?);
        Ok(())
    })?;
    rosters.keys = arr(get(r, "keys")?)?.iter().map(b).collect::<R<_>>()?;
    let sb = get(j, "sent")?;
    let mut sent = SentBox::default();
    each_pair(get(sb, "records")?, |k, v| {
        let p = get(v, "plaintext")?;
        sent.records.insert(
            u(k)?,
            Record {
                index: b(get(v, "index")?)?,
                plaintext: if p.is_null() {
                    None
                } else {
                    Some(read_payload(p)?)
                },
                control: bo(get(v, "control")?)?,
                written: us(get(v, "written")?)?,
                settled: bo(get(v, "settled")?)?,
            },
        );
        Ok(())
    })?;
    let bf = get(sb, "backfilled")?;
    sent.backfilled = if bf.as_i64() == Some(-1) {
        None
    } else {
        Some(us(bf)?)
    };
    let l = get(j, "ledger")?;
    let mut heard = IndexMap::new();
    each_pair(get(l, "heard")?, |k, v| {
        heard.insert(b(k)?, nat_pairs(v)?);
        Ok(())
    })?;
    let inv = get(l, "invitee")?;
    let ledger = Ledger {
        published: index_pairs(get(l, "published")?)?,
        acked_by: nat_pairs(get(l, "acked_by")?)?,
        heard,
        induction: match s(get(l, "induction")?)?.as_str() {
            "catching up" => Induction::CatchingUp,
            "inducting" => Induction::Inducting,
            _ => Induction::Idle,
        },
        invitee: if inv.is_null() {
            None
        } else {
            let p = tup(inv, 2)?;
            Some(Invitee {
                name: s(&p[0])?,
                read_cap: b(&p[1])?.into(),
            })
        },
        commit: bo(get(l, "commit")?)?,
        starts: index_pairs(get(l, "starts")?)?,
    };
    let mut readers = IndexMap::new();
    each_pair(get(j, "readers")?, |k, v| {
        readers.insert(b(k)?, read_reader(v)?);
        Ok(())
    })?;
    let mut pending = IndexMap::new();
    each_pair(get(j, "pending")?, |k, v| {
        let mut acks = IndexMap::new();
        each_pair(get(v, "acks")?, |sk, a| {
            let p = tup(a, 2)?;
            acks.insert(
                b(sk)?,
                AckedRun {
                    before: ob(&p[0])?,
                    now: b(&p[1])?,
                },
            );
            Ok(())
        })?;
        pending.insert(
            us(k)?,
            Pending {
                numbers: arr(get(v, "numbers")?)?
                    .iter()
                    .map(|x| {
                        let p = tup(x, 2)?;
                        Ok(NumberAt {
                            index: us(&p[0])?,
                            at: if p[1].is_null() {
                                None
                            } else {
                                Some(read_at(&p[1])?)
                            },
                        })
                    })
                    .collect::<R<_>>()?,
                introduced: ob(get(v, "introduced")?)?,
                acks,
                control: bo(get(v, "control")?)?,
            },
        );
        Ok(())
    })?;
    let ia = get(j, "introduced_at")?;
    let mut received = IndexMap::new();
    each_pair(get(j, "received")?, |k, v| {
        let p = tup(k, 2)?;
        received.insert(
            ReceivedAt {
                sender: b(&p[0])?,
                index: b(&p[1])?,
            },
            us(v)?,
        );
        Ok(())
    })?;
    Ok(Group {
        read_cap: b(get(j, "read_cap")?)?.into(),
        policy: read_retention(get(j, "policy")?)?,
        recheck: us(get(j, "recheck")?)?,
        rosters,
        readers,
        sent,
        ledger,
        epoch: us(get(j, "epoch")?)?,
        pool: indexes(get(j, "pool")?)?,
        tip: b(get(j, "tip")?)?,
        deriving: bo(get(j, "deriving")?)?,
        outbox: arr(get(j, "outbox")?)?.iter().map(b).collect::<R<_>>()?,
        pending,
        tokens: us(get(j, "tokens")?)?,
        unnumbered: arr(get(j, "unnumbered")?)?
            .iter()
            .map(read_at)
            .collect::<R<_>>()?,
        introduced_at: if ia.is_null() {
            None
        } else {
            Some(IntroRef {
                introducer: us(get(ia, "introducer")?)?,
                index: b(get(ia, "index")?)?,
            })
        },
        joined_through: ob(get(j, "joined_through")?)?,
        awaiting_start: index_pairs(get(j, "awaiting_start")?)?,
        allocates: j.get("allocates").and_then(Value::as_bool).unwrap_or(true),
        received,
    })
}
