//! Local durable dispatch: a trusted, allow-listed `request` starts your
//! handler, and its one result goes back as a correlated `finding` or
//! `proposal`. Agent launch, credentials, and permissions live in the handler.
use crate::{
    client::{self, Stored},
    envelope,
    identity::{self, Identity},
    local,
};
use clap::Subcommand;
use handler::{Handler, ResultMessage};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
mod handler;

const MAX_ATTEMPTS: i64 = 4;
const MAX_REQUEST_TEXT_BYTES: usize = 64 * 1024;
/// Text of earlier messages a handler sees alongside a request, by default.
const DEFAULT_CONTEXT_BYTES: u32 = 24 * 1024;
const MAX_CONTEXT_BYTES: u32 = 1024 * 1024;
fn default_context_bytes() -> u32 {
    DEFAULT_CONTEXT_BYTES
}
const SQLITE_SCHEMA: &str = "
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO state VALUES ('cursor','0');
CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'received',
  attempts INTEGER NOT NULL DEFAULT 0,
  result TEXT,
  next_at INTEGER NOT NULL DEFAULT 0
);";
/// Jobs ready to run: new, or retrying and past their backoff.
const SQLITE_READY: &str = "SELECT payload,result,attempts FROM jobs
     WHERE status IN ('received','retrying') AND next_at<=unixepoch() ORDER BY rowid LIMIT 20";

#[derive(Subcommand)]
pub enum DispatcherCmd {
    /// Trust the allowed senders and save the handler configuration
    Configure {
        /// Senders whose requests start the handler (same relay as you)
        #[arg(long, required = true)]
        allow: Vec<String>,
        /// Absolute directory the handler runs in
        #[arg(long)]
        workdir: PathBuf,
        /// Absolute path of the handler executable
        #[arg(long)]
        handler: PathBuf,
        #[arg(long)]
        handler_arg: Vec<String>,
        /// Environment variable names passed through to the handler
        #[arg(long)]
        handler_env: Vec<String>,
        /// Seconds one handler run may take
        #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u32).range(1..=86400))]
        timeout_seconds: u32,
        /// Bytes of earlier messages passed to the handler with each request
        #[arg(long, default_value_t = DEFAULT_CONTEXT_BYTES, value_parser = clap::value_parser!(u32).range(1..=MAX_CONTEXT_BYTES as i64))]
        thread_context_bytes: u32,
        /// Requests per conversation before follow-ups stop
        #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u32).range(1..=32))]
        max_thread_requests: u32,
        /// Conversation age in seconds after which follow-ups stop
        #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(u32).range(1..=86400))]
        thread_ttl_seconds: u32,
    },
    /// Poll the inbox and run the handler; --once does a single pass
    Run {
        #[arg(long)]
        once: bool,
    },
    /// Show the configuration and job counts
    Status,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    allow: Vec<String>,
    work_dir: PathBuf,
    handler: Handler,
    timeout_seconds: u32,
    /// Added after the first release; older files load with the default.
    #[serde(default = "default_context_bytes")]
    context_bytes: u32,
    max_thread_requests: u32,
    thread_ttl_seconds: u32,
}

fn config_path(home: &Path) -> PathBuf {
    home.join("dispatcher.json")
}
fn config(home: &Path) -> Result<Config, String> {
    let path = config_path(home);
    if !path.exists() {
        return Err("dispatcher is not configured; run ecco dispatcher configure".into());
    }
    let cfg: Config = serde_json::from_str(&local::read(&path, 65536)?)
        .map_err(|e| format!("invalid dispatcher config: {e}"))?;
    validate(home, &cfg)?;
    Ok(cfg)
}
fn validate(home: &Path, cfg: &Config) -> Result<(), String> {
    let authority = identity::authority(&Identity::load(home)?.relay);
    if cfg.allow.is_empty()
        || cfg.allow.iter().any(|a| {
            a.rsplit_once('@')
                .is_none_or(|(name, relay)| name.is_empty() || relay != authority)
        })
    {
        return Err("dispatcher needs same-relay --allow addresses".into());
    }
    if !cfg.work_dir.is_absolute() || !cfg.work_dir.is_dir() || cfg.work_dir.parent().is_none() {
        return Err("--workdir must be an existing absolute directory other than /".into());
    }
    if !(1..=86400).contains(&cfg.timeout_seconds)
        || !(1..=MAX_CONTEXT_BYTES).contains(&cfg.context_bytes)
        || !(1..=32).contains(&cfg.max_thread_requests)
        || !(1..=86400).contains(&cfg.thread_ttl_seconds)
    {
        return Err("invalid dispatcher limits".into());
    }
    cfg.handler.validate()
}

pub fn command(home: &Path, cmd: DispatcherCmd) -> Result<(), String> {
    match cmd {
        DispatcherCmd::Configure {
            allow,
            workdir,
            handler,
            handler_arg,
            handler_env,
            timeout_seconds,
            thread_context_bytes,
            max_thread_requests,
            thread_ttl_seconds,
        } => {
            let cfg = Config {
                allow,
                work_dir: workdir,
                handler: Handler {
                    executable: handler.to_string_lossy().into_owned(),
                    args: handler_arg,
                    env: handler_env,
                },
                timeout_seconds,
                context_bytes: thread_context_bytes,
                max_thread_requests,
                thread_ttl_seconds,
            };
            validate(home, &cfg)?;
            for addr in &cfg.allow {
                identity::contacts_set(home, addr, "approved")?;
            }
            local::write(
                &config_path(home),
                serde_json::to_string_pretty(&cfg).unwrap().as_bytes(),
            )?;
            println!(
                "dispatcher configured for {}; start it with ecco dispatcher run",
                cfg.allow.join(", ")
            );
            Ok(())
        }
        DispatcherCmd::Run { once } => run(home, once),
        DispatcherCmd::Status => {
            let cfg = config(home)?;
            println!("handler: {}", cfg.handler.executable);
            println!("allow:   {}", cfg.allow.join(", "));
            let db = database(home)?;
            let mut rows = db
                .prepare("SELECT status,count(*) FROM jobs GROUP BY status ORDER BY status")
                .map_err(|e| e.to_string())?;
            let counts = rows
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            for (status, count) in counts {
                println!("{status}: {count}");
            }
            Ok(())
        }
    }
}

fn database(home: &Path) -> Result<Connection, String> {
    let path = home.join("dispatcher.sqlite");
    let db = Connection::open(&path).map_err(|e| e.to_string())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    db.busy_timeout(Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    db.execute_batch(SQLITE_SCHEMA).map_err(|e| e.to_string())?;
    Ok(db)
}
fn cursor(db: &Connection) -> Result<u64, String> {
    db.query_row("SELECT value FROM state WHERE key='cursor'", [], |r| {
        r.get::<_, String>(0)
    })
    .map_err(|e| e.to_string())?
    .parse()
    .map_err(|e: std::num::ParseIntError| e.to_string())
}

/// The request text as the handler will see it: decrypted when sealed to us.
fn request_text(id: &Identity, env: &envelope::Envelope) -> Option<String> {
    let body = if envelope::is_encrypted(&env.body) {
        envelope::open_body(&env.body, &id.addr(), &id.root_key())?
    } else {
        env.body.clone()
    };
    let text = body.get("text")?.as_str()?;
    (!text.is_empty() && text.len() <= MAX_REQUEST_TEXT_BYTES).then(|| text.to_owned())
}

/// Record allow-listed requests as jobs and advance the cursor in one
/// transaction, so a crash never skips or double-counts a request.
fn ingest(
    db: &mut Connection,
    home: &Path,
    id: &Identity,
    cfg: &Config,
    messages: Vec<Stored>,
    next: u64,
) -> Result<(), String> {
    let (visible, _, _) = crate::agent_surface::partition(home, id, messages);
    let tx = db.transaction().map_err(|e| e.to_string())?;
    for stored in visible {
        let env = &stored.env;
        if env.kind != "request" || !env.to.contains(&id.addr()) || !cfg.allow.contains(&env.from) {
            continue;
        }
        // A request sealed to someone else cannot be handled automatically.
        let status = if request_text(id, env).is_some() {
            "received"
        } else if envelope::is_encrypted(&env.body) {
            "needs-human"
        } else {
            continue;
        };
        tx.execute(
            "INSERT OR IGNORE INTO jobs(id,payload,status) VALUES (?,?,?)",
            rusqlite::params![env.id, serde_json::to_string(&stored).unwrap(), status],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.execute(
        "UPDATE state SET value=? WHERE key='cursor'",
        [next.to_string()],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}

/// The message this one answers, read from the body we can see (an encrypted
/// body keeps `in_reply_to` inside the ciphertext).
fn in_reply_to(id: &Identity, stored: &Stored) -> Option<String> {
    let (body, _) = crate::agent_surface::resolved_body(id, stored);
    body["in_reply_to"].as_str().map(str::to_owned)
}

/// The conversation before `request`, as the handler sees it: the request's
/// reply chain first, then the newest other messages, whole messages only,
/// until `budget` bytes of text are spent. Trusted senders only, oldest
/// first, decrypted where sealed to us.
fn context(
    home: &Path,
    id: &Identity,
    thread: &[Stored],
    request: &Stored,
    budget: usize,
) -> Vec<Value> {
    let (visible, _, _) = crate::agent_surface::partition(home, id, thread.to_vec());
    let by_id: BTreeMap<&str, &Stored> = visible.iter().map(|s| (s.env.id.as_str(), s)).collect();
    let mut chain: Vec<&Stored> = Vec::new();
    let mut parent = in_reply_to(id, request);
    while let Some(found) = parent.as_deref().and_then(|p| by_id.get(p)) {
        if chain.iter().any(|c| c.env.id == found.env.id) {
            break;
        }
        chain.push(found);
        parent = in_reply_to(id, found);
    }
    let mut recent: Vec<&Stored> = visible
        .iter()
        .filter(|s| s.tseq < request.tseq && !chain.iter().any(|c| c.env.id == s.env.id))
        .collect();
    recent.sort_by_key(|s| std::cmp::Reverse(s.tseq));
    let mut chosen: Vec<(u64, Value)> = Vec::new();
    let mut spent = 0;
    for s in chain.into_iter().chain(recent) {
        let (body, _) = crate::agent_surface::resolved_body(id, s);
        let text = body["text"].clone();
        spent += text.as_str().map_or(0, str::len);
        if spent > budget {
            break;
        }
        chosen.push((
            s.tseq,
            json!({ "id": s.env.id, "from": s.env.from, "kind": s.env.kind, "text": text }),
        ));
    }
    chosen.sort_by_key(|(tseq, _)| *tseq);
    chosen.into_iter().map(|(_, m)| m).collect()
}

/// Our reply (or, with `follow`, our follow-up request) to `request`, if sent.
fn correlated<'a>(
    id: &Identity,
    thread: &'a [Stored],
    request: &str,
    follow: bool,
) -> Option<&'a Stored> {
    let self_addr = id.addr();
    thread.iter().find(|s| {
        s.env.from == self_addr
            && in_reply_to(id, s).as_deref() == Some(request)
            && if follow {
                s.env.kind == "request"
            } else {
                ["finding", "proposal"].contains(&s.env.kind.as_str())
            }
    })
}

/// A follow-up is allowed while the reply chain stays between the two
/// parties, is complete, and is within the configured count and age.
fn follow_allowed(
    thread: &[Stored],
    request: &Stored,
    id: &Identity,
    cfg: &Config,
    now: u64,
) -> bool {
    let by_id: BTreeMap<_, _> = thread.iter().map(|s| (s.env.id.as_str(), s)).collect();
    let mut current = Some(request);
    let mut seen = BTreeSet::new();
    let mut count = 0;
    let mut first = u64::MAX;
    while let Some(stored) = current {
        let env = &stored.env;
        if !seen.insert(&env.id)
            || !((env.from == id.addr() && env.to.contains(&request.env.from))
                || (env.from == request.env.from && env.to.contains(&id.addr())))
        {
            return false;
        }
        if env.kind == "request" {
            count += 1;
            first = first.min(stored.received_at);
        }
        current = match env.body["in_reply_to"].as_str() {
            Some(parent) => match by_id.get(parent) {
                Some(s) => Some(*s),
                None => return false,
            },
            None => None,
        };
    }
    count > 0
        && count < cfg.max_thread_requests
        && now < first.saturating_add(cfg.thread_ttl_seconds as u64)
}

/// A correlated send that mirrors the request's encryption. The reply is
/// idempotent per request (main.rs `automatic_idempotency_key`).
fn send(
    home: &Path,
    id: &Identity,
    request: &Stored,
    kind: &str,
    text: &str,
) -> Result<(), String> {
    let env = crate::prepare_envelope(
        home,
        id,
        crate::SendInput {
            about: request.env.about.clone(),
            kind: kind.into(),
            body: crate::message_body(text.into(), Some(request.env.id.clone())),
            to: vec![request.env.from.clone()],
            encrypt: envelope::is_encrypted(&request.env.body),
        },
        None,
    )?;
    client::send(id, &env).map(|_| ())
}

fn execute(
    db: &Connection,
    home: &Path,
    id: &Identity,
    cfg: &Config,
    request: &Stored,
    saved: Option<&str>,
) -> Result<&'static str, String> {
    if !cfg.allow.contains(&request.env.from)
        || identity::standing(
            &identity::contacts_load(home),
            &id.addr(),
            &request.env.from,
        ) != identity::Standing::Trusted
    {
        return Err("request sender is no longer trusted and allowed".into());
    }
    let thread = client::thread(id, &request.env.about, 0, 0)?;
    let replied = correlated(id, &thread, &request.env.id, false).is_some();
    if replied && saved.is_none() {
        return Ok("completed");
    }
    let result = if let Some(saved) = saved {
        ResultMessage::decode(serde_json::from_str(saved).map_err(|e| e.to_string())?)?
    } else {
        let text = request_text(id, &request.env).ok_or("request has no usable text")?;
        let input = json!({
            "schema": crate::wire::DISPATCH,
            "type": "request",
            "envelope": {
                "id": request.env.id,
                "from": request.env.from,
                "about": request.env.about,
                "text": text,
            },
            "thread": context(home, id, &thread, request, cfg.context_bytes as usize),
        });
        let result = cfg.handler.run(
            &cfg.work_dir,
            &input,
            Duration::from_secs(cfg.timeout_seconds as u64),
        )?;
        db.execute(
            "UPDATE jobs SET result=? WHERE id=?",
            rusqlite::params![serde_json::to_string(&result).unwrap(), request.env.id],
        )
        .map_err(|e| e.to_string())?;
        result
    };
    if !replied {
        send(home, id, request, &result.kind, &result.text)?;
    }
    if let Some(text) = &result.follow_up {
        if correlated(id, &thread, &request.env.id, true).is_none()
            && follow_allowed(&thread, request, id, cfg, envelope::now())
        {
            send(home, id, request, "request", text)?;
        }
    }
    Ok(if result.kind == "proposal" {
        "needs-human"
    } else {
        "completed"
    })
}

fn process_ready(
    db: &mut Connection,
    home: &Path,
    id: &Identity,
    cfg: &Config,
) -> Result<(), String> {
    let jobs: Vec<(String, Option<String>, i64)> = db
        .prepare(SQLITE_READY)
        .map_err(|e| e.to_string())?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    for (payload, saved, attempts) in jobs {
        if local::cancelled() {
            break;
        }
        let request: Stored = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
        let attempt = attempts + 1;
        db.execute(
            "UPDATE jobs SET status='running',attempts=? WHERE id=?",
            rusqlite::params![attempt, request.env.id],
        )
        .map_err(|e| e.to_string())?;
        let (status, delay) = match execute(db, home, id, cfg, &request, saved.as_deref()) {
            Ok(status) => (status, 0),
            Err(e) => {
                eprintln!("dispatcher request {}: {e}", request.env.id);
                if attempt >= MAX_ATTEMPTS {
                    ("failed", 0)
                } else {
                    ("retrying", 2i64 << attempt)
                }
            }
        };
        db.execute(
            "UPDATE jobs SET status=?,next_at=unixepoch()+? WHERE id=?",
            rusqlite::params![status, delay, request.env.id],
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn run(home: &Path, once: bool) -> Result<(), String> {
    let cfg = config(home)?;
    let id = Identity::load(home)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(home.join("dispatcher.lock"))
        .map_err(|e| e.to_string())?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("another dispatcher owns this identity".into());
    }
    local::install_signals();
    let mut db = database(home)?;
    // Jobs left running by a previous process are retried; a saved result is reused.
    db.execute(
        "UPDATE jobs SET status='retrying',next_at=0 WHERE status='running'",
        [],
    )
    .map_err(|e| e.to_string())?;
    loop {
        if local::cancelled() {
            return Ok(());
        }
        let step = cursor(&db).and_then(|cursor| {
            let (messages, until) = client::inbox(&id, cursor, if once { 0 } else { 20 })?;
            ingest(&mut db, home, &id, &cfg, messages, until)?;
            process_ready(&mut db, home, &id, &cfg)
        });
        match step {
            Ok(()) if once => return Ok(()),
            Ok(()) => {}
            Err(e) if once => return Err(e),
            Err(e) => {
                eprintln!("dispatcher retry: {e}");
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(home: &Path, peer: &str) -> Config {
        Config {
            allow: vec![peer.into()],
            work_dir: home.to_path_buf(),
            handler: Handler {
                executable: "/bin/true".into(),
                args: vec![],
                env: vec![],
            },
            timeout_seconds: 900,
            context_bytes: DEFAULT_CONTEXT_BYTES,
            max_thread_requests: 8,
            thread_ttl_seconds: 3600,
        }
    }
    fn home(tag: &str) -> (PathBuf, Identity) {
        let home =
            std::env::temp_dir().join(format!("ecco-dispatch-{tag}-{}", rand::random::<u64>()));
        let id = Identity::generate("me", "https://relay.test", None);
        id.save(&home).unwrap();
        identity::contacts_set(&home, "peer@relay.test", "approved").unwrap();
        (home, id)
    }
    fn request(id: &Identity, from: &str, n: u64, body: serde_json::Value) -> Stored {
        Stored {
            gseq: n,
            tseq: n,
            received_at: 100,
            env: envelope::Envelope::seal(
                "topic".into(),
                body,
                from.into(),
                "request".into(),
                vec![],
                vec![id.addr()],
                100,
                &id.agent_key(),
            ),
        }
    }

    #[test]
    fn configuration_is_validated_against_the_identity_and_filesystem() {
        let (home, _) = home("validate");
        let good = config(&home, "peer@relay.test");
        validate(&home, &good).unwrap();
        let foreign = Config {
            allow: vec!["peer@other.test".into()],
            ..good.clone()
        };
        assert!(validate(&home, &foreign).is_err());
        let relative = Config {
            work_dir: PathBuf::from("repo"),
            ..good.clone()
        };
        assert!(validate(&home, &relative).is_err());
        let root = Config {
            work_dir: PathBuf::from("/"),
            ..good.clone()
        };
        assert!(validate(&home, &root).is_err());
        let limits = Config {
            timeout_seconds: 0,
            ..good.clone()
        };
        assert!(validate(&home, &limits).is_err());
        assert!(serde_json::from_str::<Config>(r#"{"allow":[],"extra":1}"#).is_err());
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn handler_context_is_the_reply_chain_then_recent_messages_within_the_budget() {
        let (home, id) = home("context");
        let peer = "peer@relay.test";
        let make = |from: &str, kind: &str, text: &str, parent: Option<&str>, n: u64| Stored {
            gseq: n,
            tseq: n,
            received_at: n,
            env: envelope::Envelope::seal(
                "topic".into(),
                crate::message_body(text.into(), parent.map(str::to_string)),
                from.into(),
                kind.into(),
                vec![],
                vec![id.addr()],
                n,
                &id.agent_key(),
            ),
        };
        let texts = |messages: &[Value]| -> Vec<String> {
            messages
                .iter()
                .map(|m| m["text"].as_str().unwrap().to_string())
                .collect()
        };
        // A conversation: request, answer, follow-up; a stranger's note; unrelated chatter; a sealed note.
        let first = make(peer, "request", "first", None, 1);
        let answer = make(&id.addr(), "finding", "answer", Some(&first.env.id), 2);
        let stranger = make("stranger@relay.test", "note", "held", None, 3);
        let sealed = Stored {
            gseq: 4,
            tseq: 4,
            received_at: 4,
            env: envelope::Envelope::seal(
                "topic".into(),
                envelope::seal_body(
                    &json!({"text":"sealed to me"}),
                    &[(id.addr(), id.root_key().verifying_key())],
                )
                .unwrap(),
                peer.into(),
                "note".into(),
                vec![],
                vec![id.addr()],
                4,
                &id.agent_key(),
            ),
        };
        let chatter: Vec<Stored> = (5..=30)
            .map(|n| make(peer, "note", &format!("chatter {n}"), None, n))
            .collect();
        let follow = make(peer, "request", "second", Some(&answer.env.id), 31);
        let after = make(peer, "note", "after", None, 32);
        let mut thread = vec![first, answer, stranger, sealed];
        thread.extend(chatter);
        thread.push(follow.clone());
        thread.push(after);
        // Everything fits: trusted messages before the request, oldest first, decrypted.
        let all = context(&home, &id, &thread, &follow, 1 << 20);
        assert_eq!(all.len(), 29); // 3 kept, 26 chatter; the stranger's note is held
        assert_eq!(texts(&all[..3]), ["first", "answer", "sealed to me"]);
        assert_eq!(texts(&all[28..]), ["chatter 30"]);
        // A tight budget keeps the reply chain and the newest chatter, whole messages only.
        let tight = context(
            &home,
            &id,
            &thread,
            &follow,
            "first".len() + "answer".len() + "chatter 30".len() + 3,
        );
        assert_eq!(texts(&tight), ["first", "answer", "chatter 30"]);
        // A request with no lineage gets the newest messages that fit.
        let fresh = make(peer, "request", "new topic", None, 33);
        thread.push(fresh.clone());
        let recent = context(&home, &id, &thread, &fresh, "after".len() + "second".len());
        assert_eq!(texts(&recent), ["second", "after"]);
        assert!(context(&home, &id, &thread, &fresh, 1).is_empty());
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn follow_ups_stop_at_count_age_and_incomplete_chains() {
        let id = Identity::generate("me", "https://relay.test", None);
        let peer = "peer@relay.test";
        let cfg = Config {
            max_thread_requests: 3,
            thread_ttl_seconds: 300,
            ..config(Path::new("/tmp"), peer)
        };
        let make = |from: &str, to: &str, kind: &str, parent: Option<&str>, time: u64| Stored {
            gseq: time,
            tseq: time,
            received_at: time,
            env: envelope::Envelope::seal(
                "topic".into(),
                crate::message_body("request".into(), parent.map(str::to_string)),
                from.into(),
                kind.into(),
                vec![],
                vec![to.into()],
                time,
                &id.agent_key(),
            ),
        };
        let root = make(peer, &id.addr(), "request", None, 100);
        let answer = make(&id.addr(), peer, "finding", Some(&root.env.id), 101);
        let next = make(peer, &id.addr(), "request", Some(&answer.env.id), 102);
        let thread = vec![root, answer, next.clone()];
        assert!(follow_allowed(&thread, &next, &id, &cfg, 200));
        assert!(!follow_allowed(&thread, &next, &id, &cfg, 400));
        let short = Config {
            max_thread_requests: 2,
            ..cfg.clone()
        };
        assert!(!follow_allowed(&thread, &next, &id, &short, 200));
        assert!(!follow_allowed(&thread[1..], &next, &id, &cfg, 200));
        let mut foreign = thread.clone();
        foreign[0].env.from = "stranger@relay.test".into();
        assert!(!follow_allowed(&foreign, &next, &id, &cfg, 200));
    }

    #[test]
    fn contact_policy_and_job_cursor_commit_together() {
        let (home, id) = home("cursor");
        let cfg = config(&home, "peer@relay.test");
        let text = json!({"text":"request"});
        let mut db = database(&home).unwrap();
        ingest(
            &mut db,
            &home,
            &id,
            &cfg,
            vec![
                request(&id, "peer@relay.test", 1, text.clone()),
                request(&id, "held@relay.test", 2, text.clone()),
            ],
            2,
        )
        .unwrap();
        assert_eq!(cursor(&db).unwrap(), 2);
        let jobs = || {
            db.query_row("SELECT count(*) FROM jobs", [], |r| r.get::<_, i64>(0))
                .unwrap()
        };
        assert_eq!(jobs(), 1);
        db.execute_batch("CREATE TRIGGER stop_insert BEFORE INSERT ON jobs BEGIN SELECT RAISE(ABORT,'stop'); END;").unwrap();
        assert!(ingest(
            &mut db,
            &home,
            &id,
            &cfg,
            vec![request(&id, "peer@relay.test", 3, text)],
            3
        )
        .is_err());
        assert_eq!(cursor(&db).unwrap(), 2);
        drop(db);
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn encrypted_requests_are_decrypted_and_undecryptable_ones_need_a_human() {
        let (home, id) = home("enc");
        let cfg = config(&home, "peer@relay.test");
        let status = |db: &Connection| {
            db.query_row("SELECT status FROM jobs", [], |r| r.get::<_, String>(0))
                .unwrap()
        };
        let readable = envelope::seal_body(
            &json!({"text":"secret request"}),
            &[(id.addr(), id.root_key().verifying_key())],
        )
        .unwrap();
        let mut db = database(&home).unwrap();
        let sealed = request(&id, "peer@relay.test", 1, readable);
        ingest(&mut db, &home, &id, &cfg, vec![sealed.clone()], 1).unwrap();
        assert_eq!(status(&db), "received");
        assert_eq!(
            request_text(&id, &sealed.env).as_deref(),
            Some("secret request")
        );
        db.execute("DELETE FROM jobs", []).unwrap();
        let stranger = Identity::generate("other", "https://relay.test", None);
        let sealed_elsewhere = envelope::seal_body(
            &json!({"text":"not for us"}),
            &[(id.addr(), stranger.root_key().verifying_key())],
        )
        .unwrap();
        ingest(
            &mut db,
            &home,
            &id,
            &cfg,
            vec![request(&id, "peer@relay.test", 2, sealed_elsewhere)],
            2,
        )
        .unwrap();
        assert_eq!(status(&db), "needs-human");
        assert_eq!(cursor(&db).unwrap(), 2);
        drop(db);
        fs::remove_dir_all(home).unwrap();
    }
}
