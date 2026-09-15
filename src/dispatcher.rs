//! Local durable dispatch. Agent launch details are separate from queue policy.
use crate::{
    client::{self, Stored},
    identity::{self, Identity},
    local, reporting,
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
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
mod handler;
mod service;

#[derive(Subcommand)]
pub enum DispatcherCmd {
    /// Trust allowed senders and start a local dispatcher on the same relay.
    Install {
        #[arg(long, required = true)]
        allow: Vec<String>,
        #[arg(long)]
        workdir: PathBuf,
        #[arg(long)]
        handler: PathBuf,
        #[arg(long)]
        handler_arg: Vec<String>,
        /// Environment variable names to retain for the handler
        #[arg(long)]
        handler_env: Vec<String>,
        #[arg(long,default_value_t=8,value_parser=clap::value_parser!(u32).range(1..=32))]
        max_thread_requests: u32,
        #[arg(long,default_value_t=3600,value_parser=clap::value_parser!(u32).range(1..=86400))]
        thread_ttl_seconds: u32,
    },
    Start,
    Restart,
    Stop,
    Status,
    Logs,
    Uninstall,
    /// Run the installed dispatcher in the foreground
    Run {
        #[arg(long)]
        once: bool,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    version: u32,
    allow: Vec<String>,
    work_dir: PathBuf,
    handler: Handler,
    max_thread_requests: u32,
    thread_ttl_seconds: u32,
}
impl Config {
    fn handler_name(&self) -> &str {
        Path::new(&self.handler.executable)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("handler")
    }
}
pub fn config_path(home: &Path) -> PathBuf {
    home.join("dispatcher/config.json")
}
fn config(home: &Path) -> Result<Config, String> {
    let cfg: Config = serde_json::from_str(&local::read(&config_path(home), 65536)?)
        .map_err(|e| format!("invalid dispatcher config: {e}"))?;
    if cfg.version != 1 {
        return Err("unsupported dispatcher config; reinstall with ecco dispatcher install".into());
    }
    validate(home, &cfg)?;
    Ok(cfg)
}
fn validate(home: &Path, cfg: &Config) -> Result<(), String> {
    let id = Identity::load(home)?;
    let authority = identity::authority(&id.relay);
    if cfg.allow.is_empty()
        || cfg.allow.iter().any(|a| {
            a.rsplit_once('@')
                .is_none_or(|(name, relay)| name.is_empty() || relay != authority)
        })
    {
        return Err("dispatcher needs same-relay --allow addresses".into());
    }
    if !cfg.work_dir.is_absolute()
        || !cfg.work_dir.is_dir()
        || cfg.work_dir.parent().is_none()
        || cfg.work_dir.to_string_lossy().contains(['\n', '\r'])
    {
        return Err("--workdir must be an existing absolute directory other than /".into());
    }
    if !(1..=32).contains(&cfg.max_thread_requests)
        || !(1..=86400).contains(&cfg.thread_ttl_seconds)
    {
        return Err("invalid dispatcher conversation limits".into());
    }
    cfg.handler.validate()
}
fn install_config(home: &Path, cfg: Config) -> Result<(), String> {
    validate(home, &cfg)?;
    service::install(home, &cfg)?;
    println!("Dispatcher installed and started.");
    Ok(())
}
pub fn command(home: &Path, cmd: DispatcherCmd) -> Result<(), String> {
    match cmd {
        DispatcherCmd::Install {
            allow,
            workdir,
            handler,
            handler_arg,
            handler_env,
            max_thread_requests,
            thread_ttl_seconds,
        } => {
            let handler = Handler {
                executable: handler.to_string_lossy().into_owned(),
                args: handler_arg,
                env: handler_env,
            };
            install_config(
                home,
                Config {
                    version: 1,
                    allow,
                    work_dir: workdir,
                    handler,
                    max_thread_requests,
                    thread_ttl_seconds,
                },
            )
        }
        DispatcherCmd::Run { once } => run(home, once),
        other => service::command(home, other),
    }
}
fn database(home: &Path) -> Result<Connection, String> {
    let path = home.join("dispatcher.sqlite");
    let db = Connection::open(&path).map_err(|e| e.to_string())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    db.busy_timeout(Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    let exists: i64 = db
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='jobs'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if exists > 0 {
        let columns: Vec<String> = db
            .prepare("PRAGMA table_info(jobs)")
            .map_err(|e| e.to_string())?
            .query_map([], |r| r.get(1))
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        if !columns.iter().any(|s| s == "payload") {
            return Err("existing dispatcher database uses an unsupported format; preserved without changes".into());
        }
    }
    db.execute_batch("PRAGMA journal_mode=WAL;CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL);INSERT OR IGNORE INTO state VALUES ('cursor','0'),('sequence','0');CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,payload TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'received',attempts INTEGER NOT NULL DEFAULT 0,result TEXT,next_at INTEGER NOT NULL DEFAULT 0);CREATE TABLE IF NOT EXISTS report_outbox(sequence INTEGER PRIMARY KEY,payload TEXT NOT NULL,created_at INTEGER NOT NULL DEFAULT (unixepoch()));").map_err(|e|e.to_string())?;
    let id = Identity::load(home)?;
    let candidate = format!(
        "disp:{:032x}@{}",
        rand::random::<u128>(),
        identity::authority(&id.relay)
    );
    db.execute(
        "INSERT OR IGNORE INTO state VALUES ('dispatcher_id',?)",
        [candidate],
    )
    .map_err(|e| e.to_string())?;
    Ok(db)
}
fn state(db: &Connection, key: &str) -> Result<String, String> {
    db.query_row("SELECT value FROM state WHERE key=?", [key], |r| r.get(0))
        .map_err(|e| e.to_string())
}
fn event(
    db: &Connection,
    cfg: &Config,
    job: &Stored,
    status: &str,
    attempt: i64,
) -> Result<(), String> {
    let sequence:i64=db.query_row("UPDATE state SET value=CAST(value AS INTEGER)+1 WHERE key='sequence' RETURNING CAST(value AS INTEGER)",[],|r|r.get(0)).map_err(|e|e.to_string())?;
    let dispatcher = state(db, "dispatcher_id")?;
    let payload = json!({"v":1,"eventId":format!("{dispatcher}/{sequence}"),"dispatcherId":dispatcher,"jobId":job.env.id,"sequence":sequence,"state":status,"provider":cfg.handler_name(),"attempt":attempt,"at":local::timestamp(),"about":job.env.about});
    db.execute(
        "INSERT INTO report_outbox(sequence,payload) VALUES (?,?)",
        rusqlite::params![sequence, payload.to_string()],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
fn request_text(id: &Identity, env: &crate::envelope::Envelope) -> Option<String> {
    let body = if crate::envelope::is_encrypted(&env.body) {
        crate::envelope::open_body(&env.body, &id.addr(), &id.root_key())?
    } else {
        env.body.clone()
    };
    let text = body.get("text")?.as_str()?;
    (!text.is_empty() && text.len() <= 65536).then(|| text.to_owned())
}

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
        if env.from == id.addr() || !env.to.contains(&id.addr()) {
            continue;
        }
        let status = if env.kind == "proposal" {
            "needs-human"
        } else if env.kind != "request" || !cfg.allow.contains(&env.from) {
            continue;
        } else if request_text(id, env).is_some() {
            "received"
        } else if crate::envelope::is_encrypted(&env.body)
            && crate::envelope::open_body(&env.body, &id.addr(), &id.root_key()).is_none()
        {
            "needs-human"
        } else {
            continue;
        };
        if tx
            .execute(
                "INSERT OR IGNORE INTO jobs(id,payload,status) VALUES (?,?,?)",
                rusqlite::params![env.id, serde_json::to_string(&stored).unwrap(), status],
            )
            .map_err(|e| e.to_string())?
            > 0
        {
            event(&tx, cfg, &stored, status, 0)?;
        }
    }
    tx.execute(
        "UPDATE state SET value=? WHERE key='cursor'",
        [next.to_string()],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())
}
fn report(db: &Connection, id: &Identity, api: &str, cfg: &Config) -> Result<(), String> {
    db.execute_batch("DELETE FROM report_outbox WHERE created_at < unixepoch()-7776000; DELETE FROM report_outbox WHERE sequence IN (SELECT sequence FROM report_outbox ORDER BY sequence DESC LIMIT -1 OFFSET 10000);").map_err(|e|e.to_string())?;
    let rows: Vec<(i64, String)> = db
        .prepare("SELECT sequence,payload FROM report_outbox ORDER BY sequence LIMIT 100")
        .map_err(|e| e.to_string())?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let events: Vec<Value> = rows
        .iter()
        .map(|(_, s)| serde_json::from_str(s))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let body = json!({"v":1,"events":events,"heartbeat":{"v":1,"dispatcherId":state(db,"dispatcher_id")?,"provider":cfg.handler_name(),"at":local::timestamp()}});
    let activity = json!({"schema":reporting::ACTIVITY_SCHEMA,"type":"dispatcher","observer":id.addr(),"report":body});
    reporting::post(id, api, &activity.to_string())?;
    for (sequence, _) in rows {
        db.execute("DELETE FROM report_outbox WHERE sequence=?", [sequence])
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn correlated(thread: &[Stored], self_addr: &str, request: &str, follow: bool) -> bool {
    correlated_message(thread, self_addr, request, follow).is_some()
}
fn correlated_message<'a>(
    thread: &'a [Stored],
    self_addr: &str,
    request: &str,
    follow: bool,
) -> Option<&'a Stored> {
    thread.iter().find(|s| {
        s.env.from == self_addr
            && s.env.body["in_reply_to"] == request
            && if follow {
                s.env.kind == "request"
            } else {
                ["finding", "proposal"].contains(&s.env.kind.as_str())
            }
    })
}
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
        current = if let Some(parent) = env.body["in_reply_to"].as_str() {
            match by_id.get(parent) {
                Some(s) => Some(*s),
                None => return false,
            }
        } else {
            None
        };
    }
    count > 0
        && count < cfg.max_thread_requests
        && now < first.saturating_add(cfg.thread_ttl_seconds as u64)
}
fn send(
    home: &Path,
    id: &Identity,
    request: &Stored,
    kind: &str,
    text: &str,
) -> Result<Stored, String> {
    let env = crate::prepare_envelope(
        home,
        id,
        crate::SendInput {
            about: request.env.about.clone(),
            kind: kind.into(),
            body: crate::message_body(text.into(), Some(request.env.id.clone())),
            to: vec![request.env.from.clone()],
            encrypt: false,
        },
        None,
    )?;
    let receipt = client::send(home, id, &env)?;
    Ok(Stored {
        env,
        gseq: receipt.gseq,
        tseq: receipt.tseq,
        received_at: receipt.received_at,
    })
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
    let thread = client::thread(home, id, &request.env.about, 0, 0)?;
    let replied = correlated(&thread, &id.addr(), &request.env.id, false);
    if replied && saved.is_none() {
        return Ok("completed");
    }
    let result = if let Some(saved) = saved {
        ResultMessage::decode(serde_json::from_str(saved).map_err(|e| e.to_string())?)?
    } else {
        let text = request_text(id, &request.env).ok_or("request has no usable text")?;
        let input = json!({"schema":"ecco-dispatch-v1","type":"request","untrusted":true,"envelope":{"id":request.env.id,"from":request.env.from,"about":request.env.about,"text":text}});
        let result = cfg.handler.run(&cfg.work_dir, &input)?;
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
        if !correlated(&thread, &id.addr(), &request.env.id, true)
            && follow_allowed(&thread, request, id, cfg, crate::envelope::now())
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
    let jobs:Vec<(String,Option<String>,i64)>=db.prepare("SELECT payload,result,attempts FROM jobs WHERE status IN ('received','retrying') AND next_at<=unixepoch() ORDER BY rowid LIMIT 20").map_err(|e|e.to_string())?.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|e|e.to_string())?.collect::<Result<_,_>>().map_err(|e|e.to_string())?;
    for (payload, saved, attempts) in jobs {
        if local::cancelled() {
            break;
        }
        let request: Stored = serde_json::from_str(&payload).map_err(|e| e.to_string())?;
        let attempt = attempts + 1;
        let tx = db.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE jobs SET status='running',attempts=? WHERE id=?",
            rusqlite::params![attempt, request.env.id],
        )
        .map_err(|e| e.to_string())?;
        event(&tx, cfg, &request, "running", attempt)?;
        tx.commit().map_err(|e| e.to_string())?;
        let (status, delay) = match execute(db, home, id, cfg, &request, saved.as_deref()) {
            Ok(status) => (status, 0),
            Err(e) => {
                eprintln!("dispatcher request {}: {e}", request.env.id);
                (
                    if attempt >= 4 { "failed" } else { "retrying" },
                    (1i64 << attempt.min(8)) * 2,
                )
            }
        };
        let tx = db.transaction().map_err(|e| e.to_string())?;
        tx.execute(
            "UPDATE jobs SET status=?,next_at=unixepoch()+? WHERE id=?",
            rusqlite::params![status, delay, request.env.id],
        )
        .map_err(|e| e.to_string())?;
        event(&tx, cfg, &request, status, attempt)?;
        tx.commit().map_err(|e| e.to_string())?;
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
    db.execute(
        "UPDATE jobs SET status='retrying',next_at=0 WHERE status='running'",
        [],
    )
    .map_err(|e| e.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let worker_home = home.to_path_buf();
    let worker_cfg = cfg.clone();
    let reporter = std::thread::spawn(move || {
        if let (Ok(db), Ok(id)) = (database(&worker_home), Identity::load(&worker_home)) {
            loop {
                if let Ok(api) = reporting::destination(&worker_home) {
                    if let Err(e) = report(&db, &id, &api, &worker_cfg) {
                        eprintln!("dispatcher reporting retained: {e}");
                    }
                    let _ =
                        reporting::Outbox::open(&worker_home, api).and_then(|q| q.flush(3, true));
                }
                for _ in 0..60 {
                    if worker_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
    });
    let result = (|| {
        loop {
            if local::cancelled() {
                break;
            }
            let cursor = state(&db, "cursor")?
                .parse()
                .map_err(|e: std::num::ParseIntError| e.to_string())?;
            match client::inbox(home, &id, cursor, if once { 0 } else { 20 })
                .and_then(|(messages, until)| ingest(&mut db, home, &id, &cfg, messages, until))
            {
                Ok(()) => {}
                Err(e) => {
                    if once {
                        return Err(e);
                    }
                    eprintln!("dispatcher inbox retry: {e}");
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
            match process_ready(&mut db, home, &id, &cfg) {
                Ok(()) => {}
                Err(e) => {
                    if once {
                        return Err(e);
                    }
                    eprintln!("dispatcher job retry: {e}");
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
            if once {
                break;
            }
        }
        Ok(())
    })();
    stop.store(true, Ordering::Relaxed);
    let _ = reporter.join();
    if let Ok(api) = reporting::destination(home) {
        let _ = report(&db, &id, &api, &cfg);
        let _ = reporting::Outbox::open(home, api).and_then(|q| q.flush(3, true));
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn follow_ups_stop_at_count_age_and_incomplete_chains() {
        let id = Identity::generate("me", "https://relay.test", None);
        let peer = "peer@relay.test";
        let cfg = Config {
            version: 1,
            allow: vec![peer.into()],
            work_dir: PathBuf::from("/tmp"),
            handler: Handler {
                executable: "/bin/true".into(),
                args: vec![],
                env: vec![],
            },
            max_thread_requests: 3,
            thread_ttl_seconds: 300,
        };
        let make = |from: &str, to: &str, kind: &str, parent: Option<&str>, time: u64| Stored {
            gseq: time,
            tseq: time,
            received_at: time,
            env: crate::envelope::Envelope::seal(
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
        let home = std::env::temp_dir().join(format!("ecco-dispatch-{}", rand::random::<u64>()));
        let id = Identity::generate("me", "https://relay.test", None);
        id.save(&home).unwrap();
        identity::contacts_set(&home, "peer@relay.test", "approved").unwrap();
        let cfg = Config {
            version: 1,
            allow: vec!["peer@relay.test".into()],
            work_dir: home.clone(),
            handler: Handler {
                executable: "/bin/true".into(),
                args: vec![],
                env: vec![],
            },
            max_thread_requests: 8,
            thread_ttl_seconds: 3600,
        };
        let make = |from: &str, n: u64| Stored {
            gseq: n,
            tseq: n,
            received_at: 100,
            env: crate::envelope::Envelope::seal(
                "topic".into(),
                json!({"text":"request"}),
                from.into(),
                "request".into(),
                vec![],
                vec![id.addr()],
                100,
                &id.agent_key(),
            ),
        };
        let mut db = database(&home).unwrap();
        ingest(
            &mut db,
            &home,
            &id,
            &cfg,
            vec![make("peer@relay.test", 1), make("held@relay.test", 2)],
            2,
        )
        .unwrap();
        assert_eq!(state(&db, "cursor").unwrap(), "2");
        assert_eq!(
            db.query_row("SELECT count(*) FROM jobs", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT count(*) FROM report_outbox", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        db.execute_batch("CREATE TRIGGER stop_insert BEFORE INSERT ON jobs BEGIN SELECT RAISE(ABORT,'stop'); END;").unwrap();
        assert!(ingest(
            &mut db,
            &home,
            &id,
            &cfg,
            vec![make("peer@relay.test", 3)],
            3
        )
        .is_err());
        assert_eq!(state(&db, "cursor").unwrap(), "2");
        drop(db);
        fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn encrypted_requests_are_decrypted_and_undecryptable_ones_need_a_human() {
        let home =
            std::env::temp_dir().join(format!("ecco-dispatch-enc-{}", rand::random::<u64>()));
        let id = Identity::generate("me", "https://relay.test", None);
        id.save(&home).unwrap();
        identity::contacts_set(&home, "peer@relay.test", "approved").unwrap();
        let cfg = Config {
            version: 1,
            allow: vec!["peer@relay.test".into()],
            work_dir: home.clone(),
            handler: Handler {
                executable: "/bin/true".into(),
                args: vec![],
                env: vec![],
            },
            max_thread_requests: 8,
            thread_ttl_seconds: 3600,
        };
        let envelope = |body| Stored {
            gseq: 1,
            tseq: 1,
            received_at: 100,
            env: crate::envelope::Envelope::seal(
                "topic".into(),
                body,
                "peer@relay.test".into(),
                "request".into(),
                vec![],
                vec![id.addr()],
                100,
                &id.agent_key(),
            ),
        };
        let readable = crate::envelope::seal_body(
            &json!({"text":"secret request"}),
            &[(id.addr(), id.root_key().verifying_key())],
        )
        .unwrap();
        let mut db = database(&home).unwrap();
        ingest(&mut db, &home, &id, &cfg, vec![envelope(readable)], 1).unwrap();
        assert_eq!(
            db.query_row("SELECT status FROM jobs", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "received"
        );
        let payload: String = db
            .query_row("SELECT payload FROM jobs", [], |r| r.get(0))
            .unwrap();
        let stored: Stored = serde_json::from_str(&payload).unwrap();
        assert_eq!(
            request_text(&id, &stored.env).as_deref(),
            Some("secret request")
        );
        db.execute("DELETE FROM jobs", []).unwrap();
        let stranger = Identity::generate("other", "https://relay.test", None);
        let sealed_elsewhere = crate::envelope::seal_body(
            &json!({"text":"not for us"}),
            &[(id.addr(), stranger.root_key().verifying_key())],
        )
        .unwrap();
        ingest(
            &mut db,
            &home,
            &id,
            &cfg,
            vec![envelope(sealed_elsewhere)],
            2,
        )
        .unwrap();
        assert_eq!(
            db.query_row("SELECT status FROM jobs", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "needs-human"
        );
        assert_eq!(state(&db, "cursor").unwrap(), "2");
        drop(db);
        fs::remove_dir_all(home).unwrap();
    }
}
