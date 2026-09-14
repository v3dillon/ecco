//! Native transcript capture. Conversion stays in the dashboard service.
use crate::{agents, dashboard, local};
use clap::Subcommand;
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde_json::{json, Value};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
const MAX_BYTES: usize = 16 * 1024 * 1024;

#[derive(Subcommand)]
pub enum TraceCmd {
    /// Configure native trace hooks for an agent, or detected installed agents
    Install {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        api: Option<String>,
    },
    /// Remove Ecco's trace hook for an agent
    Uninstall {
        #[arg(long)]
        from: Option<String>,
    },
    /// Capture a native transcript; without a file, read the native hook payload
    Push {
        #[arg(long, required_unless_present = "trace")]
        from: Option<String>,
        #[arg(long, conflicts_with = "trace")]
        transcript: Option<PathBuf>,
        #[arg(long, conflicts_with = "transcript")]
        trace: Option<PathBuf>,
        #[arg(long)]
        api: Option<String>,
        #[arg(long)]
        thinking: bool,
    },
    /// Retry trace uploads retained after network or service failures
    Retry {
        #[arg(long)]
        api: Option<String>,
    },
}
pub fn setup(home: &Path, api: &str, selected: Option<&str>, remove: bool) -> Result<(), String> {
    let home = home.canonicalize().map_err(|e| e.to_string())?;
    let selected: Vec<_> = if let Some(name) = selected {
        vec![agents::find(name)?]
    } else {
        agents::catalog()
            .iter()
            .filter(|a| remove || local::executable(&a.command).is_ok())
            .collect()
    };
    for agent in &selected {
        agents::install(agent, &home, api, remove)?;
    }
    if selected.is_empty() {
        println!("No supported agent CLI detected. Run ecco agents, then ecco init --agent NAME.");
    } else if !remove {
        println!(
            "Restart open agent sessions. Traces upload privately; the dashboard requires Pro."
        );
    }
    Ok(())
}
pub fn run(home: &Path, cmd: TraceCmd) -> Result<(), String> {
    match cmd {
        TraceCmd::Install { from, api } => {
            let api = dashboard::api(home, api.as_deref())?;
            dashboard::configure(home, &api)?;
            setup(home, &api, from.as_deref(), false)
        }
        TraceCmd::Uninstall { from } => setup(home, "", from.as_deref(), true),
        TraceCmd::Retry { api } => {
            dashboard::Outbox::open(home, dashboard::api(home, api.as_deref())?)?
                .flush(usize::MAX)
                .map(|_| ())
        }
        TraceCmd::Push {
            from,
            transcript,
            trace,
            api,
            thinking,
        } => {
            // Native hooks must never fail the surrounding agent session.
            if let Err(e) = push(
                home,
                from.as_deref(),
                transcript.as_deref(),
                trace.as_deref(),
                api.as_deref(),
                thinking,
            ) {
                eprintln!("ecco capture: {e}");
            }
            Ok(())
        }
    }
}
fn push(
    home: &Path,
    from: Option<&str>,
    transcript: Option<&Path>,
    trace: Option<&Path>,
    api: Option<&str>,
    thinking: bool,
) -> Result<(), String> {
    let queue = dashboard::Outbox::open(home, dashboard::api(home, api)?)?;
    let (format, body) = if let Some(path) = trace {
        ("ecco-trace-v1", local::read(path, MAX_BYTES)?)
    } else {
        let from = from.ok_or("--from is required for native transcripts")?;
        agents::find(from)?;
        let payload = if let Some(path) = transcript {
            json!({"transcript_path":path})
        } else {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(65537)
                .read_to_end(&mut bytes)
                .map_err(|e| e.to_string())?;
            if bytes.len() > 65536 {
                return Err("hook input exceeded limit".into());
            }
            serde_json::from_slice(&bytes).map_err(|e| format!("invalid hook payload: {e}"))?
        };
        let (agent, content, turn) = resolve(from, &payload, &local::home()?)?;
        let mut body = json!({"agent":agent,"transcript":content,"thinking":thinking});
        if let Some(turn) = turn {
            body["turnId"] = json!(turn);
        }
        ("ecco-native-v1", body.to_string())
    };
    queue.enqueue(format, &body)?;
    if let Err(error) = queue.flush(3) {
        eprintln!("trace retained for the next hook or ecco traces retry: {error}");
    }
    Ok(())
}
fn field<'a>(payload: &'a Value, snake: &str, camel: &str) -> Option<&'a str> {
    payload
        .get(snake)
        .or_else(|| payload.get(camel))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}
fn directory(user_home: &Path, variable: &str, relative: &str) -> PathBuf {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .unwrap_or_else(|| user_home.join(relative))
}
fn find(root: &Path, accept: &impl Fn(&Path) -> bool) -> Option<PathBuf> {
    for entry in fs::read_dir(root).ok()?.filter_map(Result::ok) {
        let kind = entry.file_type().ok()?;
        let path = entry.path();
        if kind.is_file() && accept(&path) {
            return Some(path);
        }
        if kind.is_dir() {
            if let Some(found) = find(&path, accept) {
                return Some(found);
            }
        }
    }
    None
}
fn session_file(root: &Path, session: &str, filename: Option<&str>) -> Option<PathBuf> {
    find(root, &|path| {
        if let Some(file) = filename {
            path.file_name().is_some_and(|v| v == file)
                && path.components().any(|p| p.as_os_str() == session)
        } else {
            path.file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.ends_with(".jsonl") && v.contains(session))
        }
    })
}
fn rows(connection: &Connection, sql: &str, session: &str) -> Result<Vec<Value>, String> {
    let mut statement = connection.prepare(sql).map_err(|e| e.to_string())?;
    let names: Vec<String> = statement
        .column_names()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let rows = statement
        .query_map([session], |row| {
            let mut out = serde_json::Map::new();
            for (i, name) in names.iter().enumerate() {
                out.insert(
                    name.clone(),
                    match row.get_ref(i)? {
                        ValueRef::Null => Value::Null,
                        ValueRef::Integer(n) => json!(n),
                        ValueRef::Real(n) => json!(n),
                        ValueRef::Text(s) => json!(String::from_utf8_lossy(s)),
                        ValueRef::Blob(_) => Value::Null,
                    },
                );
            }
            Ok(Value::Object(out))
        })
        .map_err(|e| e.to_string())?;
    let mut result = Vec::new();
    let mut size = 0;
    for row in rows {
        let row = row.map_err(|e| e.to_string())?;
        size += row.to_string().len();
        if size > MAX_BYTES {
            return Err("native transcript exceeds capture limit".into());
        }
        result.push(row);
    }
    Ok(result)
}
fn resolve(
    from: &str,
    payload: &Value,
    user_home: &Path,
) -> Result<(String, String, Option<String>), String> {
    if !payload.is_object() {
        return Err("hook payload must be an object".into());
    }
    if field(payload, "subagent_type", "subagentType").is_some()
        || field(payload, "agent_type", "agentType").is_some()
    {
        return Err("subagent session ignored".into());
    }
    let turn =
        if from == "codex" && field(payload, "hook_event_name", "hookEventName") == Some("Stop") {
            field(payload, "turn_id", "turnId").map(str::to_string)
        } else {
            None
        };
    if let Some(path) = field(payload, "transcript_path", "transcriptPath")
        .or_else(|| field(payload, "session_file", "sessionFile"))
    {
        return Ok((from.into(), local::read(Path::new(path), MAX_BYTES)?, turn));
    }
    let session = field(payload, "session_id", "sessionId")
        .or_else(|| field(payload, "thread_id", "threadId"))
        .ok_or("hook needs a transcript path or session id")?;
    if session.contains(['/', '\\', '\0']) {
        return Err("invalid session id".into());
    }
    if from == "hermes" {
        let root = directory(user_home, "HERMES_HOME", ".hermes");
        let db =
            Connection::open_with_flags(root.join("state.db"), OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| e.to_string())?;
        let sessions = rows(
            &db,
            "SELECT id,model,started_at,ended_at,end_reason FROM sessions WHERE id=?",
            session,
        )?;
        let data = sessions.first().ok_or("Hermes session not found")?;
        let messages = rows(&db,"SELECT role,content,tool_call_id,tool_calls,tool_name,timestamp,finish_reason,reasoning,reasoning_content FROM messages WHERE session_id=? ORDER BY timestamp,id",session)?;
        return Ok((
            from.into(),
            json!({"session":data,"messages":messages}).to_string(),
            turn,
        ));
    }
    if from == "opencode" {
        let command = local::executable("opencode")?;
        let content = local::process(
            &[
                command.to_string_lossy().into_owned(),
                "export".into(),
                session.into(),
            ],
            None,
            user_home,
            &std::env::vars().collect(),
            Duration::from_secs(15),
            MAX_BYTES,
        )?;
        return Ok((from.into(), content, turn));
    }
    if from == "openclaw" {
        let root = directory(user_home, "OPENCLAW_STATE_DIR", ".openclaw").join("agents");
        let agent = field(payload, "agent_id", "agentId");
        if agent.is_some_and(|s| s.contains(['/', '\\']) || s == "..") {
            return Err("invalid OpenClaw agent id".into());
        }
        let roots: Vec<PathBuf> = if let Some(a) = agent {
            vec![root.join(a)]
        } else {
            fs::read_dir(root)
                .map_err(|e| e.to_string())?
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.path())
                .collect()
        };
        for root in roots {
            let database = root.join("agent/openclaw-agent.sqlite");
            if database.exists() {
                let db = Connection::open_with_flags(database, OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .map_err(|e| e.to_string())?;
                if let Ok(events) = rows(
                    &db,
                    "SELECT event_json FROM transcript_events WHERE session_id=? ORDER BY seq",
                    session,
                ) {
                    let text = events
                        .iter()
                        .filter_map(|e| e["event_json"].as_str())
                        .collect::<Vec<_>>()
                        .join("\n");
                    if !text.is_empty() {
                        return Ok((from.into(), text, turn));
                    }
                }
            }
            if let Some(path) = session_file(&root.join("sessions"), session, None) {
                return Ok((from.into(), local::read(&path, MAX_BYTES)?, turn));
            }
        }
        return Err("OpenClaw transcript not found".into());
    }
    let (source, path) = match from {
        "codex" => {
            let root = directory(user_home, "CODEX_HOME", ".codex");
            (
                from,
                session_file(&root.join("sessions"), session, None)
                    .or_else(|| session_file(&root.join("archived_sessions"), session, None)),
            )
        }
        "grok" | "claude-code" => (
            "grok",
            session_file(
                &directory(user_home, "GROK_HOME", ".grok").join("sessions"),
                session,
                Some("chat_history.jsonl"),
            ),
        ),
        "kimi-code" => (
            from,
            session_file(
                &directory(user_home, "KIMI_CODE_HOME", ".kimi-code").join("sessions"),
                session,
                Some("wire.jsonl"),
            ),
        ),
        _ => return Err(format!("{from} requires a transcript path")),
    };
    let path = path.ok_or_else(|| format!("{from} transcript not found for {session}"))?;
    Ok((source.into(), local::read(&path, MAX_BYTES)?, turn))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_hook_keeps_format_and_turn_without_local_conversion() {
        let path =
            std::env::temp_dir().join(format!("ecco-capture-{}.jsonl", rand::random::<u64>()));
        fs::write(&path, "native data\n").unwrap();
        let (source, text, turn) = resolve(
            "codex",
            &json!({"transcriptPath":path,"hookEventName":"Stop","turnId":"turn-1"}),
            Path::new("/unused"),
        )
        .unwrap();
        assert_eq!(source, "codex");
        assert_eq!(text, "native data\n");
        assert_eq!(turn.as_deref(), Some("turn-1"));
        assert!(resolve(
            "pi",
            &json!({"transcriptPath":path,"agentType":"child"}),
            Path::new("/unused")
        )
        .is_err());
        fs::remove_file(path).unwrap();
    }
}
