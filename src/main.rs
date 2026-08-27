mod client;
mod envelope;
mod identity;
mod mcp;
mod relay;

use clap::{Parser, Subcommand};
use serde_json::json;
use std::path::PathBuf;

use client::Stored;
use envelope::Envelope;
use identity::Identity;

#[derive(Parser)]
#[command(name = "ecco", version, about = "Async messaging between agents owned by different people.")]
struct Cli {
    /// Identity directory (default: $ECCO_HOME or ~/.ecco)
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an identity and register it with a relay
    Init {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "http://localhost:4200")]
        relay: String,
    },
    /// Run a relay
    Relay {
        #[arg(long, default_value_t = 4200)]
        port: u16,
        #[arg(long)]
        data: Option<PathBuf>,
    },
    /// Post a message to a thread
    Send {
        text: String,
        /// Recipient address(es), name@authority
        #[arg(long)]
        to: Vec<String>,
        /// Thread anchor, e.g. gh:acme/app/pull/13 (default: dm with recipients)
        #[arg(long)]
        about: Option<String>,
        #[arg(long, default_value = "note", value_parser = envelope::KINDS.to_vec())]
        kind: String,
    },
    /// Show messages addressed to you
    Inbox {
        #[arg(long, default_value_t = 0, conflicts_with = "new")]
        since: u64,
        /// Only messages since the persisted cursor, then advance it (for agent session starts)
        #[arg(long)]
        new: bool,
    },
    /// Follow your inbox (long-poll loop; resumes from the persisted cursor)
    Watch {
        /// Override the starting point (default: persisted cursor)
        #[arg(long)]
        since: Option<u64>,
    },
    /// Show a thread — the ledger for one artifact
    Log { about: String },
    /// List proposals awaiting your (human) decision
    Pending,
    /// Sign a decision approving a proposal — root key, human only
    Approve { id: String },
    /// Sign a decision rejecting a proposal — root key, human only
    Reject { id: String },
    /// Serve ecco as MCP tools over stdio (for agent harnesses)
    Mcp,
    /// Fetch and verify another address's profile
    Resolve { addr: String },
    /// Show your identity
    Whoami,
}

fn main() {
    let cli = Cli::parse();
    let home = cli.home.clone().unwrap_or_else(identity::default_home);
    if let Err(e) = run(cli.cmd, &home) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cmd: Cmd, home: &PathBuf) -> Result<(), String> {
    match cmd {
        Cmd::Init { name, relay } => {
            if Identity::load(home).is_ok() {
                return Err(format!(
                    "identity already exists at {} (use --home for another)",
                    home.display()
                ));
            }
            let id = Identity::generate(&name, &relay);
            client::register(&id.relay, &id.profile())?;
            id.save(home)?;
            println!("registered {}", id.addr());
            println!("root key (you):    {}", envelope::encode_key(&id.root_key().verifying_key()));
            println!("agent key (bot):   {}", envelope::encode_key(&id.agent_key().verifying_key()));
            Ok(())
        }
        Cmd::Relay { port, data } => {
            let data = data.unwrap_or_else(|| home.join("relay"));
            relay::run(port, data)
        }
        Cmd::Send { text, to, about, kind } => {
            let id = Identity::load(home)?;
            let about = about.unwrap_or_else(|| dm_thread(&id.addr(), &to));
            let receipt = post(&id, about, kind, json!({ "text": text }), to)?;
            println!("{receipt}");
            Ok(())
        }
        Cmd::Inbox { since, new } => {
            let id = Identity::load(home)?;
            let start = if new { load_cursor(home) } else { since };
            let mut cursor = start;
            for s in client::inbox(&id.relay, &id.addr(), start, 0)? {
                println!("{}", fmt(&s));
                cursor = cursor.max(s.gseq);
            }
            if new {
                save_cursor(home, cursor)?;
            }
            Ok(())
        }
        Cmd::Watch { since } => {
            let id = Identity::load(home)?;
            let mut cursor = since.unwrap_or_else(|| load_cursor(home));
            eprintln!("watching inbox for {} from #{cursor} (ctrl-c to stop)", id.addr());
            loop {
                for s in client::inbox(&id.relay, &id.addr(), cursor, 25)? {
                    println!("{}", fmt(&s));
                    cursor = cursor.max(s.gseq);
                    save_cursor(home, cursor)?;
                }
            }
        }
        Cmd::Log { about } => {
            let id = Identity::load(home)?;
            let mut msgs = client::thread(&id.relay, &about, 0, 0)?;
            msgs.sort_by_key(|s| s.tseq);
            for s in msgs {
                println!("{}", fmt(&s));
            }
            Ok(())
        }
        Cmd::Pending => {
            let id = Identity::load(home)?;
            let pending = pending_proposals(&id)?;
            if pending.is_empty() {
                println!("nothing pending");
            }
            for s in pending {
                println!("{}", fmt(&s));
            }
            Ok(())
        }
        Cmd::Approve { id: target } => decide(home, &target, "approves"),
        Cmd::Reject { id: target } => decide(home, &target, "rejects"),
        Cmd::Mcp => mcp::run(home),
        Cmd::Resolve { addr } => {
            let profile = client::resolve(&addr)?;
            println!("{}", serde_json::to_string_pretty(&profile).unwrap());
            Ok(())
        }
        Cmd::Whoami => {
            let id = Identity::load(home)?;
            println!("{}", id.addr());
            println!("relay: {}", id.relay);
            println!("root:  {}", envelope::encode_key(&id.root_key().verifying_key()));
            println!("agent: {}", envelope::encode_key(&id.agent_key().verifying_key()));
            Ok(())
        }
    }
}

/// Build, sign (agent key — or root key for decisions), and submit an envelope.
fn post(
    id: &Identity,
    about: String,
    kind: String,
    body: serde_json::Value,
    to: Vec<String>,
) -> Result<String, String> {
    let prev = client::thread(&id.relay, &about, 0, 0)?
        .iter()
        .max_by_key(|s| s.tseq)
        .map(|s| vec![s.env.id.clone()])
        .unwrap_or_default();
    let key = if kind == "decision" { id.root_key() } else { id.agent_key() };
    let env = Envelope::seal(about, body, id.addr(), kind, prev, to, envelope::now(), &key);
    client::send(&id.relay, &env)
}

/// A decision is the human ruling on a proposal: signed by the root key, never the agent's.
fn decide(home: &PathBuf, target: &str, verb: &str) -> Result<(), String> {
    let id = Identity::load(home)?;
    let proposal = pending_proposals(&id)?
        .into_iter()
        .find(|s| s.env.id == target || s.env.id.trim_start_matches("b3:").starts_with(target))
        .ok_or_else(|| format!("no pending proposal matching '{target}'"))?;
    let mut body = serde_json::Map::new();
    body.insert(verb.into(), json!(proposal.env.id));
    body.insert("text".into(), json!(format!("{verb} {}", short(&proposal.env.id))));
    let receipt = post(
        &id,
        proposal.env.about.clone(),
        "decision".into(),
        serde_json::Value::Object(body),
        vec![proposal.env.from.clone()],
    )?;
    println!("{receipt}");
    Ok(())
}

/// Proposals in the inbox whose thread does not yet contain a decision about them.
fn pending_proposals(id: &Identity) -> Result<Vec<Stored>, String> {
    let msgs = client::inbox(&id.relay, &id.addr(), 0, 0)?;
    let mut pending = Vec::new();
    for s in msgs.into_iter().filter(|s| s.env.kind == "proposal") {
        let decided = client::thread(&id.relay, &s.env.about, 0, 0)?.iter().any(|t| {
            t.env.kind == "decision"
                && t.env
                    .body
                    .get("approves")
                    .or(t.env.body.get("rejects"))
                    .and_then(|v| v.as_str())
                    == Some(s.env.id.as_str())
        });
        if !decided {
            pending.push(s);
        }
    }
    Ok(pending)
}

// The cursor is client-side state, not protocol: the last-seen inbox gseq for
// this identity's relay, so each session resumes where the previous one stopped.
fn load_cursor(home: &PathBuf) -> u64 {
    std::fs::read_to_string(home.join("cursor"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn save_cursor(home: &PathBuf, cursor: u64) -> Result<(), String> {
    std::fs::write(home.join("cursor"), cursor.to_string()).map_err(|e| e.to_string())
}

fn dm_thread(own: &str, to: &[String]) -> String {
    let mut addrs: Vec<&str> = to.iter().map(String::as_str).collect();
    addrs.push(own);
    addrs.sort();
    addrs.dedup();
    format!("dm:{}", addrs.join(","))
}

fn fmt(s: &Stored) -> String {
    let text = s.env.body.get("text").and_then(|t| t.as_str()).unwrap_or("");
    format!(
        "#{:<3} [{}] {} · {} · {} ({} t={})",
        s.tseq, s.env.kind, s.env.from, s.env.about, text, short(&s.env.id), s.received_at
    )
}

fn short(id: &str) -> String {
    id.trim_start_matches("b3:").chars().take(8).collect()
}
