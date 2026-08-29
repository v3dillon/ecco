mod agent_surface;
mod client;
mod coordination;
mod envelope;
mod identity;
mod mcp;
mod outbox;
mod relay;
mod store;

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

use client::Stored;
use envelope::Envelope;
use identity::Identity;

#[derive(Parser)]
#[command(
    name = "ecco",
    version,
    about = "Async messaging between agents owned by different people."
)]
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
        /// Bearer token, if the relay is private
        #[arg(long)]
        token: Option<String>,
    },
    /// Run a relay
    Relay {
        #[arg(long, default_value_t = 4200)]
        port: u16,
        #[arg(long)]
        data: Option<PathBuf>,
        /// Require this bearer token on every request (or set ECCO_RELAY_TOKEN)
        #[arg(long)]
        token: Option<String>,
        /// Require signed reads — for multi-tenant relays (or set ECCO_RELAY_SIGNED)
        #[arg(long)]
        signed: bool,
        /// Address authority, e.g. relay.ecco.bot (or set ECCO_RELAY_AUTHORITY). Default: localhost:<port>
        #[arg(long)]
        authority: Option<String>,
        /// Fail-closed allowedRoots from the limits snapshot (or set ECCO_RELAY_ALLOW_ROOTS). Requires --limits-url and --signed
        #[arg(long)]
        allow_roots: bool,
        /// Limits snapshot URL for per-sender retention windows (or set ECCO_RELAY_LIMITS_URL)
        #[arg(long)]
        limits_url: Option<String>,
        /// Default retention in days for senders without a window; 0 keeps forever (or set ECCO_RELAY_RETENTION_DAYS). Unset with no limits URL: never expire
        #[arg(long)]
        retention_days: Option<u32>,
    },
    /// Relay operator tools. Not protocol: they act on one relay's store.
    Admin {
        #[command(subcommand)]
        cmd: AdminCmd,
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
        /// Encrypt the body to the recipients' root keys
        #[arg(long, short = 'e')]
        encrypt: bool,
        /// Envelope id of the request this message answers
        #[arg(long)]
        in_reply_to: Option<String>,
        /// Stable retry key for managed dispatchers (1-128 safe ASCII bytes)
        #[arg(long, value_parser = outbox::parse_key)]
        idempotency_key: Option<String>,
    },
    /// Coordinate exclusive work on a generic thread anchor
    Work {
        #[command(subcommand)]
        cmd: WorkCmd,
    },
    /// Show messages addressed to you
    Inbox {
        #[arg(long, default_value_t = 0, conflicts_with = "new")]
        since: u64,
        /// Only messages since the persisted cursor, then advance it (for agent session starts)
        #[arg(long)]
        new: bool,
        /// Return a stable machine-readable batch
        #[arg(long)]
        json: bool,
        /// Long-poll timeout in seconds
        #[arg(long, default_value_t = 0)]
        wait: u64,
    },
    /// Follow your inbox (long-poll loop; resumes from the persisted cursor)
    Watch {
        /// Override the starting point (default: persisted cursor)
        #[arg(long)]
        since: Option<u64>,
    },
    /// Show a thread — the ledger for one artifact
    Log {
        about: String,
        /// Return a stable machine-readable batch
        #[arg(long)]
        json: bool,
    },
    /// Held first-contact messages awaiting your (human) review
    Requests,
    /// Approve a sender — their messages become visible to your agent
    Trust { addr: String },
    /// Block a sender — their messages are dropped from view
    Block { addr: String },
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
    /// Inspect local identity readiness without contacting the relay
    Status {
        /// Return the ecco-status-v1 object
        #[arg(long)]
        json: bool,
    },
    /// Revoke the agent key: publish a profile with no delegations. The name stays yours (root key)
    Deactivate,
}

#[derive(Subcommand)]
enum WorkCmd {
    Status {
        #[arg(long)]
        about: String,
    },
    Claim {
        #[arg(long)]
        about: String,
        #[arg(long)]
        to: Vec<String>,
        #[arg(long)]
        branch: Option<String>,
        #[arg(long, default_value_t = coordination::DEFAULT_TTL_SECONDS)]
        ttl_seconds: u64,
        #[arg(long)]
        text: Option<String>,
    },
    Release {
        #[arg(long)]
        about: String,
        #[arg(long)]
        claim: Option<String>,
    },
}

#[derive(Subcommand)]
enum AdminCmd {
    /// Remove one envelope by id (takedown). Peers keep their signed copies
    Remove {
        id: String,
        /// Relay data dir (default: $ECCO_HOME/relay)
        #[arg(long)]
        data: Option<PathBuf>,
    },
    /// Run one retention pass now with this default window in days (0 keeps forever)
    Sweep {
        #[arg(long)]
        days: u32,
        /// Relay data dir (default: $ECCO_HOME/relay)
        #[arg(long)]
        data: Option<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();
    let home = cli.home.clone().unwrap_or_else(identity::default_home);
    if let Err(e) = run(cli.cmd, &home) {
        if let Some(json) = coordination::claim_lost_json(&e) {
            println!("{json}");
            std::process::exit(2);
        }
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cmd: Cmd, home: &Path) -> Result<(), String> {
    match cmd {
        Cmd::Init { name, relay, token } => {
            let id = Identity::prepare(home, &name, &relay, token)?;
            client::register(&id)?;
            println!("registered {}", id.addr());
            println!(
                "root key (you):    {}",
                envelope::encode_key(&id.root_key().verifying_key())
            );
            println!(
                "agent key (bot):   {}",
                envelope::encode_key(&id.agent_key().verifying_key())
            );
            Ok(())
        }
        Cmd::Relay {
            port,
            data,
            token,
            signed,
            authority,
            allow_roots,
            limits_url,
            retention_days,
        } => {
            let data = data.unwrap_or_else(|| home.join("relay"));
            let token = token.or_else(|| std::env::var("ECCO_RELAY_TOKEN").ok());
            let signed = signed || std::env::var("ECCO_RELAY_SIGNED").is_ok();
            let authority = authority
                .or_else(|| std::env::var("ECCO_RELAY_AUTHORITY").ok())
                .map(|s| identity::authority(&s))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("localhost:{port}"));
            let allow_roots = allow_roots || std::env::var("ECCO_RELAY_ALLOW_ROOTS").is_ok();
            let retention = relay::Retention {
                limits_url: limits_url.or_else(|| std::env::var("ECCO_RELAY_LIMITS_URL").ok()),
                default_days: match retention_days {
                    Some(d) => Some(d),
                    None => match std::env::var("ECCO_RELAY_RETENTION_DAYS") {
                        Ok(v) => Some(v.trim().parse().map_err(|_| {
                            format!("ECCO_RELAY_RETENTION_DAYS: '{v}' is not a day count")
                        })?),
                        Err(_) => None,
                    },
                },
            };
            relay::run(port, data, token, signed, authority, allow_roots, retention)
        }
        Cmd::Admin { cmd } => match cmd {
            AdminCmd::Remove { id, data } => {
                let store = store::Store::open(&data.unwrap_or_else(|| home.join("relay")))?;
                if store.remove(&id).map_err(|(_, e)| e)? {
                    println!("removed {id}");
                    Ok(())
                } else {
                    Err(format!("no envelope with id {id}"))
                }
            }
            AdminCmd::Sweep { days, data } => {
                let store = store::Store::open(&data.unwrap_or_else(|| home.join("relay")))?;
                let n = relay::sweep_once(&store, days)?;
                println!("expired {n} envelope(s)");
                Ok(())
            }
        },
        Cmd::Send {
            text,
            to,
            about,
            kind,
            encrypt,
            in_reply_to,
            idempotency_key,
        } => {
            let id = Identity::load(home)?;
            let about = about.unwrap_or_else(|| dm_thread(&id.addr(), &to));
            let body = message_body(text, in_reply_to);
            let receipt = post_idempotent(
                home,
                &id,
                SendInput {
                    about,
                    kind,
                    body,
                    to,
                    encrypt,
                },
                idempotency_key.as_deref(),
            )?;
            println!("{}", serde_json::to_string(&receipt).unwrap());
            Ok(())
        }
        Cmd::Work { cmd } => {
            let id = Identity::load(home)?;
            let value = match cmd {
                WorkCmd::Status { about } => {
                    serde_json::to_value(coordination::status(&id, &about)?).unwrap()
                }
                WorkCmd::Claim {
                    about,
                    to,
                    branch,
                    ttl_seconds,
                    text,
                } => serde_json::to_value(coordination::claim(
                    home,
                    &id,
                    &about,
                    to,
                    branch,
                    ttl_seconds,
                    text,
                )?)
                .unwrap(),
                WorkCmd::Release { about, claim } => {
                    serde_json::to_value(coordination::release(home, &id, &about, claim)?).unwrap()
                }
            };
            println!("{}", serde_json::to_string(&value).unwrap());
            Ok(())
        }
        Cmd::Inbox {
            since,
            new,
            json: as_json,
            wait,
        } => {
            let id = Identity::load(home)?;
            let start = if new { load_cursor(home) } else { since };
            let msgs = client::inbox(&id, start, wait)?;
            let max_gseq = agent_surface::next_cursor(start, &msgs);
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string(&agent_surface::inbox_json(home, &id, max_gseq, msgs))
                        .unwrap()
                );
            } else {
                let (visible, held, _) = agent_surface::partition(home, &id, msgs);
                for s in &visible {
                    println!("{}", fmt(&id, s, false));
                }
                if !held.is_empty() {
                    eprintln!(
                        "({} held from unknown senders — review with `ecco requests`)",
                        held.len()
                    );
                }
            }
            if new {
                save_cursor(home, max_gseq)?;
            }
            Ok(())
        }
        Cmd::Watch { since } => {
            let id = Identity::load(home)?;
            let mut cursor = since.unwrap_or_else(|| load_cursor(home));
            eprintln!(
                "watching inbox for {} from #{cursor} (ctrl-c to stop)",
                id.addr()
            );
            loop {
                let batch = client::inbox(&id, cursor, 25)?;
                let max_gseq = batch.iter().map(|s| s.gseq).max();
                let (visible, held, _) = agent_surface::partition(home, &id, batch);
                for s in &visible {
                    println!("{}", fmt(&id, s, false));
                }
                for s in &held {
                    eprintln!(
                        "held: [{}] from {} — review with `ecco requests`",
                        s.env.kind, s.env.from
                    );
                }
                if let Some(m) = max_gseq {
                    cursor = cursor.max(m);
                    save_cursor(home, cursor)?;
                }
            }
        }
        Cmd::Log {
            about,
            json: as_json,
        } => {
            let id = Identity::load(home)?;
            let mut msgs = client::thread(&id, &about, 0, 0)?;
            msgs.sort_by_key(|s| s.tseq);
            if as_json {
                println!(
                    "{}",
                    serde_json::to_string(&agent_surface::log_json(home, &id, msgs)).unwrap()
                );
            } else {
                let contacts = identity::contacts_load(home);
                let me = id.addr();
                for s in msgs {
                    match identity::standing(&contacts, &me, &s.env.from) {
                        identity::Standing::Blocked => {}
                        st => println!("{}", fmt(&id, &s, st == identity::Standing::Unknown)),
                    }
                }
            }
            Ok(())
        }
        Cmd::Requests => {
            let id = Identity::load(home)?;
            let msgs = client::inbox(&id, 0, 0)?;
            let (_, held, _) = agent_surface::partition(home, &id, msgs);
            if held.is_empty() {
                println!("no pending contact requests");
                return Ok(());
            }
            for s in &held {
                println!("{}", fmt(&id, s, true));
            }
            eprintln!("approve with `ecco trust <addr>`; drop with `ecco block <addr>`");
            Ok(())
        }
        Cmd::Trust { addr } => {
            let id = Identity::load(home)?;
            identity::contacts_set(home, &addr, "approved")?;
            println!("trusted {addr}");
            let msgs = client::inbox(&id, 0, 0)?;
            for s in msgs.iter().filter(|s| s.env.from == addr) {
                println!("{}", fmt(&id, s, false));
            }
            Ok(())
        }
        Cmd::Block { addr } => {
            identity::contacts_set(home, &addr, "blocked")?;
            println!("blocked {addr}");
            Ok(())
        }
        Cmd::Pending => {
            let id = Identity::load(home)?;
            let pending = pending_proposals(home, &id)?;
            if pending.is_empty() {
                println!("nothing pending");
            }
            for s in pending {
                println!("{}", fmt(&id, &s, false));
            }
            Ok(())
        }
        Cmd::Approve { id: target } => decide(home, &target, "approves"),
        Cmd::Reject { id: target } => decide(home, &target, "rejects"),
        Cmd::Mcp => mcp::run(home),
        Cmd::Resolve { addr } => {
            let own = Identity::load(home).ok();
            let token = own.as_ref().and_then(|id| token_for(id, &addr));
            let profile = client::resolve(&addr, token)?;
            println!("{}", serde_json::to_string_pretty(&profile).unwrap());
            Ok(())
        }
        Cmd::Whoami => {
            let id = Identity::load(home)?;
            println!("{}", id.addr());
            println!("relay: {}", id.relay);
            println!(
                "root:  {}",
                envelope::encode_key(&id.root_key().verifying_key())
            );
            println!(
                "agent: {}",
                envelope::encode_key(&id.agent_key().verifying_key())
            );
            Ok(())
        }
        Cmd::Status { json: _ } => {
            println!("{}", serde_json::to_string(&local_status(home)).unwrap());
            Ok(())
        }
        Cmd::Deactivate => {
            let id = Identity::load(home)?;
            client::publish(&id, &id.profile_revoked())?;
            println!("deactivated {}", id.addr());
            println!("the agent key no longer signs or reads as this address");
            println!(
                "the name stays reserved by your root key; identity.json is kept at {}",
                home.display()
            );
            Ok(())
        }
    }
}

/// Build, sign (agent key — or root key for decisions), and submit an envelope.
/// Sending to an address implies trusting it (README §4) — unless blocked.
/// With `encrypt`, the body is sealed to each recipient's root key plus our own
/// resolution failure is an error — we never fall back to plaintext.
fn post(
    home: &Path,
    id: &Identity,
    about: String,
    kind: String,
    body: serde_json::Value,
    to: Vec<String>,
    encrypt: bool,
) -> Result<client::Receipt, String> {
    post_idempotent(
        home,
        id,
        SendInput {
            about,
            kind,
            body,
            to,
            encrypt,
        },
        None,
    )
}

#[derive(Serialize)]
struct SendInput {
    about: String,
    kind: String,
    body: Value,
    to: Vec<String>,
    encrypt: bool,
}

fn post_idempotent(
    home: &Path,
    id: &Identity,
    input: SendInput,
    idempotency_key: Option<&str>,
) -> Result<client::Receipt, String> {
    if let Some(key) = idempotency_key {
        let logical = serde_json::to_vec(&json!({
            "from": id.addr(), "send": input
        }))
        .expect("logical send input is serializable");
        let input_hash = blake3::hash(&logical).to_hex().to_string();
        let env = outbox::reserve(home, key, &input_hash, || build_envelope(home, id, input))?;
        return client::send(id, &env);
    }
    let env = build_envelope(home, id, input)?;
    client::send(id, &env)
}

fn post_envelope(
    home: &Path,
    id: &Identity,
    about: String,
    kind: String,
    body: serde_json::Value,
    to: Vec<String>,
    encrypt: bool,
) -> Result<(Envelope, client::Receipt), String> {
    let env = build_envelope(
        home,
        id,
        SendInput {
            about,
            kind,
            body,
            to,
            encrypt,
        },
    )?;
    let receipt = client::send(id, &env)?;
    Ok((env, receipt))
}

fn build_envelope(home: &Path, id: &Identity, input: SendInput) -> Result<Envelope, String> {
    let SendInput {
        about,
        kind,
        body,
        to,
        encrypt,
    } = input;
    let contacts = identity::contacts_load(home);
    for addr in &to {
        if identity::standing(&contacts, &id.addr(), addr) == identity::Standing::Unknown {
            identity::contacts_set(home, addr, "approved")?;
        }
    }
    let body = if encrypt {
        if kind == "decision" {
            return Err("decisions stay plaintext — they are the audit layer (README §6)".into());
        }
        let mut recipients = vec![(id.addr(), id.root_key().verifying_key())];
        for addr in &to {
            if *addr == id.addr() {
                continue;
            }
            let profile = client::resolve(addr, token_for(id, addr))?;
            recipients.push((addr.clone(), envelope::decode_key(&profile.root)?));
        }
        envelope::seal_body(&body, &recipients)?
    } else {
        body
    };
    // An unreadable thread (auth-v0 non-participant) yields empty prev. The
    // relay then refuses the post unless the anchor is still empty (README §5).
    let prev = client::thread(id, &about, 0, 0)
        .unwrap_or_default()
        .iter()
        .max_by_key(|s| s.tseq)
        .map(|s| vec![s.env.id.clone()])
        .unwrap_or_default();
    let key = if kind == "decision" {
        id.root_key()
    } else {
        id.agent_key()
    };
    let env = Envelope::seal(
        about,
        body,
        id.addr(),
        kind,
        prev,
        to,
        envelope::now(),
        &key,
    );
    Ok(env)
}

fn message_body(text: String, in_reply_to: Option<String>) -> Value {
    match in_reply_to {
        Some(id) => json!({ "text": text, "in_reply_to": id }),
        None => json!({ "text": text }),
    }
}

#[derive(Serialize)]
struct LocalStatus {
    schema: &'static str,
    ready: bool,
    identity: LocalIdentityStatus,
}

#[derive(Serialize)]
struct LocalIdentityStatus {
    state: &'static str,
    address: Option<String>,
    relay: Option<String>,
}

fn local_status(home: &Path) -> LocalStatus {
    let path = home.join("identity.json");
    let identity = if !path.exists() {
        LocalIdentityStatus {
            state: "missing",
            address: None,
            relay: None,
        }
    } else {
        match Identity::load(home) {
            Ok(id) => LocalIdentityStatus {
                state: "ready",
                address: Some(id.addr()),
                relay: Some(id.relay),
            },
            Err(_) => LocalIdentityStatus {
                state: "invalid",
                address: None,
                relay: None,
            },
        }
    };
    LocalStatus {
        schema: "ecco-status-v1",
        ready: identity.state == "ready",
        identity,
    }
}

/// A decision is the human ruling on a proposal: signed by the root key, never the agent's.
fn decide(home: &Path, target: &str, verb: &str) -> Result<(), String> {
    let id = Identity::load(home)?;
    let proposal = pending_proposals(home, &id)?
        .into_iter()
        .find(|s| s.env.id == target || s.env.id.trim_start_matches("b3:").starts_with(target))
        .ok_or_else(|| format!("no pending proposal matching '{target}'"))?;
    let mut body = serde_json::Map::new();
    body.insert(verb.into(), json!(proposal.env.id));
    body.insert(
        "text".into(),
        json!(format!("{verb} {}", short(&proposal.env.id))),
    );
    let receipt = post(
        home,
        &id,
        proposal.env.about.clone(),
        "decision".into(),
        serde_json::Value::Object(body),
        vec![proposal.env.from.clone()],
        false,
    )?;
    println!("{}", serde_json::to_string(&receipt).unwrap());
    Ok(())
}

/// Proposals from trusted senders whose thread does not yet contain a decision.
fn pending_proposals(home: &Path, id: &Identity) -> Result<Vec<Stored>, String> {
    let msgs = client::inbox(id, 0, 0)?;
    let (visible, _, _) = agent_surface::partition(home, id, msgs);
    let mut pending = Vec::new();
    for s in visible.into_iter().filter(|s| s.env.kind == "proposal") {
        let decided = client::thread(id, &s.env.about, 0, 0)?.iter().any(|t| {
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
fn load_cursor(home: &Path) -> u64 {
    std::fs::read_to_string(home.join("cursor"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn save_cursor(home: &Path, cursor: u64) -> Result<(), String> {
    std::fs::write(home.join("cursor"), cursor.to_string()).map_err(|e| e.to_string())
}

fn dm_thread(own: &str, to: &[String]) -> String {
    let mut addrs: Vec<&str> = to.iter().map(String::as_str).collect();
    addrs.push(own);
    addrs.sort();
    addrs.dedup();
    format!("dm:{}", addrs.join(","))
}

/// Our bearer token, but only for addresses on our own relay — a token must
/// never travel to a foreign relay.
fn token_for<'a>(id: &'a Identity, addr: &str) -> Option<&'a str> {
    addr.rsplit_once('@')
        .filter(|(_, auth)| *auth == identity::authority(&id.relay))
        .and(id.token.as_deref())
}

fn fmt(id: &Identity, s: &Stored, untrusted: bool) -> String {
    let (body, encrypted) = agent_surface::resolved_body(id, s);
    let text = body.get("text").and_then(|t| t.as_str()).unwrap_or("");
    let tag = if untrusted { "[untrusted] " } else { "" };
    let lock = if encrypted { "[enc] " } else { "" };
    format!(
        "#{:<3} {tag}{lock}[{}] {} · {} · {} ({} t={})",
        s.tseq,
        s.env.kind,
        s.env.from,
        s.env.about,
        text,
        short(&s.env.id),
        s.received_at
    )
}

fn short(id: &str) -> String {
    id.trim_start_matches("b3:").chars().take(8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_home() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ecco-main-test-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn cli_accepts_machine_message_contract_flags() {
        let cli = Cli::try_parse_from(["ecco", "inbox", "--json", "--since", "9", "--wait", "25"])
            .unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Inbox {
                since: 9,
                new: false,
                json: true,
                wait: 25
            }
        ));
        let cli =
            Cli::try_parse_from(["ecco", "send", "done", "--in-reply-to", "b3:request"]).unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Send {
                in_reply_to: Some(ref id),
                ..
            } if id == "b3:request"
        ));
        let cli = Cli::try_parse_from(["ecco", "send", "done", "--idempotency-key", "dispatch:42"])
            .unwrap();
        assert!(matches!(
            cli.cmd,
            Cmd::Send { idempotency_key: Some(ref key), .. } if key == "dispatch:42"
        ));
        assert!(
            Cli::try_parse_from(["ecco", "send", "done", "--idempotency-key", "bad key",]).is_err()
        );
        assert!(matches!(
            Cli::try_parse_from(["ecco", "log", "topic", "--json"])
                .unwrap()
                .cmd,
            Cmd::Log { json: true, .. }
        ));
        assert!(matches!(
            Cli::try_parse_from(["ecco", "status", "--json"])
                .unwrap()
                .cmd,
            Cmd::Status { json: true }
        ));
    }

    #[test]
    fn status_is_local_stable_and_redacted() {
        let home = temp_home();
        let missing = serde_json::to_value(local_status(&home)).unwrap();
        assert_eq!(missing["schema"], "ecco-status-v1");
        assert_eq!(missing["ready"], false);
        assert_eq!(missing["identity"]["state"], "missing");

        let id = Identity::generate(
            "alice",
            "https://relay.example",
            Some("do-not-print".into()),
        );
        id.save(&home).unwrap();
        let ready = serde_json::to_value(local_status(&home)).unwrap();
        assert_eq!(ready["ready"], true);
        assert_eq!(ready["identity"]["address"], "alice@relay.example");
        let output = ready.to_string();
        assert!(!output.contains("do-not-print"));
        assert!(!output.contains(&id.root_secret));
        assert!(!output.contains(&id.agent_secret));

        std::fs::write(home.join("identity.json"), "{bad").unwrap();
        let invalid = serde_json::to_value(local_status(&home)).unwrap();
        assert_eq!(invalid["identity"]["state"], "invalid");
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn reply_field_is_optional() {
        assert_eq!(
            message_body("done".into(), Some("b3:req".into())),
            json!({"text":"done","in_reply_to":"b3:req"})
        );
        assert_eq!(message_body("done".into(), None), json!({"text":"done"}));
    }
}
