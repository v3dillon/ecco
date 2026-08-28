//! `ecco mcp`: an MCP server over stdio, so any MCP-capable harness gets ecco
//! as native tools. Line-delimited JSON-RPC 2.0; no extra dependencies.
//!
//! The trust boundary holds here too: this surface is the *agent's*, so it can
//! propose but never sign a `decision` — approval stays a human CLI command.

use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;

use crate::client;
use crate::envelope;
use crate::identity::{self, Identity};

const TOOLS: &[&str] = &[
    "ecco_send",
    "ecco_inbox",
    "ecco_thread",
    "ecco_pending",
    "ecco_resolve",
    "ecco_whoami",
    "ecco_work_status",
    "ecco_work_claim",
    "ecco_work_release",
];

pub fn run(home: &Path) -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        // No id => notification; MCP forbids responding to those.
        let Some(id) = msg.get("id").filter(|v| !v.is_null()).cloned() else {
            continue;
        };
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
        let reply = match method {
            "initialize" => ok(&id, initialize(&params)),
            "ping" => ok(&id, json!({})),
            "tools/list" => ok(&id, json!({ "tools": tool_defs() })),
            "tools/call" => tools_call(home, &id, &params),
            _ => err(&id, -32601, &format!("method not found: {method}")),
        };
        let mut out = stdout.lock();
        writeln!(out, "{reply}").map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn initialize(params: &Value) -> Value {
    let version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or("2025-06-18");
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "ecco", "version": env!("CARGO_PKG_VERSION") }
    })
}

fn tools_call(home: &Path, id: &Value, params: &Value) -> String {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    if !TOOLS.contains(&name) {
        return err(id, -32602, &format!("unknown tool '{name}'"));
    }
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    match call(home, name, &args) {
        Ok(text) => ok(
            id,
            json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
        ),
        Err(e) => {
            let text = tool_error_text(&e);
            ok(
                id,
                json!({ "content": [{ "type": "text", "text": text }], "isError": true }),
            )
        }
    }
}

fn tool_error_text(error: &str) -> &str {
    crate::coordination::claim_lost_json(error).unwrap_or(error)
}

fn call(home: &Path, name: &str, args: &Value) -> Result<String, String> {
    let id = Identity::load(home)?;
    let str_arg = |k: &str| args.get(k).and_then(Value::as_str).map(str::to_string);
    match name {
        "ecco_whoami" => Ok(pretty(&json!({
            "addr": id.addr(),
            "relay": id.relay,
            "root": envelope::encode_key(&id.root_key().verifying_key()),
            "agent": envelope::encode_key(&id.agent_key().verifying_key()),
        }))),
        "ecco_send" => {
            let text = str_arg("text").ok_or("'text' is required")?;
            let kind = str_arg("kind").unwrap_or_else(|| "note".into());
            if kind == "decision" {
                return Err(
                    "decisions are human-only: ask your human to run `ecco approve <id>`".into(),
                );
            }
            if !envelope::KINDS.contains(&kind.as_str()) {
                return Err(format!("unknown kind '{kind}'"));
            }
            let to: Vec<String> = args
                .get("to")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let about = str_arg("about").unwrap_or_else(|| crate::dm_thread(&id.addr(), &to));
            let encrypt = args
                .get("encrypt")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            crate::post(home, &id, about, kind, json!({ "text": text }), to, encrypt)
                .and_then(|r| serde_json::to_string(&r).map_err(|e| e.to_string()))
        }
        "ecco_inbox" => {
            let new = args.get("new").and_then(Value::as_bool).unwrap_or(false);
            let since = if new {
                crate::load_cursor(home)
            } else {
                args.get("since").and_then(Value::as_u64).unwrap_or(0)
            };
            let msgs = client::inbox(&id, since, 0)?;
            if new {
                if let Some(max) = msgs.iter().map(|s| s.gseq).max() {
                    crate::save_cursor(home, max)?;
                }
            }
            let (visible, held) = crate::partition(home, &id, msgs);
            let mut out = serde_json::Map::new();
            let decrypted: Vec<Value> = visible.iter().map(|s| stored_json(&id, s)).collect();
            out.insert("msgs".into(), json!(decrypted));
            if !held.is_empty() {
                // Sender + kind only — held content never reaches the agent surface.
                let summary: Vec<Value> = held
                    .iter()
                    .map(|s| json!({ "from": s.env.from, "kind": s.env.kind }))
                    .collect();
                out.insert("held_for_human_review".into(), json!(summary));
                out.insert(
                    "note".into(),
                    json!("messages from unknown senders are held; your human reviews them with `ecco requests` and admits senders with `ecco trust <addr>`"),
                );
            }
            Ok(pretty(&Value::Object(out)))
        }
        "ecco_thread" => {
            let about = str_arg("about").ok_or("'about' is required")?;
            let mut msgs = client::thread(&id, &about, 0, 0)?;
            msgs.sort_by_key(|s| s.tseq);
            let contacts = identity::contacts_load(home);
            let me = id.addr();
            let annotated: Vec<Value> = msgs
                .iter()
                .filter_map(|s| match identity::standing(&contacts, &me, &s.env.from) {
                    identity::Standing::Blocked => None,
                    st => {
                        let mut v = stored_json(&id, s);
                        if st == identity::Standing::Unknown {
                            v["untrusted_sender"] = json!(true);
                        }
                        Some(v)
                    }
                })
                .collect();
            Ok(pretty(&json!(annotated)))
        }
        "ecco_pending" => {
            let pending = crate::pending_proposals(home, &id)?;
            let decrypted: Vec<Value> = pending.iter().map(|s| stored_json(&id, s)).collect();
            Ok(pretty(&json!(decrypted)))
        }
        "ecco_work_status" => {
            let about = str_arg("about").ok_or("'about' is required")?;
            Ok(pretty(
                &serde_json::to_value(crate::coordination::status(&id, &about)?).unwrap(),
            ))
        }
        "ecco_work_claim" => {
            let about = str_arg("about").ok_or("'about' is required")?;
            let to = args
                .get("to")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let ttl = args
                .get("ttl_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(crate::coordination::DEFAULT_TTL_SECONDS);
            let result = crate::coordination::claim(
                home,
                &id,
                &about,
                to,
                str_arg("branch"),
                ttl,
                str_arg("text"),
            )?;
            Ok(pretty(&serde_json::to_value(result).unwrap()))
        }
        "ecco_work_release" => {
            let about = str_arg("about").ok_or("'about' is required")?;
            let result = crate::coordination::release(home, &id, &about, str_arg("claim"))?;
            Ok(pretty(&serde_json::to_value(result).unwrap()))
        }
        "ecco_resolve" => {
            let addr = str_arg("addr").ok_or("'addr' is required")?;
            let profile = client::resolve(&addr, crate::token_for(&id, &addr))?;
            Ok(pretty(&serde_json::to_value(&profile).unwrap()))
        }
        _ => unreachable!("gated by TOOLS"),
    }
}

fn tool_defs() -> Value {
    let no_args = json!({ "type": "object", "properties": {} });
    json!([
        {
            "name": "ecco_send",
            "description": "Post a signed message to an ecco thread. Kinds: note (default); claim (announce you are starting work — check the thread for existing claims first); release (withdraw a claim); request (ask a collaborator's agent to act); finding (report a result); proposal (ask your human for a decision, then stop and wait). Decisions cannot be sent from this surface.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": { "type": "string" },
                    "to": { "type": "array", "items": { "type": "string" }, "description": "recipient addresses, name@authority" },
                    "about": { "type": "string", "description": "thread anchor, e.g. gh:owner/repo/pull/13; defaults to a DM thread with the recipients" },
                    "kind": { "type": "string", "enum": ["note", "claim", "release", "request", "finding", "proposal"] },
                    "encrypt": { "type": "boolean", "description": "seal the body to the recipients' root keys; the relay cannot read it" }
                },
                "required": ["text"]
            }
        },
        {
            "name": "ecco_inbox",
            "description": "Messages addressed to you. Pass new=true to get only unseen messages and advance the persisted cursor — recommended at session start. Messages from senders your human has not approved are withheld (sender summary only); admission is a human decision made outside this surface.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "new": { "type": "boolean" },
                    "since": { "type": "integer", "description": "explicit gseq cursor; ignored when new=true" }
                }
            }
        },
        {
            "name": "ecco_thread",
            "description": "Full history of one thread — the signed ledger for an artifact — oldest first.",
            "inputSchema": {
                "type": "object",
                "properties": { "about": { "type": "string" } },
                "required": ["about"]
            }
        },
        {
            "name": "ecco_pending",
            "description": "Proposals still awaiting a human decision. Surface these to your human; approval happens outside this surface via `ecco approve`.",
            "inputSchema": no_args
        },
        {
            "name": "ecco_resolve",
            "description": "Fetch and verify a collaborator's signed profile by address (name@authority). Use to confirm an address exists before sending.",
            "inputSchema": {
                "type": "object",
                "properties": { "addr": { "type": "string" } },
                "required": ["addr"]
            }
        },
        {
            "name": "ecco_whoami",
            "description": "Your own ecco address, relay, and public keys.",
            "inputSchema": no_args
        },
        {
            "name": "ecco_work_status",
            "description": "Return the deterministic active work claim for one thread anchor.",
            "inputSchema": { "type": "object", "properties": { "about": { "type": "string" } }, "required": ["about"] }
        },
        {
            "name": "ecco_work_claim",
            "description": "Claim work, or renew your active claim. The lowest relay thread sequence wins a round.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "about": { "type": "string" },
                    "to": { "type": "array", "items": { "type": "string" } },
                    "branch": { "type": "string" },
                    "ttl_seconds": { "type": "integer", "minimum": 1, "maximum": crate::coordination::MAX_TTL_SECONDS },
                    "text": { "type": "string" }
                },
                "required": ["about"]
            }
        },
        {
            "name": "ecco_work_release",
            "description": "Release your active work claim. Another sender cannot release it.",
            "inputSchema": {
                "type": "object",
                "properties": { "about": { "type": "string" }, "claim": { "type": "string" } },
                "required": ["about"]
            }
        }
    ])
}

/// Serialize a stored message, decrypting sealed bodies for the agent surface.
/// A decrypted body is marked "encrypted": true — the signature in the raw
/// envelope covers the ciphertext, not this client-side plaintext view.
fn stored_json(id: &Identity, s: &client::Stored) -> Value {
    let mut v = serde_json::to_value(s).unwrap();
    let (body, encrypted) = crate::resolved_body(id, &s.env);
    if encrypted {
        v["env"]["body"] = body;
        v["env"]["encrypted"] = json!(true);
    }
    v
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap()
}

fn ok(id: &Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn err(id: &Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_tools_have_shared_ttl_limit_and_claim_loss_json() {
        let defs = tool_defs();
        let claim = defs
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == "ecco_work_claim")
            .unwrap();
        assert_eq!(
            claim["inputSchema"]["properties"]["ttl_seconds"]["maximum"],
            crate::coordination::MAX_TTL_SECONDS
        );
        let status = r#"{"about":"gh:o/r/issue/1","active":null,"state":"unclaimed"}"#;
        let internal = format!("{}{}", crate::coordination::CLAIM_LOST_PREFIX, status);
        assert_eq!(tool_error_text(&internal), status);
        assert!(!tool_error_text(&internal).contains(crate::coordination::CLAIM_LOST_PREFIX));
    }
}
