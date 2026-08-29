//! The contact-policy boundary for output that an agent can read.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

use crate::client::Stored;
use crate::envelope;
use crate::identity::{self, Identity};

pub(crate) fn inbox_json(home: &Path, id: &Identity, cursor: u64, messages: Vec<Stored>) -> Value {
    let (visible, held, rejected) = partition(home, id, messages);
    json!({
        "cursor": cursor.to_string(),
        "messages": visible.iter().map(|s| stored_json(id, s)).collect::<Vec<_>>(),
        "held": held_summaries(&held),
        "rejected": rejected_summaries(&rejected),
    })
}

pub(crate) fn log_json(home: &Path, id: &Identity, messages: Vec<Stored>) -> Value {
    let (visible, held, rejected) = partition(home, id, messages);
    json!({
        "messages": visible.iter().map(|s| stored_json(id, s)).collect::<Vec<_>>(),
        "held": held_summaries(&held),
        "rejected": rejected_summaries(&rejected),
    })
}

pub(crate) fn next_cursor(start: u64, messages: &[Stored]) -> u64 {
    messages
        .iter()
        .map(|stored| stored.gseq)
        .fold(start, u64::max)
}

/// Split messages into trusted, unknown, and blocked groups.
pub(crate) fn partition(
    home: &Path,
    id: &Identity,
    messages: Vec<Stored>,
) -> (Vec<Stored>, Vec<Stored>, Vec<Stored>) {
    let contacts = identity::contacts_load(home);
    let me = id.addr();
    let (mut visible, mut held, mut rejected) = (Vec::new(), Vec::new(), Vec::new());
    for stored in messages {
        match identity::standing(&contacts, &me, &stored.env.from) {
            identity::Standing::Trusted => visible.push(stored),
            identity::Standing::Unknown => held.push(stored),
            identity::Standing::Blocked => rejected.push(stored),
        }
    }
    (visible, held, rejected)
}

/// Decrypt a sealed body for local display; the bool reports encryption.
pub(crate) fn resolved_body(id: &Identity, stored: &Stored) -> (Value, bool) {
    let body = &stored.env.body;
    if envelope::is_encrypted(body) {
        match envelope::open_body(body, &id.addr(), &id.root_key()) {
            Some(value) => (value, true),
            None => (json!({ "text": "<encrypted: not sealed to you>" }), true),
        }
    } else {
        (body.clone(), false)
    }
}

/// Replace ciphertext with the local plaintext view after contact-policy checks.
pub(crate) fn stored_json(id: &Identity, stored: &Stored) -> Value {
    let mut value = serde_json::to_value(stored).unwrap();
    let (body, encrypted) = resolved_body(id, stored);
    if encrypted {
        value["env"]["body"] = body;
        value["env"]["encrypted"] = json!(true);
    }
    value
}

fn held_summaries(held: &[Stored]) -> Vec<Value> {
    let mut counts = BTreeMap::<(&str, &str), usize>::new();
    for stored in held {
        *counts
            .entry((&stored.env.from, &stored.env.kind))
            .or_default() += 1;
    }
    counts
        .into_iter()
        .map(|((sender, kind), count)| json!({ "sender": sender, "kind": kind, "count": count }))
        .collect()
}

fn rejected_summaries(rejected: &[Stored]) -> Vec<Value> {
    rejected
        .iter()
        .map(|stored| json!({ "id": stored.env.id, "reason": "sender is blocked" }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Envelope;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_home() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ecco-agent-surface-test-{}-{nonce}",
            std::process::id()
        ))
    }

    fn stored(id: &Identity, gseq: u64, from: &str, kind: &str, body: Value) -> Stored {
        let key = if from == id.addr() {
            id.agent_key()
        } else {
            Identity::generate(
                from.split('@').next().unwrap(),
                "http://localhost:4200",
                None,
            )
            .agent_key()
        };
        Stored {
            gseq,
            tseq: gseq,
            received_at: 1,
            env: Envelope::seal(
                "topic".into(),
                body,
                from.into(),
                kind.into(),
                vec![],
                vec![id.addr()],
                1,
                &key,
            ),
        }
    }

    #[test]
    fn filters_agent_output_and_keeps_the_cursor_monotonic() {
        let home = temp_home();
        let id = Identity::generate("me", "http://localhost:4200", None);
        id.save(&home).unwrap();
        identity::contacts_set(&home, "trusted@localhost:4200", "approved").unwrap();
        identity::contacts_set(&home, "blocked@localhost:4200", "blocked").unwrap();
        let messages = vec![
            stored(
                &id,
                4,
                "trusted@localhost:4200",
                "request",
                json!({"text":"ok"}),
            ),
            stored(
                &id,
                7,
                "unknown@localhost:4200",
                "request",
                json!({"text":"secret"}),
            ),
            stored(
                &id,
                6,
                "unknown@localhost:4200",
                "request",
                json!({"text":"secret2"}),
            ),
            stored(
                &id,
                5,
                "blocked@localhost:4200",
                "note",
                json!({"text":"drop"}),
            ),
        ];
        assert_eq!(next_cursor(9, &messages), 9);
        assert_eq!(next_cursor(0, &messages), 7);

        let inbox = inbox_json(&home, &id, 7, messages.clone());
        let log = log_json(&home, &id, messages);
        assert_eq!(inbox["cursor"], "7");
        assert_eq!(inbox["messages"].as_array().unwrap().len(), 1);
        assert_eq!(
            inbox["held"],
            json!([{"sender":"unknown@localhost:4200","kind":"request","count":2}])
        );
        assert_eq!(inbox["rejected"].as_array().unwrap().len(), 1);
        assert!(log.get("cursor").is_none());
        for output in [&inbox, &log] {
            let output = output.to_string();
            assert!(!output.contains("secret"));
            assert!(!output.contains("drop"));
        }
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn decrypts_visible_messages() {
        let id = Identity::generate("me", "http://localhost:4200", None);
        let sealed = envelope::seal_body(
            &json!({"text":"private"}),
            &[(id.addr(), id.root_key().verifying_key())],
        )
        .unwrap();
        let message = stored(&id, 1, &id.addr(), "finding", sealed);
        let value = stored_json(&id, &message);
        assert_eq!(value["env"]["body"]["text"], "private");
        assert_eq!(value["env"]["encrypted"], true);
    }
}
