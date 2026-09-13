//! Verify original scoped checkpoint statements. Signatures do not prove completeness or time.
use crate::{
    envelope,
    federation::{self, is_digest, is_hex64},
};
use serde_json::{json, Value};

const SCHEMA: &str = "ecco.evidence-checkpoint/v1";
const WITNESS_SCHEMA: &str = "ecco.checkpoint-witness/v1";

fn text<'a>(v: &'a Value, field: &str) -> Result<&'a str, String> {
    v.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("invalid checkpoint {field}"))
}
fn uint(v: &Value, field: &str) -> Result<u64, String> {
    v.get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("invalid checkpoint {field}"))
}

/// Verify a statement against an independently accepted source key, without asserting continuity.
/// Unknown signed fields remain part of the original signature and document digest.
pub fn verify_statement(value: &Value, key: &str) -> Result<(), String> {
    envelope::validate_json(value)?;
    let scope = text(value, "scope")?;
    let audience = text(value, "audience")?;
    if text(value, "schema")? != SCHEMA
        || text(value, "key")? != key
        || [scope, audience]
            .iter()
            .any(|s| s.is_empty() || s.encode_utf16().count() > 2048)
    {
        return Err("invalid checkpoint scope".into());
    }
    uint(value, "sequence")?;
    uint(value, "observedAt")?;
    match value.get("previous") {
        Some(Value::Null) => (),
        Some(Value::String(s)) if s.strip_prefix("b3:").is_some_and(is_hex64) => (),
        _ => return Err("invalid checkpoint predecessor".into()),
    }
    let events = value["events"]
        .as_array()
        .ok_or("invalid checkpoint events")?;
    let ids: Vec<&str> = events
        .iter()
        .map(|v| v.as_str().ok_or("invalid checkpoint event"))
        .collect::<Result<_, _>>()?;
    if ids.len() > 10_000
        || !ids.iter().all(|s| is_digest(s))
        || ids.windows(2).any(|pair| pair[0] >= pair[1])
        || text(value, "commitment")?
            != federation::digest(&json!({"scope":scope,"audience":audience,"events":events}))
    {
        return Err("checkpoint manifest mismatch".into());
    }
    federation::verify_signed(value, key)
}

/// Verify a genesis or one contiguous edge. Callers must retain and verify the whole chain.
/// Forks and cumulative-manifest retractions are valid signed evidence, not signature errors.
pub fn verify(value: &Value, key: &str, previous: Option<&Value>) -> Result<(), String> {
    verify_statement(value, key)?;
    if let Some(p) = previous {
        verify_statement(p, key)?;
        if value["scope"] != p["scope"]
            || value["audience"] != p["audience"]
            || uint(value, "sequence")? != uint(p, "sequence")? + 1
            || text(value, "previous")? != federation::digest(p)
            || uint(value, "observedAt")? < uint(p, "observedAt")?
        {
            return Err("checkpoint continuity mismatch".into());
        }
    } else if value["previous"] != Value::Null || uint(value, "sequence")? != 0 {
        return Err("previous checkpoint required".into());
    }
    Ok(())
}

/// Authenticate an independently pinned witness's custody and clock claim, retaining the original.
pub fn verify_witness(
    checkpoint: &Value,
    receipt: &Value,
    policy: &Value,
    now: u64,
) -> Result<(), String> {
    envelope::validate_json(receipt)?;
    let source = text(policy, "source")?;
    let witness = text(policy, "witness")?;
    verify_statement(checkpoint, source)?;
    if source == witness
        || text(receipt, "schema")? != WITNESS_SCHEMA
        || text(receipt, "checkpoint")? != federation::digest(checkpoint)
        || ["source", "witness", "scope", "audience"]
            .iter()
            .any(|k| receipt[k] != policy[k])
        || checkpoint["scope"] != policy["scope"]
        || checkpoint["audience"] != policy["audience"]
        || uint(receipt, "receivedAt")? < uint(checkpoint, "observedAt")?
        || uint(receipt, "receivedAt")? > now
    {
        return Err("witness original, scope or time mismatch".into());
    }
    federation::verify_signed(receipt, witness)
}
