//! Additive economic event profile inside a v0 envelope body.
//! This verifies assertion authority, never spending permission or fulfillment truth.
use crate::{envelope::Envelope, federation, identity::Profile};
use serde_json::Value;

pub const SCHEMA: &str = "ecco.economic-event/v1";

const TYPES: &[&str] = &[
    "identity_created",
    "operating_version_changed",
    "identity_verified",
    "key_rotated",
    "identity_recovered",
    "ownership_transferred",
    "delegation_created",
    "delegation_revoked",
    "authorization_granted",
    "intent_created",
    "offer_created",
    "offer_accepted",
    "interaction_started",
    "task_started",
    "artifact_delivered",
    "payment_authorized",
    "payment_settled",
    "fulfillment_acknowledged",
    "fulfillment_rejected",
    "refund",
    "chargeback",
    "dispute_opened",
    "evidence_submitted",
    "dispute_resolved",
    "external_attestation",
];

/// Events that stand alone rather than referring to an `interaction_started` event.
const STANDALONE: &[&str] = &[
    "identity_created",
    "operating_version_changed",
    "identity_verified",
    "key_rotated",
    "identity_recovered",
    "ownership_transferred",
    "delegation_created",
    "delegation_revoked",
    "authorization_granted",
    "external_attestation",
    "interaction_started",
];

/// Events only the controller (root) key may assert; a grant never covers them.
const CONTROLLER_ONLY: &[&str] = &[
    "identity_created",
    "operating_version_changed",
    "key_rotated",
    "identity_recovered",
    "ownership_transferred",
    "delegation_created",
    "delegation_revoked",
    "authorization_granted",
];

const PAYMENT: &[&str] = &[
    "payment_authorized",
    "payment_settled",
    "refund",
    "chargeback",
];

/// The economic event carried by `env`, if its body declares one under this schema.
pub fn event(env: &Envelope) -> Option<&Value> {
    let event = env.body.get("economic")?;
    (event["schema"] == SCHEMA).then_some(event)
}

fn native_payment(v: &Value) -> bool {
    let decimal =
        |s: &str| !s.is_empty() && !s.starts_with('0') && s.bytes().all(|c| c.is_ascii_digit());
    let network = v["network"]
        .as_str()
        .and_then(|s| s.strip_prefix("eip155:"))
        .is_some_and(|s| s.len() <= 15 && decimal(s));
    let addresses = ["asset", "payer", "payee"].iter().all(|k| {
        v[k].as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .is_some_and(|s| s.len() == 40 && s.bytes().all(|c| c.is_ascii_hexdigit()))
    });
    let maximum = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let value = v["value"].as_str().is_some_and(|s| {
        decimal(s) && (s.len() < maximum.len() || (s.len() == maximum.len() && s <= maximum))
    });
    network && addresses && value
}

fn hash(value: &Value) -> bool {
    value.as_str().is_some_and(federation::is_digest)
}

pub(crate) fn text(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| !s.is_empty() && s.len() <= 2048)
}

fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn money(value: &Value) -> Result<(), String> {
    require(
        value["unit"] == "minor" && value["exponent"].as_u64().is_some_and(|n| n <= 9),
        "explicit monetary units required",
    )?;
    require(
        value["currency"]
            .as_str()
            .is_some_and(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_uppercase())),
        "invalid currency",
    )?;
    require(
        value["value"].as_str().is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 38
                && s.bytes().all(|b| b.is_ascii_digit())
                && (s == "0" || !s.starts_with('0'))
        }),
        "amount must be an unsigned atomic decimal string",
    )
}

pub fn verify_assertion(env: &Envelope, profile: &Profile, at: u64) -> Result<(), String> {
    let Some(event) = env.body.get("economic") else {
        return Ok(());
    };
    require(
        event["schema"] == SCHEMA,
        "unsupported economic event schema",
    )?;
    let kind = event["type"]
        .as_str()
        .ok_or("economic event type required")?;
    require(
        TYPES.contains(&kind) && event["payload"].is_object(),
        "invalid economic event type/payload",
    )?;
    require(
        event["links"]
            .as_array()
            .is_some_and(|v| v.iter().all(hash)),
        "evidence links must be content hashes",
    )?;
    let payload = &event["payload"];
    require(
        event.get("interaction").is_none_or(hash),
        "invalid interaction reference",
    )?;
    require(
        event.get("principal").is_none_or(text),
        "invalid economic principal",
    )?;
    if kind == "identity_created" {
        if let Some(recovery) = payload.get("recovery") {
            let keys = recovery["keys"]
                .as_array()
                .ok_or("recovery keys required")?;
            let unique: std::collections::BTreeSet<_> =
                keys.iter().filter_map(Value::as_str).collect();
            require(
                !keys.is_empty()
                    && unique.len() == keys.len()
                    && keys.iter().all(|k| {
                        k.as_str()
                            .and_then(|s| s.strip_prefix("ed25519:"))
                            .is_some_and(federation::is_hex64)
                    })
                    && recovery["threshold"]
                        .as_u64()
                        .is_some_and(|n| n > 0 && n <= keys.len() as u64),
                "invalid inception recovery policy",
            )?;
            for field in ["delaySeconds", "contestSeconds"] {
                require(
                    recovery
                        .get(field)
                        .is_none_or(|v| v.as_u64().is_some_and(|n| n <= 2_592_000)),
                    "invalid recovery window",
                )?;
            }
        }
    }
    if kind == "interaction_started" {
        if let Some(policy) = payload.get("disputePolicy") {
            require(
                text(&payload["arbiter"])
                    && hash(&policy["procedureDigest"])
                    && text(&policy["appealArbiter"])
                    && policy["appealWindowSeconds"]
                        .as_u64()
                        .is_some_and(|n| n > 0 && n <= 2_592_000),
                "invalid contractual appeal policy",
            )?;
        }
        require(
            payload.get("nativePayment").is_none_or(native_payment),
            "invalid native payment terms",
        )?;
        money(&payload["amount"])?;
        let milestones = payload["milestones"]
            .as_array()
            .ok_or("milestones required")?;
        let unique: std::collections::BTreeSet<_> =
            milestones.iter().filter_map(Value::as_str).collect();
        require(
            text(&payload["buyer"])
                && text(&payload["seller"])
                && payload["buyer"] != payload["seller"]
                && hash(&payload["termsDigest"])
                && text(&payload["category"])
                && text(&payload["dueAt"])
                && payload["maturityDays"].as_u64().is_some_and(|n| n <= 3650)
                && !milestones.is_empty()
                && milestones.len() <= 100
                && unique.len() == milestones.len()
                && milestones.iter().all(text)
                && payload["amount"]["value"] != "0"
                && payload.get("sellerOperatingHead").is_none_or(hash),
            "invalid interaction terms",
        )?;
    }
    if kind.starts_with("dispute_") || kind == "evidence_submitted" {
        require(text(&payload["disputeId"]), "dispute ID required")?;
    }
    if kind == "dispute_resolved" {
        require(
            ["buyer", "seller", "partial", "withdrawn", "unresolved"]
                .contains(&payload["outcome"].as_str().unwrap_or("")),
            "unsupported dispute outcome",
        )?;
    }

    if !STANDALONE.contains(&kind) {
        require(
            hash(&event["interaction"]),
            "interaction reference required",
        )?;
    }
    if [
        "offer_accepted",
        "artifact_delivered",
        "fulfillment_acknowledged",
        "fulfillment_rejected",
    ]
    .contains(&kind)
    {
        require(hash(&payload["termsDigest"]), "exact terms digest required")?;
    }
    if [
        "artifact_delivered",
        "fulfillment_acknowledged",
        "fulfillment_rejected",
    ]
    .contains(&kind)
    {
        require(
            hash(&payload["artifactDigest"]) && text(&payload["milestone"]),
            "artifact and milestone required",
        )?;
    }
    if PAYMENT.contains(&kind) {
        money(&payload["amount"])?;
        let source = &payload["source"];
        require(
            ["provider", "account", "objectId", "observer", "method"]
                .iter()
                .all(|key| text(&source[key]))
                && (source["environment"] == "test" || source["environment"] == "live"),
            "explicit payment provenance required",
        )?;
    }
    if kind == "operating_version_changed" {
        require(
            (payload.get("previous").is_some_and(Value::is_null) || hash(&payload["previous"]))
                && hash(&payload["versionDigest"]),
            "operating version requires predecessor and configuration digest",
        )?;
        for component in ["modelDigest", "toolsDigest", "policyDigest"] {
            require(
                payload.get(component).is_none_or(hash),
                "invalid configuration component digest",
            )?;
        }
    }
    if env.key == profile.root {
        return Ok(());
    }
    require(
        !CONTROLLER_ONLY.contains(&kind),
        "controller transitions and grant issuance require the controller key",
    )?;
    let grant = &event["grant"];
    require(
        grant["schema"] == "ecco.evidence-grant/v1"
            && grant["issuer"] == profile.root
            && grant["key"] == env.key,
        "explicit evidence assertion grant required",
    )?;
    require(
        grant["types"]
            .as_array()
            .is_some_and(|v| v.iter().any(|t| t == kind))
            && grant["interaction"] == event["interaction"],
        "evidence grant scope mismatch",
    )?;
    require(
        grant["notBefore"].as_u64().is_some_and(|n| n <= at)
            && grant["expiresAt"].as_u64().is_some_and(|n| n > at),
        "evidence grant outside validity",
    )?;
    federation::verify_signed(grant, &profile.root)
}

#[cfg(test)]
mod tests {
    use super::native_payment;
    use serde_json::json;
    #[test]
    fn exact_native_units_never_accept_fiat_labels_overflow_or_ambiguous_addresses() {
        let mut terms = json!({"network":"eip155:8453","asset":format!("0x{}", "1".repeat(40)),"payer":format!("0x{}", "2".repeat(40)),"payee":format!("0x{}", "3".repeat(40)),"value":"1000000"});
        assert!(native_payment(&terms));
        terms["value"] =
            json!("115792089237316195423570985008687907853269984665640564039457584007913129639936");
        assert!(!native_payment(&terms));
        terms["value"] = json!("1.0");
        assert!(!native_payment(&terms));
        terms["value"] = json!("1000000");
        terms["network"] = json!("USD");
        assert!(!native_payment(&terms));
        terms["network"] = json!("eip155:8453");
        terms["payee"] = json!("vendor@example");
        assert!(!native_payment(&terms));
    }
}
