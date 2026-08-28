//! Generic work coordination, evaluated only from signed thread messages.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

use crate::client::{self, Receipt, Stored};
use crate::identity::Identity;

pub const DEFAULT_TTL_SECONDS: u64 = 1800;
pub const MAX_TTL_SECONDS: u64 = 24 * 60 * 60;
pub const CLAIM_LOST_PREFIX: &str = "CLAIM_LOST:";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveClaim {
    pub branch: Option<String>,
    pub claim_id: String,
    pub expires_at: u64,
    pub from: String,
    pub round_after: Option<String>,
    pub text: Option<String>,
    pub tseq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkStatus {
    pub about: String,
    pub active: Option<ActiveClaim>,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResult {
    pub about: String,
    pub claim: ActiveClaim,
    pub receipt: Receipt,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseResult {
    pub about: String,
    pub claim_id: Option<String>,
    pub receipt: Option<Receipt>,
    pub released: bool,
    pub state: String,
}

#[derive(Debug, Deserialize)]
struct ClaimBody {
    claim_id: String,
    #[serde(default)]
    after: Option<String>,
    ttl_seconds: u64,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    renewal_of: Option<String>,
}

/// Evaluate messages in verified relay thread-sequence order. The first claim
/// in a round is the permanent winner of that round; it is never promoted from
/// a losing claim. Only the winner's sender can renew or release it.
pub fn evaluate(about: &str, messages: &[Stored], now: u64) -> Result<WorkStatus, String> {
    let mut ordered: Vec<&Stored> = messages.iter().collect();
    ordered.sort_by_key(|s| s.tseq);
    let mut winner: Option<ActiveClaim> = None;
    let mut released = false;
    for stored in ordered {
        stored.env.verify()?;
        if stored.env.about != about {
            return Err("coordination message belongs to a different thread".into());
        }
        if let Some(body) = parse_claim(stored) {
            if !(1..=MAX_TTL_SECONDS).contains(&body.ttl_seconds) {
                continue;
            }
            match &mut winner {
                None if body.renewal_of.is_none() => {
                    winner = Some(ActiveClaim {
                        branch: body.branch,
                        claim_id: body.claim_id,
                        expires_at: stored.received_at.saturating_add(body.ttl_seconds),
                        from: stored.env.from.clone(),
                        round_after: body.after,
                        text: body.text,
                        tseq: stored.tseq,
                    });
                    released = false;
                }
                Some(w)
                    if !released
                        && stored.received_at < w.expires_at
                        && body.after == w.round_after
                        && stored.env.from == w.from
                        && body.claim_id == w.claim_id
                        && body.renewal_of.as_deref() == Some(w.claim_id.as_str()) =>
                {
                    w.expires_at = stored.received_at.saturating_add(body.ttl_seconds);
                    w.branch = body.branch.or_else(|| w.branch.clone());
                    w.text = body.text.or_else(|| w.text.clone());
                }
                Some(w)
                    if body.renewal_of.is_none()
                        && body.after != w.round_after
                        && (released || w.expires_at <= stored.received_at) =>
                {
                    *w = ActiveClaim {
                        branch: body.branch,
                        claim_id: body.claim_id,
                        expires_at: stored.received_at.saturating_add(body.ttl_seconds),
                        from: stored.env.from.clone(),
                        round_after: body.after,
                        text: body.text,
                        tseq: stored.tseq,
                    };
                    released = false;
                }
                _ => {}
            }
        } else if stored.env.kind == "release" {
            if let (Some(w), Some(claim)) = (
                winner.as_ref(),
                stored.env.body.get("claim_id").and_then(Value::as_str),
            ) {
                if stored.env.from == w.from && claim == w.claim_id {
                    released = true;
                }
            }
        }
    }
    let active = winner.filter(|w| !released && w.expires_at > now);
    Ok(WorkStatus {
        about: about.into(),
        state: if active.is_some() {
            "claimed"
        } else {
            "unclaimed"
        }
        .into(),
        active,
    })
}

fn parse_claim(stored: &Stored) -> Option<ClaimBody> {
    (stored.env.kind == "claim")
        .then(|| serde_json::from_value(stored.env.body.clone()).ok())
        .flatten()
}

pub fn status(id: &Identity, about: &str) -> Result<WorkStatus, String> {
    let messages = verified_thread(id, about)?;
    evaluate(about, &messages, crate::envelope::now())
}

pub fn claim(
    home: &Path,
    id: &Identity,
    about: &str,
    to: Vec<String>,
    branch: Option<String>,
    ttl_seconds: u64,
    text: Option<String>,
) -> Result<ClaimResult, String> {
    validate_ttl(ttl_seconds)?;
    validate_recipients(id, &to)?;
    let messages = verified_thread(id, about)?;
    let current = evaluate(about, &messages, crate::envelope::now())?;
    if let Some(active) = current.active.clone() {
        if active.from != id.addr() {
            return Err(format!(
                "CLAIM_LOST:{}",
                serde_json::to_string(&current).unwrap()
            ));
        }
        return send_claim(
            home,
            id,
            about,
            to,
            branch,
            ttl_seconds,
            text,
            active.round_after,
            active.claim_id.clone(),
            Some(active.claim_id),
        );
    }
    let after = messages
        .iter()
        .max_by_key(|s| s.tseq)
        .map(|s| s.env.id.clone());
    let mut bytes = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    send_claim(
        home,
        id,
        about,
        to,
        branch,
        ttl_seconds,
        text,
        after,
        format!("claim:{}", hex::encode(bytes)),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn send_claim(
    home: &Path,
    id: &Identity,
    about: &str,
    to: Vec<String>,
    branch: Option<String>,
    ttl_seconds: u64,
    text: Option<String>,
    after: Option<String>,
    claim_id: String,
    renewal_of: Option<String>,
) -> Result<ClaimResult, String> {
    let body = json!({ "after": after, "branch": branch, "claim_id": claim_id, "renewal_of": renewal_of, "text": text, "ttl_seconds": ttl_seconds });
    let (env, receipt) =
        crate::post_envelope(home, id, about.into(), "claim".into(), body, to, false)?;
    let messages = verified_thread(id, about)?;
    bind_receipt(&receipt, &env, about, &messages)?;
    let status = evaluate(about, &messages, crate::envelope::now())?;
    let Some(active) = status.active.clone() else {
        return Err(format!(
            "CLAIM_LOST:{}",
            serde_json::to_string(&status).unwrap()
        ));
    };
    if active.claim_id != claim_id || active.from != id.addr() {
        return Err(format!(
            "CLAIM_LOST:{}",
            serde_json::to_string(&status).unwrap()
        ));
    }
    Ok(ClaimResult {
        about: about.into(),
        claim: active,
        receipt,
        state: "claimed".into(),
    })
}

pub fn release(
    home: &Path,
    id: &Identity,
    about: &str,
    claim_id: Option<String>,
) -> Result<ReleaseResult, String> {
    let current = status(id, about)?;
    let Some(active) = current.active else {
        return Ok(ReleaseResult {
            about: about.into(),
            claim_id,
            receipt: None,
            released: false,
            state: "unclaimed".into(),
        });
    };
    if active.from != id.addr() {
        return Ok(ReleaseResult {
            about: about.into(),
            claim_id: Some(active.claim_id),
            receipt: None,
            released: false,
            state: "owned_by_other".into(),
        });
    }
    if claim_id.as_ref().is_some_and(|c| c != &active.claim_id) {
        return Err("claim does not match the active owner claim".into());
    }
    let target = active.claim_id;
    let (env, receipt) = crate::post_envelope(
        home,
        id,
        about.into(),
        "release".into(),
        json!({ "claim_id": target }),
        Vec::new(),
        false,
    )?;
    let messages = verified_thread(id, about)?;
    bind_receipt(&receipt, &env, about, &messages)?;
    Ok(ReleaseResult {
        about: about.into(),
        claim_id: Some(target),
        receipt: Some(receipt),
        released: true,
        state: "unclaimed".into(),
    })
}

fn verified_thread(id: &Identity, about: &str) -> Result<Vec<Stored>, String> {
    let messages = client::thread(id, about, 0, 0)?;
    for stored in &messages {
        stored.env.verify()?;
        if stored.env.about != about {
            return Err("relay returned an envelope from a different thread".into());
        }
    }
    Ok(messages)
}

fn bind_receipt(
    receipt: &Receipt,
    env: &crate::envelope::Envelope,
    about: &str,
    messages: &[Stored],
) -> Result<(), String> {
    let accepted = messages.iter().any(|stored| {
        stored.gseq == receipt.gseq
            && stored.tseq == receipt.tseq
            && stored.received_at == receipt.received_at
            && stored.env.id == receipt.id
            && stored.env.id == env.id
            && stored.env.about == about
    });
    accepted
        .then_some(())
        .ok_or_else(|| "relay receipt does not match the fetched stored row".into())
}

fn validate_recipients(id: &Identity, to: &[String]) -> Result<(), String> {
    let own_authority = crate::identity::authority(&id.relay);
    for addr in to {
        let (_, authority) = addr
            .split_once('@')
            .ok_or_else(|| format!("'{addr}' is not name@authority"))?;
        if authority != own_authority {
            return Err(format!(
                "work claim recipient '{addr}' is not on thread relay '{own_authority}'"
            ));
        }
    }
    Ok(())
}

fn validate_ttl(ttl_seconds: u64) -> Result<(), String> {
    if (1..=MAX_TTL_SECONDS).contains(&ttl_seconds) {
        Ok(())
    } else {
        Err(format!(
            "ttl_seconds must be between 1 and {MAX_TTL_SECONDS}"
        ))
    }
}

pub fn claim_lost_json(error: &str) -> Option<&str> {
    error.strip_prefix(CLAIM_LOST_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn msg(key: &SigningKey, from: &str, kind: &str, body: Value, tseq: u64, at: u64) -> Stored {
        Stored {
            gseq: tseq,
            tseq,
            received_at: at,
            env: crate::envelope::Envelope::seal(
                "gh:owner/repo/issue/123".into(),
                body,
                from.into(),
                kind.into(),
                vec![],
                vec![],
                1,
                key,
            ),
        }
    }

    fn claim(key: &SigningKey, from: &str, id: &str, tseq: u64, at: u64) -> Stored {
        msg(
            key,
            from,
            "claim",
            json!({"after":null,"branch":null,"claim_id":id,"renewal_of":null,"text":null,"ttl_seconds":10}),
            tseq,
            at,
        )
    }

    #[test]
    fn lowest_tseq_wins_and_loser_never_promotes() {
        let (a, b) = (
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
        );
        let mut messages = vec![claim(&b, "b@x", "b", 2, 100), claim(&a, "a@x", "a", 1, 100)];
        assert_eq!(
            evaluate("gh:owner/repo/issue/123", &messages, 101)
                .unwrap()
                .active
                .unwrap()
                .claim_id,
            "a"
        );
        messages.push(msg(&a, "a@x", "release", json!({"claim_id":"a"}), 3, 102));
        assert!(evaluate("gh:owner/repo/issue/123", &messages, 103)
            .unwrap()
            .active
            .is_none());
    }

    #[test]
    fn only_owner_releases() {
        let (a, b) = (
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
        );
        let messages = vec![
            claim(&a, "a@x", "a", 1, 100),
            msg(&b, "b@x", "release", json!({"claim_id":"a"}), 2, 101),
        ];
        assert!(evaluate("gh:owner/repo/issue/123", &messages, 102)
            .unwrap()
            .active
            .is_some());
    }

    #[test]
    fn expiry_uses_received_at_and_owner_can_renew() {
        let a = SigningKey::generate(&mut OsRng);
        let mut messages = vec![claim(&a, "a@x", "a", 1, 100)];
        assert!(evaluate("gh:owner/repo/issue/123", &messages, 110)
            .unwrap()
            .active
            .is_none());
        messages.push(msg(&a, "a@x", "claim", json!({"after":null,"branch":null,"claim_id":"a","renewal_of":"a","text":null,"ttl_seconds":20}), 2, 105));
        assert_eq!(
            evaluate("gh:owner/repo/issue/123", &messages, 110)
                .unwrap()
                .active
                .unwrap()
                .expires_at,
            125
        );
    }

    #[test]
    fn late_old_round_renewal_cannot_replace_a_new_round() {
        let (a, b) = (
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
        );
        let mut messages = vec![claim(&a, "a@x", "a", 1, 100)];
        messages.push(msg(
            &b,
            "b@x",
            "claim",
            json!({"after":"head-2","branch":null,"claim_id":"b","renewal_of":null,"text":null,"ttl_seconds":20}),
            2,
            111,
        ));
        messages.push(msg(
            &a,
            "a@x",
            "claim",
            json!({"after":null,"branch":null,"claim_id":"a","renewal_of":"a","text":null,"ttl_seconds":100}),
            3,
            112,
        ));
        assert_eq!(
            evaluate("gh:owner/repo/issue/123", &messages, 113)
                .unwrap()
                .active
                .unwrap()
                .claim_id,
            "b"
        );
    }

    #[test]
    fn expired_claim_cannot_be_renewed() {
        let a = SigningKey::generate(&mut OsRng);
        let messages = vec![
            claim(&a, "a@x", "a", 1, 100),
            msg(
                &a,
                "a@x",
                "claim",
                json!({"after":null,"branch":null,"claim_id":"a","renewal_of":"a","text":null,"ttl_seconds":20}),
                2,
                110,
            ),
        ];
        assert!(evaluate("gh:owner/repo/issue/123", &messages, 111)
            .unwrap()
            .active
            .is_none());
    }

    #[test]
    fn invalid_ttls_are_ignored() {
        let a = SigningKey::generate(&mut OsRng);
        for ttl in [0, MAX_TTL_SECONDS + 1, u64::MAX] {
            let messages = vec![msg(
                &a,
                "a@x",
                "claim",
                json!({"after":null,"claim_id":"a","ttl_seconds":ttl}),
                1,
                100,
            )];
            assert!(evaluate("gh:owner/repo/issue/123", &messages, 101)
                .unwrap()
                .active
                .is_none());
        }
        assert!(validate_ttl(0).is_err());
        assert!(validate_ttl(MAX_TTL_SECONDS + 1).is_err());
        assert!(validate_ttl(MAX_TTL_SECONDS).is_ok());
    }

    #[test]
    fn a_new_round_starts_after_release_and_after_expiry() {
        let (a, b) = (
            SigningKey::generate(&mut OsRng),
            SigningKey::generate(&mut OsRng),
        );
        let released = vec![
            claim(&a, "a@x", "a", 1, 100),
            msg(&a, "a@x", "release", json!({"claim_id":"a"}), 2, 101),
            msg(
                &b,
                "b@x",
                "claim",
                json!({"after":"release-id","claim_id":"b","ttl_seconds":10}),
                3,
                102,
            ),
        ];
        assert_eq!(
            evaluate("gh:owner/repo/issue/123", &released, 103)
                .unwrap()
                .active
                .unwrap()
                .claim_id,
            "b"
        );
        let expired = vec![
            claim(&a, "a@x", "a", 1, 100),
            msg(
                &b,
                "b@x",
                "claim",
                json!({"after":"expired-head","claim_id":"b","ttl_seconds":10}),
                2,
                110,
            ),
        ];
        assert_eq!(
            evaluate("gh:owner/repo/issue/123", &expired, 111)
                .unwrap()
                .active
                .unwrap()
                .claim_id,
            "b"
        );
    }

    #[test]
    fn all_claim_recipients_must_share_the_home_relay() {
        let id = Identity::generate("alice", "https://relay.example", None);
        assert!(validate_recipients(&id, &["bob@relay.example".into()]).is_ok());
        assert!(validate_recipients(&id, &["bob@other.example".into()]).is_err());
        assert!(validate_recipients(&id, &[]).is_ok());
    }
}
