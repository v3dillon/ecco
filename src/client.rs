//! HTTP client for the relay API. README §5.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

use crate::envelope::{self, encode_key, Envelope};
use crate::evidence::{self, Bundle};
use crate::federation::ReceivedEvidence;
use crate::identity::{addr_relay_url, authority, request_signing_bytes, Identity, Profile};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stored {
    pub gseq: u64,
    pub tseq: u64,
    pub received_at: u64,
    pub env: Envelope,
}

/// A relay's signed acknowledgement of one accepted envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub gseq: u64,
    pub id: String,
    pub received_at: u64,
    pub relay: String,
    pub sig: String,
    pub tseq: u64,
}

#[derive(Serialize)]
struct ReceiptSigningView<'a> {
    gseq: u64,
    id: &'a str,
    received_at: u64,
    relay: &'a str,
    tseq: u64,
}

impl Receipt {
    pub fn sign(env: &Envelope, gseq: u64, tseq: u64, received_at: u64, key: &SigningKey) -> Self {
        let relay = encode_key(&key.verifying_key());
        let bytes = serde_json::to_vec(&ReceiptSigningView {
            gseq,
            id: &env.id,
            received_at,
            relay: &relay,
            tseq,
        })
        .unwrap();
        Self {
            gseq,
            id: env.id.clone(),
            received_at,
            relay,
            sig: format!("ed25519:{}", hex::encode(key.sign(&bytes).to_bytes())),
            tseq,
        }
    }

    /// Verify the self-contained relay signature and bind it to the sent envelope.
    pub fn verify(&self, env: &Envelope) -> Result<(), String> {
        if self.id != env.id {
            return Err("receipt does not identify the sent envelope".into());
        }
        let key = envelope::decode_key(&self.relay)?;
        let sig: [u8; 64] = envelope::decode_prefixed(&self.sig, "ed25519:")?
            .try_into()
            .map_err(|_| "bad receipt signature length".to_string())?;
        let bytes = serde_json::to_vec(&ReceiptSigningView {
            gseq: self.gseq,
            id: &self.id,
            received_at: self.received_at,
            relay: &self.relay,
            tseq: self.tseq,
        })
        .expect("canonical receipt encoding");
        key.verify(&bytes, &Signature::from_bytes(&sig))
            .map_err(|_| "bad receipt signature".to_string())
    }
}

#[derive(Debug, Deserialize)]
struct MsgsResponse {
    msgs: Vec<Stored>,
}

pub fn register(id: &Identity) -> Result<(), String> {
    publish(id, &id.profile())
}

/// Register or update our profile on our own relay. Same root key, same
/// name: the relay replaces the document (README §1).
pub fn publish(id: &Identity, profile: &Profile) -> Result<(), String> {
    let body = serde_json::to_string(profile).unwrap();
    post(&format!("{}/addr", id.relay), id.token.as_deref(), &body).map(|_| ())
}

/// Pass a token only when resolving on a relay you hold the token for —
/// callers must never send their bearer token to a foreign relay.
pub fn resolve(addr: &str, token: Option<&str>) -> Result<Profile, String> {
    let relay = addr_relay_url(addr)?;
    let name = addr.split_once('@').unwrap().0;
    let mut req = http_agent()
        .get(&format!("{relay}/addr/{name}"))
        .timeout(Duration::from_secs(15));
    if let Some(t) = token {
        req = req.set("authorization", &format!("Bearer {t}"));
    }
    let raw = req
        .call()
        .map_err(describe)?
        .into_string()
        .map_err(|e| e.to_string())?;
    let profile: Profile = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    profile.verify()?;
    Ok(profile)
}

/// Submit to own relay; best-effort dual-post to recipients on other relays
/// (without a token — their relay is either open or unreachable to us).
pub fn send(id: &Identity, env: &Envelope) -> Result<Receipt, String> {
    let body = serde_json::to_string(env).unwrap();
    let raw = post(&format!("{}/msgs", id.relay), id.token.as_deref(), &body)?;
    let receipt: Receipt =
        serde_json::from_str(&raw).map_err(|e| format!("bad relay receipt: {e}"))?;
    receipt.verify(env)?;
    // Economic evidence leaves the relay only through a signed disclosure.
    if env.body.get("economic").is_some() {
        return Ok(receipt);
    }
    for to in &env.to {
        if let Ok(their_relay) = addr_relay_url(to) {
            if their_relay != id.relay {
                let _ = post(&format!("{their_relay}/msgs"), None, &body); // best-effort, v0
            }
        }
    }
    Ok(receipt)
}

pub fn thread(id: &Identity, about: &str, since: u64, wait: u64) -> Result<Vec<Stored>, String> {
    let path = format!(
        "/threads?about={}&since={since}&wait={wait}",
        urlencode(about)
    );
    let messages = fetch(id, &path, wait)?;
    if messages.iter().any(|s| s.env.about != about) {
        return Err("relay returned an envelope from a different thread".into());
    }
    Ok(messages)
}

pub fn inbox(id: &Identity, since: u64, wait: u64) -> Result<Vec<Stored>, String> {
    let path = format!(
        "/inbox?addr={}&since={since}&wait={wait}",
        urlencode(&id.addr())
    );
    let messages = fetch(id, &path, wait)?;
    if messages.iter().any(|s| !s.env.to.contains(&id.addr())) {
        return Err("relay returned an envelope outside the requested inbox".into());
    }
    Ok(messages)
}

/// Fetch messages and check each sender against its current profile on our
/// relay, falling back to the relay's acceptance proof when the profile has
/// since changed.
fn fetch(id: &Identity, path: &str, wait: u64) -> Result<Vec<Stored>, String> {
    let raw = get_signed(id, path, wait.saturating_add(10))?;
    let resp: MsgsResponse = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let mut profiles: HashMap<&str, Profile> = HashMap::new();
    let mut proofs: HashMap<&str, Vec<Bundle>> = HashMap::new();
    for stored in &resp.msgs {
        let env = &stored.env;
        env.verify()?;
        let (name, from_authority) = env.from.split_once('@').ok_or("invalid sender address")?;
        if from_authority != authority(&id.relay) {
            return Err("foreign messages require the evidence federation endpoint".into());
        }
        if !profiles.contains_key(name) {
            let raw = get_signed(id, &format!("/addr/{}", urlencode(name)), 15)?;
            let profile: Profile = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
            profile.verify()?;
            if profile.name != name {
                return Err("profile name mismatch".into());
            }
            profiles.insert(name, profile);
        }
        let profile = &profiles[name];
        if evidence::sender_bound(env, profile, stored.received_at).is_ok() {
            continue;
        }
        if !proofs.contains_key(env.about.as_str()) {
            proofs.insert(&env.about, evidence(id, &env.about)?);
        }
        let bundle = proofs[env.about.as_str()]
            .iter()
            .find(|b| b.env.id == env.id)
            .ok_or("missing historical sender authorization")?;
        if bundle.profile.root != profile.root || bundle.receipt.received_at != stored.received_at {
            return Err("historical sender binding is unavailable under the current root".into());
        }
    }
    Ok(resp.msgs)
}

/// Export originals and historical acceptance proofs; never decrypted projections.
pub fn evidence(id: &Identity, about: &str) -> Result<Vec<Bundle>, String> {
    let raw = get_signed(id, &format!("/evidence?about={}", urlencode(about)), 15)?;
    let bundles: Vec<Bundle> = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    for bundle in &bundles {
        bundle.verify()?;
        if bundle.env.about != about {
            return Err("evidence is from another thread".into());
        }
    }
    Ok(bundles)
}

pub fn received_evidence(id: &Identity) -> Result<Vec<ReceivedEvidence>, String> {
    let raw = get_signed(id, "/federation/evidence", 15)?;
    let records: Vec<ReceivedEvidence> = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    for record in &records {
        record.delivery.verify()?;
        record.receipt.verify(&record.delivery)?;
        if record.delivery.audience.addr != id.addr()
            || record.delivery.audience.root != encode_key(&id.root_key().verifying_key())
        {
            return Err("foreign evidence audience mismatch".into());
        }
    }
    Ok(records)
}

/// Ask the hosted assessment service (ecco-ops signed-upload format) about an
/// exact proposed action. The answer is advisory, never a permit.
pub fn assess(id: &Identity, api: &str, input: &Value) -> Result<Value, String> {
    let path = "/api/economic/assess";
    let url = origin(api)?.join(path).unwrap();
    envelope::validate_json(input)?;
    let body = serde_json::to_string(input).map_err(|e| e.to_string())?;
    let ts = envelope::now();
    let statement = format!(
        "POST\n{path}\n{ts}\n{}",
        hex::encode(Sha256::digest(body.as_bytes()))
    );
    let sig = format!(
        "ed25519:{}",
        hex::encode(id.agent_key().sign(statement.as_bytes()).to_bytes())
    );
    let response = http_agent()
        .post(url.as_str())
        .timeout(Duration::from_secs(20))
        .set("content-type", "application/json")
        .set("x-ecco-addr", &id.addr())
        .set("x-ecco-key", &encode_key(&id.agent_key().verifying_key()))
        .set("x-ecco-ts", &ts.to_string())
        .set("x-ecco-sig", &sig)
        .send_string(&body)
        .map_err(describe)?
        .into_string()
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&response).map_err(|e| e.to_string())
}

/// Parse a bare `scheme://host[:port]` origin: HTTPS, or HTTP to loopback.
pub fn origin(url: &str) -> Result<url::Url, String> {
    let url = url::Url::parse(url).map_err(|e| e.to_string())?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.username() != ""
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
    {
        return Err(format!(
            "'{url}' must be a bare HTTPS origin (HTTP only on loopback)"
        ));
    }
    Ok(url)
}

/// Redirects off: a relay must never be able to bounce a signed request elsewhere.
pub(crate) fn http_agent() -> ureq::Agent {
    ureq::AgentBuilder::new().redirects(0).build()
}

fn post(url: &str, token: Option<&str>, body: &str) -> Result<String, String> {
    let mut req = http_agent()
        .post(url)
        .timeout(Duration::from_secs(15))
        .set("content-type", "application/json");
    if let Some(t) = token {
        req = req.set("authorization", &format!("Bearer {t}"));
    }
    req.send_string(body)
        .map_err(describe)?
        .into_string()
        .map_err(|e| e.to_string())
}

/// Own-relay GET with auth-v0 headers (README §5) — signed reads are
/// required on multi-tenant relays and harmlessly ignored on open ones.
fn get_signed(id: &Identity, path: &str, timeout_secs: u64) -> Result<String, String> {
    let mut req = http_agent()
        .get(&format!("{}{path}", id.relay))
        .timeout(Duration::from_secs(timeout_secs));
    if let Some(t) = id.token.as_deref() {
        req = req.set("authorization", &format!("Bearer {t}"));
    }
    let ts = envelope::now();
    let sig = id.agent_key().sign(&request_signing_bytes("GET", path, ts));
    req = req
        .set("x-ecco-addr", &id.addr())
        .set("x-ecco-key", &encode_key(&id.agent_key().verifying_key()))
        .set("x-ecco-ts", &ts.to_string())
        .set(
            "x-ecco-sig",
            &format!("ed25519:{}", hex::encode(sig.to_bytes())),
        );
    req.call()
        .map_err(describe)?
        .into_string()
        .map_err(|e| e.to_string())
}

fn describe(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => format!(
            "relay returned {code}: {}",
            resp.into_string().unwrap_or_default().trim()
        ),
        other => other.to_string(),
    }
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use serde_json::json;

    #[test]
    fn receipt_parses_verifies_and_binds_expected_send() {
        let relay = SigningKey::generate(&mut OsRng);
        let sender = SigningKey::generate(&mut OsRng);
        let env = Envelope::seal(
            "gh:owner/repo/pull/456".into(),
            json!({"x":1}),
            "a@x".into(),
            "note".into(),
            vec![],
            vec![],
            1,
            &sender,
        );
        let relay_key = encode_key(&relay.verifying_key());
        let bytes = serde_json::to_vec(&ReceiptSigningView {
            gseq: 9,
            id: &env.id,
            received_at: 20,
            relay: &relay_key,
            tseq: 3,
        })
        .unwrap();
        let raw = json!({"gseq":9,"id":env.id,"received_at":20,"relay":relay_key,"sig":format!("ed25519:{}", hex::encode(relay.sign(&bytes).to_bytes())),"tseq":3}).to_string();
        let receipt: Receipt = serde_json::from_str(&raw).unwrap();
        receipt.verify(&env).unwrap();
        let other = Envelope::seal(
            "gh:owner/repo/pull/456".into(),
            json!({"x":2}),
            "a@x".into(),
            "note".into(),
            vec![],
            vec![],
            1,
            &sender,
        );
        assert!(receipt.verify(&other).is_err());
    }
}
