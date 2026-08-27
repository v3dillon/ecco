//! HTTP client for the relay API. PROTOCOL.md §5.

use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::envelope::{self, encode_key, Envelope};
use crate::identity::{addr_relay_url, request_signing_bytes, Identity, Profile};

#[derive(Debug, Serialize, Deserialize)]
pub struct Stored {
    pub gseq: u64,
    pub tseq: u64,
    pub received_at: u64,
    pub env: Envelope,
}

#[derive(Debug, Deserialize)]
struct MsgsResponse {
    msgs: Vec<Stored>,
}

pub fn register(id: &Identity) -> Result<(), String> {
    let body = serde_json::to_string(&id.profile()).unwrap();
    post(&format!("{}/addr", id.relay), id.token.as_deref(), &body).map(|_| ())
}

/// Pass a token only when resolving on a relay you hold the token for —
/// callers must never send their bearer token to a foreign relay.
pub fn resolve(addr: &str, token: Option<&str>) -> Result<Profile, String> {
    let relay = addr_relay_url(addr)?;
    let name = addr.split_once('@').unwrap().0;
    let mut req = ureq::get(&format!("{relay}/addr/{name}")).timeout(Duration::from_secs(15));
    if let Some(t) = token {
        req = req.set("authorization", &format!("Bearer {t}"));
    }
    let raw = req.call().map_err(describe)?.into_string().map_err(|e| e.to_string())?;
    let profile: Profile = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    profile.verify()?;
    Ok(profile)
}

/// Submit to own relay; best-effort dual-post to recipients on other relays
/// (without a token — their relay is either open or unreachable to us).
pub fn send(id: &Identity, env: &Envelope) -> Result<String, String> {
    let body = serde_json::to_string(env).unwrap();
    let receipt = post(&format!("{}/msgs", id.relay), id.token.as_deref(), &body)?;
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
    fetch(id, &path, wait)
}

pub fn inbox(id: &Identity, since: u64, wait: u64) -> Result<Vec<Stored>, String> {
    let path = format!(
        "/inbox?addr={}&since={since}&wait={wait}",
        urlencode(&id.addr())
    );
    fetch(id, &path, wait)
}

fn fetch(id: &Identity, path: &str, wait: u64) -> Result<Vec<Stored>, String> {
    let raw = get_signed(id, path, wait + 10)?;
    let resp: MsgsResponse = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    Ok(resp.msgs)
}

fn post(url: &str, token: Option<&str>, body: &str) -> Result<String, String> {
    let mut req = ureq::post(url)
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

/// Own-relay GET with auth-v0 headers (PROTOCOL.md §5) — signed reads are
/// required on multi-tenant relays and harmlessly ignored on open ones.
fn get_signed(id: &Identity, path: &str, timeout_secs: u64) -> Result<String, String> {
    let mut req = ureq::get(&format!("{}{path}", id.relay)).timeout(Duration::from_secs(timeout_secs));
    if let Some(t) = id.token.as_deref() {
        req = req.set("authorization", &format!("Bearer {t}"));
    }
    let ts = envelope::now();
    let sig = id.agent_key().sign(&request_signing_bytes("GET", path, ts));
    req = req
        .set("x-ecco-addr", &id.addr())
        .set("x-ecco-key", &encode_key(&id.agent_key().verifying_key()))
        .set("x-ecco-ts", &ts.to_string())
        .set("x-ecco-sig", &format!("ed25519:{}", hex::encode(sig.to_bytes())));
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
