//! HTTP client for the relay API. PROTOCOL.md §5.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::envelope::Envelope;
use crate::identity::{addr_relay_url, Profile};

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

pub fn register(relay: &str, token: Option<&str>, profile: &Profile) -> Result<(), String> {
    let body = serde_json::to_string(profile).unwrap();
    post(&format!("{relay}/addr"), token, &body).map(|_| ())
}

/// Pass a token only when resolving on a relay you hold the token for —
/// callers must never send their bearer token to a foreign relay.
pub fn resolve(addr: &str, token: Option<&str>) -> Result<Profile, String> {
    let relay = addr_relay_url(addr)?;
    let name = addr.split_once('@').unwrap().0;
    let raw = get(&format!("{relay}/addr/{name}"), token, 35)?;
    let profile: Profile = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    profile.verify()?;
    Ok(profile)
}

/// Submit to own relay; best-effort dual-post to recipients on other relays
/// (without a token — their relay is either open or unreachable to us).
pub fn send(own_relay: &str, token: Option<&str>, env: &Envelope) -> Result<String, String> {
    let body = serde_json::to_string(env).unwrap();
    let receipt = post(&format!("{own_relay}/msgs"), token, &body)?;
    for to in &env.to {
        if let Ok(their_relay) = addr_relay_url(to) {
            if their_relay != own_relay {
                let _ = post(&format!("{their_relay}/msgs"), None, &body); // best-effort, v0
            }
        }
    }
    Ok(receipt)
}

pub fn thread(
    relay: &str,
    token: Option<&str>,
    about: &str,
    since: u64,
    wait: u64,
) -> Result<Vec<Stored>, String> {
    fetch(&format!(
        "{relay}/threads?about={}&since={since}&wait={wait}",
        urlencode(about)
    ), token, wait)
}

pub fn inbox(
    relay: &str,
    token: Option<&str>,
    addr: &str,
    since: u64,
    wait: u64,
) -> Result<Vec<Stored>, String> {
    fetch(&format!(
        "{relay}/inbox?addr={}&since={since}&wait={wait}",
        urlencode(addr)
    ), token, wait)
}

fn fetch(url: &str, token: Option<&str>, wait: u64) -> Result<Vec<Stored>, String> {
    let raw = get(url, token, wait + 10)?;
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

fn get(url: &str, token: Option<&str>, timeout_secs: u64) -> Result<String, String> {
    let mut req = ureq::get(url).timeout(Duration::from_secs(timeout_secs));
    if let Some(t) = token {
        req = req.set("authorization", &format!("Bearer {t}"));
    }
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
