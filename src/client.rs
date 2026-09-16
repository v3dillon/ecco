//! HTTP client for the relay API. README §5.

use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::envelope::{self, encode_key, Envelope};
use crate::identity::{addr_relay_url, request_signing_bytes, Identity, Profile};

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
    let mut req = ureq::get(&format!("{relay}/addr/{name}")).timeout(Duration::from_secs(15));
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
    Ok(take_verified(fetch(id, &path, wait)?))
}

/// Messages plus the batch high-water mark. The mark is taken before dropping
/// unverified envelopes so a forged message cannot stall the cursor.
pub fn inbox(id: &Identity, since: u64, wait: u64) -> Result<(Vec<Stored>, u64), String> {
    let path = format!(
        "/inbox?addr={}&since={since}&wait={wait}",
        urlencode(&id.addr())
    );
    let raw = fetch(id, &path, wait)?;
    let until = crate::agent_surface::next_cursor(since, &raw);
    Ok((take_verified(raw), until))
}

fn fetch(id: &Identity, path: &str, wait: u64) -> Result<Vec<Stored>, String> {
    let raw = get_signed(id, path, wait.saturating_add(10))?;
    let resp: MsgsResponse = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    Ok(resp.msgs)
}

/// The one place relay output is verified (README §2 steps 1–2). Everything
/// downstream sees verified envelopes only.
fn take_verified(msgs: Vec<Stored>) -> Vec<Stored> {
    msgs.into_iter()
        .filter(|stored| stored.env.verify().is_ok())
        .collect()
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

/// The auth-v0 headers (README §5) on a request made as this identity.
fn signed(
    req: ureq::Request,
    id: &Identity,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> ureq::Request {
    let ts = envelope::now();
    let sig = id
        .agent_key()
        .sign(&request_signing_bytes(method, path, ts, body));
    req.set("x-ecco-addr", &id.addr())
        .set("x-ecco-key", &encode_key(&id.agent_key().verifying_key()))
        .set("x-ecco-ts", &ts.to_string())
        .set("x-ecco-sig", &envelope::encode_sig(&sig))
}

/// Own-relay GET with auth-v0 headers (README §5) — signed reads are
/// required on multi-tenant relays and harmlessly ignored on open ones.
fn get_signed(id: &Identity, path: &str, timeout_secs: u64) -> Result<String, String> {
    let mut req =
        ureq::get(&format!("{}{path}", id.relay)).timeout(Duration::from_secs(timeout_secs));
    if let Some(t) = id.token.as_deref() {
        req = req.set("authorization", &format!("Bearer {t}"));
    }
    signed(req, id, "GET", path, None)
        .call()
        .map_err(describe)?
        .into_string()
        .map_err(|e| e.to_string())
}

/// A signed POST as this identity (README §5): the caller's JSON body to any
/// service that verifies those headers. The reply body comes back as is; a
/// non-2xx status is an error carrying the service's reply. Core does not
/// know what the body means.
pub fn call(id: &Identity, url: &str, body: &str) -> Result<String, String> {
    let parsed = url::Url::parse(url).map_err(|_| format!("not a URL: {url}"))?;
    crate::registration::origin(&parsed.origin().ascii_serialization())?;
    if parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err("ecco call takes a URL without query, fragment, or credentials".into());
    }
    let req = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(60))
        .build()
        .post(url)
        .set("content-type", "application/json");
    signed(req, id, "POST", parsed.path(), Some(body.as_bytes()))
        .send_string(body)
        .map_err(|e| match e {
            ureq::Error::Status(code, resp) => format!(
                "service returned {code}: {}",
                resp.into_string().unwrap_or_default().trim()
            ),
            other => other.to_string(),
        })?
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

    #[test]
    fn call_signs_the_body_and_returns_the_reply_or_the_error() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}/hook", server.server_addr());
        let id = Identity::generate("alice", "https://relay.test", None);
        let key = id.agent_key().verifying_key();
        let worker = std::thread::spawn(move || {
            for (code, reply) in [(200, r#"{"ok":true}"#), (400, "bad body")] {
                let mut request = server
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .expect("request");
                let header = |name: &str| {
                    request
                        .headers()
                        .iter()
                        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
                        .map(|h| h.value.as_str().to_string())
                        .unwrap()
                };
                assert_eq!(request.url(), "/hook");
                assert_eq!(header("x-ecco-addr"), "alice@relay.test");
                assert_eq!(header("x-ecco-key"), encode_key(&key));
                let ts: u64 = header("x-ecco-ts").parse().unwrap();
                let sig: [u8; 64] = envelope::decode_prefixed(&header("x-ecco-sig"), "ed25519:")
                    .unwrap()
                    .try_into()
                    .unwrap();
                let mut body = String::new();
                std::io::Read::read_to_string(request.as_reader(), &mut body).unwrap();
                key.verify(
                    &request_signing_bytes("POST", "/hook", ts, Some(body.as_bytes())),
                    &Signature::from_bytes(&sig),
                )
                .unwrap();
                request
                    .respond(tiny_http::Response::from_string(reply).with_status_code(code))
                    .unwrap();
            }
        });
        assert_eq!(call(&id, &url, r#"{"x":1}"#).unwrap(), r#"{"ok":true}"#);
        let err = call(&id, &url, "{}").unwrap_err();
        assert!(err.contains("400") && err.contains("bad body"), "{err}");
        worker.join().unwrap();
        for bad in [
            format!("{url}?token=x"),
            "http://remote.test/hook".to_string(),
            "not a url".to_string(),
        ] {
            assert!(call(&id, &bad, "{}").is_err(), "{bad}");
        }
    }

    #[test]
    fn unverified_envelopes_are_dropped_without_failing_the_batch() {
        let sender = SigningKey::generate(&mut OsRng);
        let valid = Envelope::seal(
            "topic".into(),
            json!({"text":"ok"}),
            "a@x".into(),
            "note".into(),
            vec![],
            vec![],
            1,
            &sender,
        );
        let mut invalid = valid.clone();
        invalid.body = json!({"text":"forged"});
        let msgs = take_verified(vec![
            Stored {
                gseq: 1,
                tseq: 1,
                received_at: 1,
                env: valid,
            },
            Stored {
                gseq: 2,
                tseq: 2,
                received_at: 1,
                env: invalid,
            },
        ]);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].gseq, 1);
        assert_eq!(msgs[0].env.body["text"], "ok");
    }
}
