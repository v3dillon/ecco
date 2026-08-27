//! The relay: a dumb store-and-forward server. Verifies, stores, orders,
//! serves. Storage lives behind store::Store — SQLite by default, Postgres
//! for the shared multi-tenant tier (--pg / DATABASE_URL).

use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::envelope::{self, encode_key, Envelope};
use crate::store::{PgStore, SqliteStore, Store, Stored, ThreadAccess};

const MAX_WAIT_SECS: u64 = 30;
const POLL_STEP: Duration = Duration::from_millis(300);
/// Public-tier abuse floors; generous for legitimate agents.
const MAX_BODY_BYTES: u64 = 64 * 1024;
const MSGS_PER_MIN_PER_SENDER: u32 = 120;
const REGISTRATIONS_PER_MIN_PER_IP: u32 = 10;

#[derive(Serialize)]
struct Receipt<'a> {
    gseq: u64,
    id: &'a str,
    received_at: u64,
    relay: &'a str,
    sig: String,
    tseq: u64,
}

#[derive(Serialize)]
struct ReceiptSigningView<'a> {
    gseq: u64,
    id: &'a str,
    received_at: u64,
    relay: &'a str,
    tseq: u64,
}

/// Fixed-window rate limiter; coarse on purpose — an abuse floor, not QoS.
struct Limiter {
    buckets: Mutex<HashMap<String, (u64, u32)>>,
}

impl Limiter {
    fn allow(&self, key: String, per_min: u32) -> bool {
        let window = envelope::now() / 60;
        let mut b = self.buckets.lock().unwrap();
        if b.len() > 100_000 {
            b.retain(|_, (w, _)| *w == window);
        }
        let e = b.entry(key).or_insert((window, 0));
        if e.0 != window {
            *e = (window, 0);
        }
        e.1 += 1;
        e.1 <= per_min
    }
}

pub struct Relay {
    store: Box<dyn Store>,
    key: SigningKey,
    token: Option<String>,
    signed: bool,
    limiter: Limiter,
}

pub fn run(
    port: u16,
    data: PathBuf,
    token: Option<String>,
    signed: bool,
    pg: Option<String>,
) -> Result<(), String> {
    fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    let key_path = data.join("relay_key");
    let key = match fs::read_to_string(&key_path) {
        Ok(hex_secret) => {
            let bytes: [u8; 32] = hex::decode(hex_secret.trim())
                .map_err(|_| "corrupt relay_key")?
                .try_into()
                .map_err(|_| "corrupt relay_key")?;
            SigningKey::from_bytes(&bytes)
        }
        Err(_) => {
            let key = SigningKey::generate(&mut rand::rngs::OsRng);
            fs::write(&key_path, hex::encode(key.to_bytes())).map_err(|e| e.to_string())?;
            key
        }
    };
    let (store, backend): (Box<dyn Store>, &str) = match &pg {
        Some(url) => (Box::new(PgStore::open(url)?), "postgres"),
        None => (Box::new(SqliteStore::open(&data)?), "sqlite"),
    };
    let relay = Arc::new(Relay {
        store,
        key,
        token,
        signed,
        limiter: Limiter {
            buckets: Mutex::new(HashMap::new()),
        },
    });
    let server = Arc::new(tiny_http::Server::http(("0.0.0.0", port)).map_err(|e| e.to_string())?);
    eprintln!(
        "ecco relay on port {port} · {backend} · signed reads: {} · key {}",
        relay.signed,
        encode_key(&relay.key.verifying_key())
    );
    let mut workers = Vec::new();
    for _ in 0..16 {
        let server = server.clone();
        let relay = relay.clone();
        workers.push(std::thread::spawn(move || {
            while let Ok(req) = server.recv() {
                relay.handle(req);
            }
        }));
    }
    for w in workers {
        let _ = w.join();
    }
    Ok(())
}

impl Relay {
    fn handle(&self, mut req: tiny_http::Request) {
        // Transport-level gate (PROTOCOL.md §5): deployment config, not protocol.
        if let Some(expected) = &self.token {
            let authed = req.headers().iter().any(|h| {
                h.field.equiv("authorization") && h.value.as_str() == format!("Bearer {expected}")
            });
            if !authed {
                let resp = tiny_http::Response::from_string("missing or bad bearer token")
                    .with_status_code(401);
                let _ = req.respond(resp);
                return;
            }
        }
        let url = req.url().to_string();
        let (path, query) = match url.split_once('?') {
            Some((p, q)) => (p.to_string(), parse_query(q)),
            None => (url.clone(), HashMap::new()),
        };
        let method = req.method().as_str().to_string();
        let ip = req
            .remote_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unknown".into());

        // auth-v0 (PROTOCOL.md §5): on a signed relay, reads must be signed by
        // a key of a registered identity; writes are already self-certifying.
        let mut reader: Option<String> = None;
        if self.signed && method == "GET" && (path == "/threads" || path == "/inbox") {
            match self.verify_read(&req, &url) {
                Ok(addr) => reader = Some(addr),
                Err(e) => {
                    let _ = req.respond(tiny_http::Response::from_string(e).with_status_code(401));
                    return;
                }
            }
        }

        let mut body = String::new();
        let _ = std::io::Read::read_to_string(
            &mut std::io::Read::take(req.as_reader(), MAX_BODY_BYTES + 1),
            &mut body,
        );

        let result = if body.len() as u64 > MAX_BODY_BYTES {
            Err((413, "body exceeds 64KB".into()))
        } else {
            match (method.as_str(), path.as_str()) {
                ("POST", "/addr") => self.post_addr(&body, &ip),
                ("GET", p) if p.starts_with("/addr/") => self.get_addr(&p["/addr/".len()..]),
                ("POST", "/msgs") => self.post_msgs(&body),
                ("GET", "/threads") => self
                    .authorize_thread(reader.as_deref(), &query)
                    .and_then(|_| self.poll(&query, true)),
                ("GET", "/inbox") => {
                    if reader.is_some() && query.get("addr") != reader.as_ref() {
                        Err((403, "an inbox is readable only by its own address".into()))
                    } else {
                        self.poll(&query, false)
                    }
                }
                _ => Err((404, "not found".into())),
            }
        };

        let response = match result {
            Ok(json) => tiny_http::Response::from_string(json).with_status_code(200),
            Err((code, msg)) => tiny_http::Response::from_string(msg).with_status_code(code),
        }
        .with_header(
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
        );
        let _ = req.respond(response);
    }

    fn post_addr(&self, body: &str, ip: &str) -> Result<String, (u16, String)> {
        if !self
            .limiter
            .allow(format!("addr:{ip}"), REGISTRATIONS_PER_MIN_PER_IP)
        {
            return Err((429, "registration rate limit".into()));
        }
        let profile: crate::identity::Profile =
            serde_json::from_str(body).map_err(|e| (400, format!("bad profile: {e}")))?;
        profile.verify().map_err(|e| (400, e))?;
        self.store.register(profile)?;
        Ok("{\"ok\":true}".into())
    }

    fn get_addr(&self, name: &str) -> Result<String, (u16, String)> {
        self.store
            .profile(name)?
            .map(|p| serde_json::to_string(&p).unwrap())
            .ok_or((404, format!("no profile for '{name}'")))
    }

    fn post_msgs(&self, body: &str) -> Result<String, (u16, String)> {
        let env: Envelope =
            serde_json::from_str(body).map_err(|e| (400, format!("bad envelope: {e}")))?;
        env.verify().map_err(|e| (400, e))?;
        if !self
            .limiter
            .allow(format!("msgs:{}", env.from), MSGS_PER_MIN_PER_SENDER)
        {
            return Err((429, "message rate limit".into()));
        }
        let sender_name = env
            .from
            .split_once('@')
            .ok_or((400, "bad from address".to_string()))?
            .0;
        let now = envelope::now();
        let profile = self
            .store
            .profile(sender_name)?
            .ok_or((400, format!("unknown sender '{}'", env.from)))?;
        profile
            .authorizes(&env.key, &env.kind, now)
            .map_err(|e| (403, e))?;
        let stored = self.store.append(env, now)?;

        let relay_key = encode_key(&self.key.verifying_key());
        let signing = serde_json::to_vec(&ReceiptSigningView {
            gseq: stored.gseq,
            id: &stored.env.id,
            received_at: stored.received_at,
            relay: &relay_key,
            tseq: stored.tseq,
        })
        .unwrap();
        let sig = self.key.sign(&signing);
        let receipt = Receipt {
            gseq: stored.gseq,
            id: &stored.env.id,
            received_at: stored.received_at,
            relay: &relay_key,
            sig: format!("ed25519:{}", hex::encode(sig.to_bytes())),
            tseq: stored.tseq,
        };
        Ok(serde_json::to_string(&receipt).unwrap())
    }

    /// auth-v0: validate the X-Ecco-* headers and return the authenticated addr.
    fn verify_read(&self, req: &tiny_http::Request, path_query: &str) -> Result<String, String> {
        let header = |name: &str| {
            req.headers()
                .iter()
                .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
                .map(|h| h.value.as_str().to_string())
        };
        let addr = header("x-ecco-addr").ok_or("missing x-ecco-addr")?;
        let key = header("x-ecco-key").ok_or("missing x-ecco-key")?;
        let sig = header("x-ecco-sig").ok_or("missing x-ecco-sig")?;
        let ts: u64 = header("x-ecco-ts")
            .ok_or("missing x-ecco-ts")?
            .parse()
            .map_err(|_| "bad x-ecco-ts")?;
        let now = envelope::now();
        if now.abs_diff(ts) > 300 {
            return Err("request timestamp outside the 300s window".into());
        }
        let name = addr.split_once('@').ok_or("bad x-ecco-addr")?.0;
        let profile = self
            .store
            .profile(name)
            .map_err(|(_, e)| e)?
            .ok_or(format!("unknown identity '{addr}'"))?;
        profile.authorizes_read(&key, now)?;
        let vk = envelope::decode_key(&key)?;
        let sig_bytes: [u8; 64] = envelope::decode_prefixed(&sig, "ed25519:")?
            .try_into()
            .map_err(|_| "bad signature length".to_string())?;
        vk.verify(
            &crate::identity::request_signing_bytes("GET", path_query, ts),
            &ed25519_dalek::Signature::from_bytes(&sig_bytes),
        )
        .map_err(|_| "bad request signature".to_string())?;
        Ok(addr)
    }

    /// auth-v0: a thread is readable by its participants; empty threads by
    /// any authenticated identity. Evaluated at request time.
    fn authorize_thread(
        &self,
        reader: Option<&str>,
        q: &HashMap<String, String>,
    ) -> Result<(), (u16, String)> {
        let Some(addr) = reader else { return Ok(()) };
        let Some(about) = q.get("about") else {
            return Err((400, "about required".into()));
        };
        match self.store.access(about, addr)? {
            ThreadAccess::NotParticipant => Err((403, "not a participant in this thread".into())),
            _ => Ok(()),
        }
    }

    /// Shared read path for /threads (by_thread=true) and /inbox, long-polling.
    fn poll(&self, q: &HashMap<String, String>, by_thread: bool) -> Result<String, (u16, String)> {
        let since: u64 = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
        let wait: u64 = q
            .get("wait")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
            .min(MAX_WAIT_SECS);
        let deadline = Instant::now() + Duration::from_secs(wait);
        loop {
            let found: Vec<Stored> = if by_thread {
                let about = q.get("about").ok_or((400, "about required".to_string()))?;
                self.store.thread(about, since)?
            } else {
                let addr = q.get("addr").ok_or((400, "addr required".to_string()))?;
                self.store.inbox(addr, since)?
            };
            if !found.is_empty() || Instant::now() >= deadline {
                return Ok(format!(
                    "{{\"msgs\":{}}}",
                    serde_json::to_string(&found).unwrap()
                ));
            }
            std::thread::sleep(POLL_STEP);
        }
    }
}

fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_string(), urldecode(v)))
        .collect()
}

fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
