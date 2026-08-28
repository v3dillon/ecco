//! The relay: a dumb store-and-forward server. Verifies, stores, orders,
//! serves. Storage is one SQLite file under --data (store::Store).

use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::envelope::{self, encode_key, Envelope};
use crate::store::{Store, Stored, ThreadAccess};

const MAX_WAIT_SECS: u64 = 30;
/// Retention pass cadence: refresh per-sender windows, then expire.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);
const POLL_STEP: Duration = Duration::from_millis(300);
/// Abuse floors for a public relay; generous for legitimate agents.
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
    store: Store,
    key: SigningKey,
    token: Option<String>,
    signed: bool,
    authority: String,
    hosted: bool,
    /// Last good `allowedRoots` from the limits snapshot. `None` means
    /// never fetched (fail-closed while hosted).
    allowed_roots: Mutex<Option<HashSet<String>>>,
    limiter: Limiter,
}

/// Envelope expiry. Not protocol: a deployment choice for relays that
/// sell retention windows. Both fields unset means the relay never expires
/// anything (self-hosted default).
#[derive(Clone, Default)]
pub struct Retention {
    /// A limits snapshot (`/api/limits.json` on the control plane). Its
    /// `addresses[addr].retentionDays` set per-sender windows; its
    /// `plans.guest.retentionDays` is the default for everyone else.
    pub limits_url: Option<String>,
    /// Default window in days for senders without an entry; 0 keeps
    /// forever. Overrides the snapshot's guest value when both exist.
    pub default_days: Option<u32>,
}

impl Retention {
    pub fn enabled(&self) -> bool {
        self.limits_url.is_some() || self.default_days.is_some()
    }
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    port: u16,
    data: PathBuf,
    token: Option<String>,
    signed: bool,
    authority: String,
    hosted: bool,
    retention: Retention,
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
    let store = Store::open(&data)?;
    let relay = Arc::new(Relay {
        store,
        key,
        token,
        signed,
        authority,
        hosted,
        allowed_roots: Mutex::new(None),
        limiter: Limiter {
            buckets: Mutex::new(HashMap::new()),
        },
    });
    let server = Arc::new(tiny_http::Server::http(("0.0.0.0", port)).map_err(|e| e.to_string())?);
    eprintln!(
        "ecco relay on port {port} · {} · authority {} · signed reads: {} · hosted: {} · retention: {} · key {}",
        data.join("relay.db").display(),
        relay.authority,
        relay.signed,
        relay.hosted,
        describe_retention(&retention),
        encode_key(&relay.key.verifying_key())
    );
    if retention.enabled() || relay.hosted {
        let relay = relay.clone();
        std::thread::spawn(move || sweeper(relay, retention));
    }
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
        let url = req.url().to_string();
        let (path, query) = match url.split_once('?') {
            Some((p, q)) => (p.to_string(), parse_query(q)),
            None => (url.clone(), HashMap::new()),
        };
        let method = req.method().as_str().to_string();
        // Transport-level gate (README §5): deployment config, not protocol.
        // GET /addr/{name} stays public — profile documents are public by design.
        if let Some(expected) = &self.token {
            let public_profile = method == "GET" && path.starts_with("/addr/");
            if !public_profile {
                let authed = req.headers().iter().any(|h| {
                    h.field.equiv("authorization")
                        && h.value.as_str() == format!("Bearer {expected}")
                });
                if !authed {
                    let resp = tiny_http::Response::from_string("missing or bad bearer token")
                        .with_status_code(401);
                    let _ = req.respond(resp);
                    return;
                }
            }
        }
        let ip = req
            .remote_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unknown".into());

        // auth-v0 (README §5): on a signed relay, reads must be signed by
        // a key of a registered identity; writes are already self-certifying.
        let mut reader: Option<String> = None;
        if self.signed && method == "GET" && (path == "/threads" || path == "/inbox") {
            match self.verify_read(&req, &url) {
                Ok(addr) => reader = Some(addr),
                Err((code, e)) => {
                    let _ = req.respond(tiny_http::Response::from_string(e).with_status_code(code));
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
        for d in &profile.delegations {
            let name = self.name_on_this_relay(&d.addr).map_err(|e| (400, e))?;
            if name != profile.name {
                return Err((
                    400,
                    format!("delegation addr '{}' does not match profile name", d.addr),
                ));
            }
        }
        self.allow_root(&profile.root)?;
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
        let sender_name = self.name_on_this_relay(&env.from).map_err(|e| (400, e))?;
        let now = envelope::now();
        let profile = self
            .store
            .profile(sender_name)?
            .ok_or((400, format!("unknown sender '{}'", env.from)))?;
        profile
            .authorizes(&env.key, &env.kind, now)
            .map_err(|e| (403, e))?;
        self.allow_root(&profile.root)?;
        // Closed threads: an existing anchor accepts posts from its
        // participants only. Anyone may start an empty anchor, and being
        // addressed is how you join. A stranger reusing your anchor gets
        // this error, never your thread.
        if let ThreadAccess::NotParticipant = self.store.access(&env.about, &env.from)? {
            return Err((
                403,
                format!(
                    "'{}' is an existing thread you are not part of; pick another anchor or ask a participant to address you",
                    env.about
                ),
            ));
        }
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

    /// `name` from `name@authority` when the authority is this relay.
    fn name_on_this_relay<'a>(&self, addr: &'a str) -> Result<&'a str, String> {
        let (name, auth) = addr
            .split_once('@')
            .ok_or_else(|| format!("'{addr}' is not name@authority"))?;
        if auth != self.authority {
            return Err(format!("authority '{auth}' is not this relay"));
        }
        Ok(name)
    }

    /// Hosted/private membership from the last-good limits snapshot.
    fn allow_root(&self, root: &str) -> Result<(), (u16, String)> {
        if !self.hosted {
            return Ok(());
        }
        match &*self.allowed_roots.lock().unwrap() {
            None => Err((503, "allowlist not ready".into())),
            Some(set) if set.contains(root) => Ok(()),
            Some(_) => Err((403, "root is not a member of this relay".into())),
        }
    }

    /// auth-v0: validate the X-Ecco-* headers and return the authenticated addr.
    fn verify_read(
        &self,
        req: &tiny_http::Request,
        path_query: &str,
    ) -> Result<String, (u16, String)> {
        let header = |name: &str| {
            req.headers()
                .iter()
                .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
                .map(|h| h.value.as_str().to_string())
        };
        let addr = header("x-ecco-addr").ok_or((401, "missing x-ecco-addr".into()))?;
        let key = header("x-ecco-key").ok_or((401, "missing x-ecco-key".into()))?;
        let sig = header("x-ecco-sig").ok_or((401, "missing x-ecco-sig".into()))?;
        let ts: u64 = header("x-ecco-ts")
            .ok_or((401, "missing x-ecco-ts".into()))?
            .parse()
            .map_err(|_| (401, "bad x-ecco-ts".into()))?;
        let now = envelope::now();
        if now.abs_diff(ts) > 300 {
            return Err((401, "request timestamp outside the 300s window".into()));
        }
        let name = self.name_on_this_relay(&addr).map_err(|e| (401, e))?;
        let profile = self
            .store
            .profile(name)?
            .ok_or((401, format!("unknown identity '{addr}'")))?;
        profile.authorizes_read(&key, now).map_err(|e| (401, e))?;
        self.allow_root(&profile.root)?;
        let vk = envelope::decode_key(&key).map_err(|e| (401, e))?;
        let sig_bytes: [u8; 64] = envelope::decode_prefixed(&sig, "ed25519:")
            .map_err(|e| (401, e))?
            .try_into()
            .map_err(|_| (401, "bad signature length".into()))?;
        vk.verify(
            &crate::identity::request_signing_bytes("GET", path_query, ts),
            &ed25519_dalek::Signature::from_bytes(&sig_bytes),
        )
        .map_err(|_| (401, "bad request signature".into()))?;
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

fn describe_retention(r: &Retention) -> String {
    match (&r.limits_url, r.default_days) {
        (None, None) => "off".into(),
        (None, Some(d)) => format!("{d}d default"),
        (Some(u), None) => format!("per-sender from {u}"),
        (Some(u), Some(d)) => format!("per-sender from {u}, {d}d default"),
    }
}

/// Per-sender windows parsed from a limits snapshot. Numbers only: the
/// relay never learns a plan id for an address. `allowed_roots` is the
/// hosted membership list from the same snapshot.
struct LimitWindows {
    per_sender: Vec<(String, u32)>,
    guest_days: Option<u32>,
    allowed_roots: Vec<String>,
}

fn parse_limits(v: &serde_json::Value) -> LimitWindows {
    let days = |v: &serde_json::Value| v.as_u64().and_then(|d| u32::try_from(d).ok());
    let per_sender = v["addresses"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(addr, caps)| days(&caps["retentionDays"]).map(|d| (addr.clone(), d)))
                .collect()
        })
        .unwrap_or_default();
    let allowed_roots = v["allowedRoots"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    LimitWindows {
        per_sender,
        guest_days: days(&v["plans"]["guest"]["retentionDays"]),
        allowed_roots,
    }
}

fn fetch_limits(url: &str) -> Result<LimitWindows, String> {
    let raw = ureq::get(url)
        .timeout(Duration::from_secs(15))
        .call()
        .map_err(|e| e.to_string())?
        .into_string()
        .map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    Ok(parse_limits(&v))
}

/// One pass: refresh the per-sender table from the snapshot (when
/// configured), then expire. A failed fetch keeps the last known windows
/// and still sweeps with the configured default, if any.
fn retention_pass(relay: &Relay, cfg: &Retention) {
    let mut default_days = cfg.default_days;
    if let Some(url) = &cfg.limits_url {
        match fetch_limits(url) {
            Ok(w) => {
                if let Err((_, e)) = relay.store.set_retention(&w.per_sender) {
                    eprintln!("relay: retention table update failed: {e}");
                }
                if relay.hosted {
                    *relay.allowed_roots.lock().unwrap() =
                        Some(w.allowed_roots.into_iter().collect());
                }
                if default_days.is_none() {
                    default_days = w.guest_days;
                }
            }
            Err(e) => eprintln!("relay: limits fetch failed ({url}): {e}"),
        }
    }
    let Some(days) = default_days else { return };
    match relay.store.sweep(envelope::now(), days) {
        Ok(0) => {}
        Ok(n) => eprintln!("relay: expired {n} envelope(s)"),
        Err((_, e)) => eprintln!("relay: sweep failed: {e}"),
    }
}

fn sweeper(relay: Arc<Relay>, cfg: Retention) {
    loop {
        retention_pass(&relay, &cfg);
        std::thread::sleep(SWEEP_INTERVAL);
    }
}

/// Admin entry: one retention pass against a store, no server.
pub fn sweep_once(store: &Store, default_days: u32) -> Result<u64, String> {
    store
        .sweep(envelope::now(), default_days)
        .map_err(|(_, e)| e)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    fn relay() -> Relay {
        let dir = std::env::temp_dir().join(format!(
            "ecco-relay-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        Relay {
            store: Store::open(&dir).unwrap(),
            key: SigningKey::generate(&mut rand::rngs::OsRng),
            token: None,
            signed: true,
            authority: "localhost:4200".into(),
            hosted: false,
            allowed_roots: Mutex::new(None),
            limiter: Limiter {
                buckets: Mutex::new(HashMap::new()),
            },
        }
    }

    fn post(
        r: &Relay,
        from: &Identity,
        about: &str,
        to: &[&Identity],
        text: &str,
    ) -> Result<String, (u16, String)> {
        let env = Envelope::seal(
            about.into(),
            json!({ "text": text }),
            from.addr(),
            "note".into(),
            vec![],
            to.iter().map(|i| i.addr()).collect(),
            envelope::now(),
            &from.agent_key(),
        );
        r.post_msgs(&serde_json::to_string(&env).unwrap())
    }

    #[test]
    fn existing_threads_accept_participants_only() {
        let r = relay();
        let alice = Identity::generate("alice", "http://localhost:4200", None);
        let bob = Identity::generate("bob", "http://localhost:4200", None);
        let mallory = Identity::generate("mallory", "http://localhost:4200", None);
        for id in [&alice, &bob, &mallory] {
            r.store.register(id.profile()).unwrap();
        }
        let pr = "gh:acme/app/pull/13";
        // Anyone may start an empty anchor; alice addresses bob.
        post(&r, &alice, pr, &[&bob], "review requested").unwrap();
        // Bob joined by being addressed.
        post(&r, &bob, pr, &[&alice], "on it").unwrap();
        // Mallory reuses the anchor: refused, and still not a participant.
        let (code, msg) = post(&r, &mallory, pr, &[], "hi").unwrap_err();
        assert_eq!(code, 403);
        assert!(msg.contains("not part of"));
        assert!(matches!(
            r.store.access(pr, &mallory.addr()).unwrap(),
            ThreadAccess::NotParticipant
        ));
        // Mallory can still start her own anchor.
        post(&r, &mallory, "gh:acme/app/pull/14", &[], "mine").unwrap();
        // And joins PR 13 once a participant addresses her.
        post(&r, &alice, pr, &[&mallory], "join us").unwrap();
        post(&r, &mallory, pr, &[&alice], "thanks").unwrap();
        assert_eq!(r.store.thread(pr, 0).unwrap().len(), 4);
    }

    fn spawn(r: Relay) -> u16 {
        let relay = std::sync::Arc::new(r);
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        std::thread::spawn(move || {
            while let Ok(req) = server.recv() {
                relay.handle(req);
            }
        });
        port
    }

    #[test]
    fn authority_mismatch_is_rejected() {
        let r = relay();
        assert_eq!(
            r.name_on_this_relay("alice@localhost:4200").unwrap(),
            "alice"
        );
        assert!(r.name_on_this_relay("alice@evil.example").is_err());
        assert!(r.name_on_this_relay("alice").is_err());

        let foreign = Identity::generate("alice", "http://evil.example", None);
        let (code, msg) = r
            .post_addr(
                &serde_json::to_string(&foreign.profile()).unwrap(),
                "1.1.1.1",
            )
            .unwrap_err();
        assert_eq!(code, 400);
        assert!(msg.contains("authority"));

        let alice = Identity::generate("alice", "http://localhost:4200", None);
        r.store.register(alice.profile()).unwrap();
        let env = Envelope::seal(
            "gh:x".into(),
            json!({ "text": "x" }),
            "alice@evil.example".into(),
            "note".into(),
            vec![],
            vec![],
            envelope::now(),
            &alice.agent_key(),
        );
        let (code, msg) = r
            .post_msgs(&serde_json::to_string(&env).unwrap())
            .unwrap_err();
        assert_eq!(code, 400);
        assert!(msg.contains("authority"));
    }

    #[test]
    fn get_addr_is_public_when_bearer_is_set() {
        let mut r = relay();
        r.token = Some("s3cret".into());
        r.signed = false;
        let alice = Identity::generate("alice", "http://localhost:4200", None);
        r.store.register(alice.profile()).unwrap();
        let port = spawn(r);
        let base = format!("http://127.0.0.1:{port}");
        let got = ureq::get(&format!("{base}/addr/alice"))
            .timeout(Duration::from_secs(2))
            .call()
            .unwrap();
        assert_eq!(got.status(), 200);
        match ureq::post(&format!("{base}/msgs"))
            .timeout(Duration::from_secs(2))
            .send_string("{}")
        {
            Err(ureq::Error::Status(401, _)) => {}
            other => panic!("expected 401 without bearer, got {other:?}"),
        }
    }

    #[test]
    fn allowlist_off_pending_empty_listed_kick() {
        let alice = Identity::generate("alice", "http://localhost:4200", None);
        let bob = Identity::generate("bob", "http://localhost:4200", None);
        let alice_body = serde_json::to_string(&alice.profile()).unwrap();
        let bob_body = serde_json::to_string(&bob.profile()).unwrap();

        let r = relay();
        r.post_addr(&alice_body, "1.1.1.1").unwrap();
        post(&r, &alice, "gh:off", &[], "hi").unwrap();

        let mut r = relay();
        r.hosted = true;
        let (code, _) = r.post_addr(&alice_body, "1.1.1.1").unwrap_err();
        assert_eq!(code, 503);

        *r.allowed_roots.lock().unwrap() = Some(HashSet::new());
        let (code, _) = r.post_addr(&alice_body, "1.1.1.1").unwrap_err();
        assert_eq!(code, 403);

        *r.allowed_roots.lock().unwrap() = Some(HashSet::from([alice.profile().root]));
        r.post_addr(&alice_body, "1.1.1.1").unwrap();
        post(&r, &alice, "gh:listed", &[], "hi").unwrap();
        let (code, _) = r.post_addr(&bob_body, "1.1.1.1").unwrap_err();
        assert_eq!(code, 403);

        *r.allowed_roots.lock().unwrap() = Some(HashSet::new());
        let (code, _) = post(&r, &alice, "gh:listed", &[], "again").unwrap_err();
        assert_eq!(code, 403);
    }

    #[test]
    fn parse_limits_reads_allowed_roots_and_defaults_missing_to_empty() {
        let w = parse_limits(&json!({
            "allowedRoots": ["ed25519:aa", "ed25519:bb"],
            "addresses": { "alice@x": { "retentionDays": 7 } },
            "plans": { "guest": { "retentionDays": 3 } }
        }));
        assert_eq!(w.allowed_roots, vec!["ed25519:aa", "ed25519:bb"]);
        assert_eq!(w.guest_days, Some(3));
        assert_eq!(w.per_sender, vec![("alice@x".into(), 7)]);
        let empty = parse_limits(&json!({}));
        assert!(empty.allowed_roots.is_empty());
        assert!(empty.per_sender.is_empty());
        assert_eq!(empty.guest_days, None);
    }
}
