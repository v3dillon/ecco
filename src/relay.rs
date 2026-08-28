//! The relay: a dumb store-and-forward server. Verifies, stores, orders,
//! serves. Storage is one SQLite file under --data (store::Store).

use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, OriginalUri, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::sync::{Notify, Semaphore};

use crate::envelope::{self, encode_key, Envelope};
use crate::store::{Store, Stored, ThreadAccess};

const MAX_WAIT_SECS: u64 = 30;
/// Retention pass cadence: refresh per-sender windows, then expire.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5 * 60);
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
    allow_roots: bool,
    /// Last good `allowedRoots` from the limits snapshot. `None` means
    /// never fetched (fail-closed while --allow-roots).
    allowed_roots: Mutex<Option<HashSet<String>>>,
    limiter: Limiter,
    wakes: Mutex<HashMap<String, Weak<Notify>>>,
    blocking: Arc<Semaphore>,
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
    allow_roots: bool,
    retention: Retention,
) -> Result<(), String> {
    if allow_roots && retention.limits_url.as_ref().is_none_or(|u| u.is_empty()) {
        return Err("--allow-roots requires --limits-url or ECCO_RELAY_LIMITS_URL".into());
    }
    if allow_roots && !signed {
        return Err("--allow-roots requires --signed or ECCO_RELAY_SIGNED".into());
    }
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
        allow_roots,
        allowed_roots: Mutex::new(None),
        limiter: Limiter {
            buckets: Mutex::new(HashMap::new()),
        },
        wakes: Mutex::new(HashMap::new()),
        blocking: Arc::new(Semaphore::new(16)),
    });
    eprintln!(
        "ecco relay on port {port} · {} · authority {} · signed reads: {} · allow-roots: {} · retention: {} · key {}",
        data.join("relay.db").display(),
        relay.authority,
        relay.signed,
        relay.allow_roots,
        describe_retention(&retention),
        encode_key(&relay.key.verifying_key())
    );
    if retention.enabled() || relay.allow_roots {
        let relay = relay.clone();
        std::thread::spawn(move || sweeper(relay, retention));
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let app = router(relay);
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .map_err(|e| e.to_string())?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .map_err(|e| e.to_string())
    })
}

fn router(relay: Arc<Relay>) -> Router {
    Router::new()
        .route("/addr", post(http_handler))
        .route("/addr/{name}", get(http_handler))
        .route("/msgs", post(http_handler))
        .route("/threads", get(http_handler))
        .route("/inbox", get(http_handler))
        .fallback(http_handler)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES as usize))
        .with_state(relay)
}

impl Relay {
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

    /// Membership from the last-good limits snapshot when --allow-roots.
    fn allow_root(&self, root: &str) -> Result<(), (u16, String)> {
        if !self.allow_roots {
            return Ok(());
        }
        match &*self.allowed_roots.lock().unwrap() {
            None => Err((503, "allowlist not ready".into())),
            Some(set) if set.contains(root) => Ok(()),
            Some(_) => Err((403, "root is not a member of this relay".into())),
        }
    }

    /// auth-v0: validate the X-Ecco-* headers and return the authenticated addr.
    fn verify_read(&self, headers: &HeaderMap, path_query: &str) -> Result<String, (u16, String)> {
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|h| h.to_str().ok())
                .map(str::to_string)
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

    fn signal(&self, key: &str) {
        let mut wakes = self.wakes.lock().unwrap();
        match wakes.get(key).and_then(Weak::upgrade) {
            Some(notify) => notify.notify_waiters(),
            None => {
                wakes.remove(key);
            }
        }
    }
}

struct Waiter {
    relay: Arc<Relay>,
    key: String,
    notify: Arc<Notify>,
}

impl Waiter {
    fn subscribe(relay: Arc<Relay>, key: String) -> Self {
        let notify = {
            let mut wakes = relay.wakes.lock().unwrap();
            wakes.get(&key).and_then(Weak::upgrade).unwrap_or_else(|| {
                let notify = Arc::new(Notify::new());
                wakes.insert(key.clone(), Arc::downgrade(&notify));
                notify
            })
        };
        Self { relay, key, notify }
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        let mut wakes = self.relay.wakes.lock().unwrap();
        if Arc::strong_count(&self.notify) == 1
            && wakes
                .get(&self.key)
                .is_some_and(|weak| weak.ptr_eq(&Arc::downgrade(&self.notify)))
        {
            wakes.remove(&self.key);
        }
    }
}

type HttpResult = Result<String, (u16, String)>;

async fn blocking<F>(relay: Arc<Relay>, work: F) -> HttpResult
where
    F: FnOnce(Arc<Relay>) -> HttpResult + Send + 'static,
{
    let permit = relay
        .blocking
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| (500, "blocking worker pool closed".into()))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work(relay)
    })
    .await
    .map_err(|e| (500, format!("blocking worker failed: {e}")))?
}

fn response(result: HttpResult) -> Response {
    match result {
        Ok(body) => (StatusCode::OK, [("content-type", "application/json")], body).into_response(),
        Err((code, body)) => (
            StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            [("content-type", "application/json")],
            body,
        )
            .into_response(),
    }
}

async fn poll(relay: Arc<Relay>, query: HashMap<String, String>, thread: bool) -> HttpResult {
    let since = query.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
    let wait = query
        .get("wait")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
        .min(MAX_WAIT_SECS);
    let value = if thread {
        query.get("about").ok_or((400, "about required".into()))?
    } else {
        query.get("addr").ok_or((400, "addr required".into()))?
    };
    let key = format!("{}:{value}", if thread { "thread" } else { "inbox" });
    let waiter = Waiter::subscribe(relay.clone(), key);
    let notified = waiter.notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    let value = value.clone();
    let found = blocking(relay.clone(), move |r| {
        let rows = if thread {
            r.store.thread(&value, since)?
        } else {
            r.store.inbox(&value, since)?
        };
        Ok(serde_json::to_string(&rows).unwrap())
    })
    .await?;
    let rows: Vec<Stored> = serde_json::from_str(&found).unwrap();
    if !rows.is_empty() || wait == 0 {
        return Ok(format!("{{\"msgs\":{found}}}"));
    }
    let _ = tokio::time::timeout(Duration::from_secs(wait), notified).await;
    let value = if thread {
        query["about"].clone()
    } else {
        query["addr"].clone()
    };
    blocking(relay, move |r| {
        let rows = if thread {
            r.store.thread(&value, since)?
        } else {
            r.store.inbox(&value, since)?
        };
        Ok(format!(
            "{{\"msgs\":{}}}",
            serde_json::to_string(&rows).unwrap()
        ))
    })
    .await
}

async fn http_handler(
    State(relay): State<Arc<Relay>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_string();
    let path_query = uri.path_and_query().map_or(path.as_str(), |v| v.as_str());
    let method_name = method.as_str();
    if let Some(expected) = &relay.token {
        let public = method == Method::GET && path.starts_with("/addr/");
        let actual = headers.get("authorization").and_then(|h| h.to_str().ok());
        if !public && actual != Some(format!("Bearer {expected}").as_str()) {
            return response(Err((401, "missing or bad bearer token".into())));
        }
    }
    let reader =
        if relay.signed && method == Method::GET && (path == "/threads" || path == "/inbox") {
            match blocking(relay.clone(), {
                let headers = headers.clone();
                let path_query = path_query.to_string();
                move |r| {
                    r.verify_read(&headers, &path_query)
                        .map(|v| serde_json::to_string(&v).unwrap())
                }
            })
            .await
            {
                Ok(v) => serde_json::from_str::<String>(&v).ok(),
                Err(e) => return response(Err(e)),
            }
        } else {
            None
        };
    if body.len() as u64 > MAX_BODY_BYTES {
        return response(Err((413, "body exceeds 64KB".into())));
    }
    let query = parse_query(uri.query().unwrap_or_default());
    let result = match (method_name, path.as_str()) {
        ("POST", "/addr") => {
            let body = String::from_utf8_lossy(&body).into_owned();
            let ip = remote.ip().to_string();
            blocking(relay, move |r| r.post_addr(&body, &ip)).await
        }
        ("GET", p) if p.starts_with("/addr/") => {
            let name = p["/addr/".len()..].to_string();
            blocking(relay, move |r| r.get_addr(&name)).await
        }
        ("POST", "/msgs") => {
            let body = String::from_utf8_lossy(&body).into_owned();
            let envelope = serde_json::from_str::<Envelope>(&body).ok();
            let result = blocking(relay.clone(), move |r| r.post_msgs(&body)).await;
            if result.is_ok() {
                if let Some(env) = envelope {
                    relay.signal(&format!("thread:{}", env.about));
                    for addr in env.to {
                        relay.signal(&format!("inbox:{addr}"));
                    }
                }
            }
            result
        }
        ("GET", "/threads") => {
            let auth = blocking(relay.clone(), {
                let query = query.clone();
                move |r| {
                    r.authorize_thread(reader.as_deref(), &query)
                        .map(|_| String::new())
                }
            })
            .await;
            match auth {
                Ok(_) => poll(relay, query, true).await,
                Err(e) => Err(e),
            }
        }
        ("GET", "/inbox") => {
            if reader.is_some() && query.get("addr") != reader.as_ref() {
                Err((403, "an inbox is readable only by its own address".into()))
            } else {
                poll(relay, query, false).await
            }
        }
        _ => Err((404, "not found".into())),
    };
    response(result)
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
/// relay never learns a plan id for an address. `allowed_roots` is `None`
/// when the field is missing, not an array, or contains a bad root —
/// keep last-good / Pending. `Some` (including empty) replaces it.
struct LimitWindows {
    per_sender: Vec<(String, u32)>,
    guest_days: Option<u32>,
    allowed_roots: Option<Vec<String>>,
}

fn is_allowed_root(s: &str) -> bool {
    let Some(hex) = s.strip_prefix("ed25519:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_allowed_roots(v: &serde_json::Value) -> Option<Vec<String>> {
    let arr = v.get("allowedRoots")?.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item.as_str()?;
        if !is_allowed_root(s) {
            return None;
        }
        out.push(s.to_string());
    }
    Some(out)
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
    LimitWindows {
        per_sender,
        guest_days: days(&v["plans"]["guest"]["retentionDays"]),
        allowed_roots: parse_allowed_roots(v),
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
                if relay.allow_roots {
                    if let Some(roots) = w.allowed_roots {
                        *relay.allowed_roots.lock().unwrap() = Some(roots.into_iter().collect());
                    }
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
#[path = "relay/tests.rs"]
mod tests;
