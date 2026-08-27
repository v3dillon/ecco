//! The relay: a dumb store-and-forward server. Verifies, stores, orders, serves.
//! State is a pair of append-only jsonl files, replayed into memory on start.

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::envelope::{self, encode_key, Envelope};
use crate::identity::Profile;

const MAX_WAIT_SECS: u64 = 30;
const POLL_STEP: Duration = Duration::from_millis(300);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stored {
    pub gseq: u64,
    pub tseq: u64,
    pub received_at: u64,
    pub env: Envelope,
}

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

struct State {
    msgs: Vec<Stored>,
    profiles: HashMap<String, Profile>,
}

pub struct Relay {
    data: PathBuf,
    key: SigningKey,
    state: Mutex<State>,
}

pub fn run(port: u16, data: PathBuf) -> Result<(), String> {
    let relay = Arc::new(Relay::open(data)?);
    let server = Arc::new(
        tiny_http::Server::http(("0.0.0.0", port)).map_err(|e| e.to_string())?,
    );
    eprintln!(
        "ecco relay on port {port} · key {}",
        encode_key(&relay.key.verifying_key())
    );
    let mut workers = Vec::new();
    for _ in 0..16 {
        let server = server.clone();
        let relay = relay.clone();
        workers.push(std::thread::spawn(move || loop {
            match server.recv() {
                Ok(req) => relay.handle(req),
                Err(_) => break,
            }
        }));
    }
    for w in workers {
        let _ = w.join();
    }
    Ok(())
}

impl Relay {
    fn open(data: PathBuf) -> Result<Relay, String> {
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
        let mut state = State {
            msgs: Vec::new(),
            profiles: HashMap::new(),
        };
        for line in read_lines(&data.join("msgs.jsonl")) {
            if let Ok(s) = serde_json::from_str::<Stored>(&line) {
                state.msgs.push(s);
            }
        }
        for line in read_lines(&data.join("profiles.jsonl")) {
            if let Ok(p) = serde_json::from_str::<Profile>(&line) {
                state.profiles.insert(p.name.clone(), p); // last write wins on replay
            }
        }
        Ok(Relay {
            data,
            key,
            state: Mutex::new(state),
        })
    }

    fn handle(&self, mut req: tiny_http::Request) {
        let url = req.url().to_string();
        let (path, query) = match url.split_once('?') {
            Some((p, q)) => (p.to_string(), parse_query(q)),
            None => (url.clone(), HashMap::new()),
        };
        let method = req.method().as_str().to_string();
        let mut body = String::new();
        let _ = std::io::Read::read_to_string(&mut req.as_reader(), &mut body);

        let result = match (method.as_str(), path.as_str()) {
            ("POST", "/addr") => self.post_addr(&body),
            ("GET", p) if p.starts_with("/addr/") => self.get_addr(&p["/addr/".len()..]),
            ("POST", "/msgs") => self.post_msgs(&body),
            ("GET", "/threads") => self.query(&query, |s, q| {
                q.get("about").map_or(false, |about| &s.env.about == about)
            }),
            ("GET", "/inbox") => self.query(&query, |s, q| {
                q.get("addr").map_or(false, |a| s.env.to.contains(a))
            }),
            _ => Err((404, "not found".into())),
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

    fn post_addr(&self, body: &str) -> Result<String, (u16, String)> {
        let profile: Profile =
            serde_json::from_str(body).map_err(|e| (400, format!("bad profile: {e}")))?;
        profile.verify().map_err(|e| (400, e))?;
        let mut state = self.state.lock().unwrap();
        if let Some(existing) = state.profiles.get(&profile.name) {
            if existing.root != profile.root {
                return Err((409, format!("name '{}' is taken", profile.name)));
            }
        }
        append_line(&self.data.join("profiles.jsonl"), &serde_json::to_string(&profile).unwrap());
        state.profiles.insert(profile.name.clone(), profile);
        Ok("{\"ok\":true}".into())
    }

    fn get_addr(&self, name: &str) -> Result<String, (u16, String)> {
        let state = self.state.lock().unwrap();
        state
            .profiles
            .get(name)
            .map(|p| serde_json::to_string(p).unwrap())
            .ok_or((404, format!("no profile for '{name}'")))
    }

    fn post_msgs(&self, body: &str) -> Result<String, (u16, String)> {
        let env: Envelope =
            serde_json::from_str(body).map_err(|e| (400, format!("bad envelope: {e}")))?;
        env.verify().map_err(|e| (400, e))?;
        let sender_name = env
            .from
            .split_once('@')
            .ok_or((400, "bad from address".to_string()))?
            .0
            .to_string();
        let now = envelope::now();

        let mut state = self.state.lock().unwrap();
        let profile = state
            .profiles
            .get(&sender_name)
            .ok_or((400, format!("unknown sender '{}'", env.from)))?;
        profile
            .authorizes(&env.key, &env.kind, now)
            .map_err(|e| (403, e))?;

        // Idempotent by id: resubmission returns a fresh receipt for the stored copy.
        let stored = match state.msgs.iter().find(|s| s.env.id == env.id) {
            Some(existing) => existing.clone(),
            None => {
                let stored = Stored {
                    gseq: state.msgs.len() as u64 + 1,
                    tseq: state.msgs.iter().filter(|s| s.env.about == env.about).count() as u64 + 1,
                    received_at: now,
                    env,
                };
                append_line(&self.data.join("msgs.jsonl"), &serde_json::to_string(&stored).unwrap());
                state.msgs.push(stored.clone());
                stored
            }
        };

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

    /// Shared read path for /threads and /inbox, with long-polling.
    fn query(
        &self,
        q: &HashMap<String, String>,
        matches: fn(&Stored, &HashMap<String, String>) -> bool,
    ) -> Result<String, (u16, String)> {
        let since: u64 = q.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
        let wait: u64 = q
            .get("wait")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
            .min(MAX_WAIT_SECS);
        let seq_of = |s: &Stored, q: &HashMap<String, String>| {
            if q.contains_key("about") { s.tseq } else { s.gseq }
        };
        let deadline = Instant::now() + Duration::from_secs(wait);
        loop {
            let found: Vec<Stored> = {
                let state = self.state.lock().unwrap();
                state
                    .msgs
                    .iter()
                    .filter(|s| matches(s, q) && seq_of(s, q) > since)
                    .cloned()
                    .collect()
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

fn read_lines(path: &PathBuf) -> Vec<String> {
    fs::read_to_string(path)
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

fn append_line(path: &PathBuf, line: &str) {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .expect("open data file");
    writeln!(f, "{line}").expect("append data file");
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
