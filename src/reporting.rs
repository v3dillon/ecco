//! Optional signed reporting. The outbox retains uploads only until acknowledged.
use crate::{
    client::Stored,
    envelope,
    identity::{self, Identity},
    local,
};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Serialize, Deserialize)]
struct Config {
    endpoint: Option<String>,
}
pub fn config_path(home: &Path) -> PathBuf {
    home.join("reporting.json")
}
pub fn configure(home: &Path, endpoint: Option<&str>) -> Result<(), String> {
    Identity::load(home)?;
    let endpoint = endpoint.map(crate::registration::origin).transpose()?;
    local::write(
        &config_path(home),
        &serde_json::to_vec(&Config { endpoint }).unwrap(),
    )
}
/// Re-running init preserves an explicit endpoint or opt-out.
pub fn setup(
    home: &Path,
    explicit: Option<&str>,
    discovered: Option<&str>,
    disabled: bool,
) -> Result<(), String> {
    if disabled {
        configure(home, None)
    } else if let Some(api) = explicit {
        configure(home, Some(api))
    } else if !config_path(home).exists() {
        if let Some(api) = discovered {
            configure(home, Some(api))
        } else {
            Ok(())
        }
    } else {
        Ok(())
    }
}
fn endpoint(home: &Path) -> Result<Option<String>, String> {
    if !config_path(home).exists() {
        return Ok(None);
    }
    let config: Config = serde_json::from_str(&local::read(&config_path(home), 4096)?)
        .map_err(|e| format!("invalid reporting config: {e}"))?;
    config
        .endpoint
        .as_deref()
        .map(crate::registration::origin)
        .transpose()
}
pub fn api(home: &Path, override_url: Option<&str>) -> Result<String, String> {
    if let Some(api) = override_url {
        return crate::registration::origin(api);
    }
    endpoint(home)?.ok_or("reporting is disabled; use ecco traces configure --api URL".into())
}
pub fn status(home: &Path) -> Result<(), String> {
    match endpoint(home)? {
        Some(api) => println!("Ecco activity reporting enabled: {api}. Uploads are private. Use ecco traces disable to opt out."),
        None => println!("Ecco activity reporting disabled. Use ecco traces configure --api URL to enable it."),
    }
    Ok(())
}

/// All client operations pass here, independent of the calling agent/harness.
/// A reporting failure must never change a successful relay operation.
pub fn observe(home: &Path, id: &Identity, messages: &[Stored]) {
    let result = (|| {
        let Some(api) = endpoint(home)? else {
            return Ok(());
        };
        let contacts = identity::contacts_load(home);
        let queue = Outbox::open(home, api)?;
        for stored in messages {
            if identity::standing(&contacts, &id.addr(), &stored.env.from)
                != identity::Standing::Trusted
                || stored.received_at > 253_402_300_799
                || stored.env.verify().is_err()
            {
                continue;
            }
            queue.enqueue("ecco-trace-v1", &message_trace(id, stored))?;
        }
        if queue.dir.exists() {
            start_upload(home)?;
        }
        Ok::<_, String>(())
    })();
    if let Err(error) = result {
        eprintln!("Ecco activity reporting: {error}");
    }
}

fn message_trace(id: &Identity, stored: &Stored) -> String {
    let env = &stored.env;
    let ts = local::timestamp_at(stored.received_at);
    // Do not decrypt or upload ciphertext. Encrypted messages expose metadata only.
    let text = if envelope::is_encrypted(&env.body) {
        Some("<encrypted>")
    } else {
        env.body["text"].as_str()
    };
    let events = [
        json!({"v":1,"kind":"header","agent":id.name,"model":null,"startedAt":ts,"source":"ecco","about":env.about,"envelopeIds":[env.id]}),
        json!({"kind":"message","ts":ts,"direction":if env.from == id.addr() {"sent"} else {"received"},"envelopeId":env.id,"about":env.about,"from":env.from,"to":env.to,"envelopeKind":env.kind,"text":text,"tseq":stored.tseq,"gseq":stored.gseq}),
        json!({"kind":"end","ts":ts,"status":"completed"}),
    ];
    events
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

// CLI processes can exit immediately. A detached core process owns network I/O;
// a per-outbox lock serializes concurrent CLI/MCP readers and dispatcher retries.
#[cfg(not(test))]
fn start_upload(home: &Path) -> Result<(), String> {
    use std::{
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };
    let mut cmd = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    cmd.arg("--home")
        .arg(home.canonicalize().map_err(|e| e.to_string())?)
        .args(["traces", "retry", "--background"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    // Reap children for long-lived MCP processes. On CLI exit init reaps them.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
#[cfg(test)]
fn start_upload(_: &Path) -> Result<(), String> {
    Ok(())
}

pub fn post(
    id: &Identity,
    api: &str,
    path: &str,
    body: &str,
    format: Option<&str>,
) -> Result<Value, String> {
    let ts = crate::envelope::now();
    let signing = format!("POST\n{path}\n{ts}\n{}", local::sha256(body));
    let sig = format!(
        "ed25519:{}",
        hex::encode(id.agent_key().sign(signing.as_bytes()).to_bytes())
    );
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(10))
        .build();
    let mut request = agent
        .post(&format!("{api}{path}"))
        .set("content-type", "application/json")
        .set("x-ecco-addr", &id.addr())
        .set(
            "x-ecco-key",
            &crate::envelope::encode_key(&id.agent_key().verifying_key()),
        )
        .set("x-ecco-ts", &ts.to_string())
        .set("x-ecco-sig", &sig);
    if let Some(format) = format {
        request = request
            .set("x-trace-format", format)
            .set("x-trace-visibility", "private");
    }
    let response = request
        .send_string(body)
        .map_err(|e| format!("reporting upload: {e}"))?;
    serde_json::from_reader(response.into_reader()).map_err(|e| e.to_string())
}
#[derive(Serialize, Deserialize)]
struct Pending {
    format: String,
    body: String,
}
pub struct Outbox {
    dir: PathBuf,
    home: PathBuf,
    api: String,
    id: Identity,
}
impl Outbox {
    pub fn open(home: &Path, api: String) -> Result<Self, String> {
        let id = Identity::load(home)?;
        let dir = home.join("trace-outbox").join(local::sha256(format!(
            "{api}\n{}\n{}",
            id.addr(),
            envelope::encode_key(&id.root_key().verifying_key())
        )));
        Ok(Self {
            dir,
            home: home.into(),
            api,
            id,
        })
    }
    pub fn enqueue(&self, format: &str, body: &str) -> Result<(), String> {
        local::mkdir(&self.dir)?;
        let data = serde_json::to_vec(&Pending {
            format: format.into(),
            body: body.into(),
        })
        .unwrap();
        if data.len() > 32 * 1024 * 1024 {
            return Err("trace exceeds outbox size limit".into());
        }
        let path = self.dir.join(format!("{}.json", local::sha256(&data)));
        if path.exists() {
            return Ok(());
        }
        local::write(&path, &data)
    }
    pub fn flush(&self, limit: usize, background: bool) -> Result<usize, String> {
        if !self.dir.exists() {
            return Ok(0);
        }
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.dir.join("upload.lock"))
            .map_err(|e| e.to_string())?;
        let mode = libc::LOCK_EX | if background { libc::LOCK_NB } else { 0 };
        if unsafe { libc::flock(lock.as_raw_fd(), mode) } != 0 {
            if background {
                return Ok(0);
            }
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut attempted = BTreeSet::new();
        let mut failure = None;
        loop {
            let pending = self.files()?;
            let files: Vec<_> = pending
                .iter()
                .filter(|p| !attempted.contains(*p))
                .take(limit.saturating_sub(attempted.len()))
                .cloned()
                .collect();
            if files.is_empty() {
                return match failure {
                    Some(error) => Err(error),
                    None => Ok(pending.len()),
                };
            }
            for path in files {
                // Respect a changed endpoint or opt-out between background requests.
                if background && endpoint(&self.home)?.as_deref() != Some(&self.api) {
                    return Ok(pending.len());
                }
                attempted.insert(path.clone());
                if let Err(error) = self.deliver(&path) {
                    // An invalid optional transcript must not block other activity traces.
                    failure.get_or_insert(error);
                }
            }
            // Pick up observations queued while the preceding requests were in flight.
        }
    }
    fn files(&self) -> Result<Vec<PathBuf>, String> {
        let mut files: Vec<_> = fs::read_dir(&self.dir)
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        Ok(files)
    }
    fn deliver(&self, path: &Path) -> Result<(), String> {
        let content = local::read(path, 32 * 1024 * 1024)?;
        let pending: Pending = serde_json::from_str(&content).map_err(|e| e.to_string())?;
        let result = post(
            &self.id,
            &self.api,
            "/api/traces",
            &pending.body,
            Some(&pending.format),
        )?;
        let hash = result["hash"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("reporting service returned no trace hash")?;
        fs::remove_file(path).map_err(|e| e.to_string())?;
        eprintln!("uploaded trace {hash}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    fn home() -> PathBuf {
        let home = std::env::temp_dir().join(format!("ecco-observe-{}", rand::random::<u64>()));
        Identity::generate("alice", "https://relay.test", None)
            .save(&home)
            .unwrap();
        home
    }
    fn queued(home: &Path) -> Vec<String> {
        let queue = Outbox::open(home, "http://localhost:9".into()).unwrap();
        fs::read_dir(queue.dir)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .map(|e| {
                serde_json::from_str::<Pending>(&local::read(&e.path(), 65536).unwrap())
                    .unwrap()
                    .body
            })
            .collect()
    }
    #[test]
    fn message_trace_matches_the_shared_service_contract() {
        let id = Identity::generate("alice", "https://relay.test", None);
        let mut env = envelope::Envelope::seal(
            "topic".into(),
            json!({"text":"hello"}),
            id.addr(),
            "note".into(),
            vec![],
            vec!["bob@relay.test".into()],
            1,
            &id.agent_key(),
        );
        // Stable envelope ID for the wire-format fixture (signature validation is tested separately).
        env.id = format!("b3:{}", "a".repeat(64));
        let stored = Stored {
            env,
            gseq: 10,
            tseq: 1,
            received_at: 1789413000,
        };
        assert_eq!(
            message_trace(&id, &stored),
            include_str!("../tests/fixtures/ecco-message.jsonl")
        );
    }
    #[test]
    fn init_discovers_reporting_without_overriding_an_opt_out_or_endpoint() {
        let home = home();
        let before = local::read(&home.join("identity.json"), 4096).unwrap();
        setup(&home, None, Some("https://ops.test"), false).unwrap();
        assert_eq!(api(&home, None).unwrap(), "https://ops.test");
        setup(&home, None, Some("https://other.test"), false).unwrap();
        assert_eq!(api(&home, None).unwrap(), "https://ops.test");
        setup(&home, None, None, true).unwrap();
        setup(&home, None, Some("https://ops.test"), false).unwrap();
        assert!(endpoint(&home).unwrap().is_none());
        setup(&home, Some("https://new.test"), None, false).unwrap();
        assert_eq!(api(&home, None).unwrap(), "https://new.test");
        assert_eq!(
            local::read(&home.join("identity.json"), 4096).unwrap(),
            before
        );
        fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn records_only_trusted_verified_messages_and_redacts_encrypted_bodies() {
        let home = home();
        let id = Identity::load(&home).unwrap();
        let make = |from: &str, text: &str| Stored {
            gseq: 10,
            tseq: 1,
            received_at: 1789413000,
            env: envelope::Envelope::seal(
                "topic".into(),
                json!({"text":text}),
                from.into(),
                "note".into(),
                vec![],
                vec![id.addr()],
                1,
                &id.agent_key(),
            ),
        };
        let own = make(&id.addr(), "hello");
        observe(&home, &id, std::slice::from_ref(&own));
        assert!(queued(&home).is_empty());
        configure(&home, Some("http://localhost:9")).unwrap();
        identity::contacts_set(&home, "trusted@relay.test", "approved").unwrap();
        identity::contacts_set(&home, "blocked@relay.test", "blocked").unwrap();
        let mut invalid = make("trusted@relay.test", "tampered");
        invalid.env.body = json!({"text":"forged"});
        observe(
            &home,
            &id,
            &[
                own.clone(),
                make("trusted@relay.test", "visible"),
                make("held@relay.test", "held-secret"),
                make("blocked@relay.test", "blocked-secret"),
                invalid,
            ],
        );
        observe(&home, &id, std::slice::from_ref(&own)); // same envelope, same bytes
        let traces = queued(&home);
        assert_eq!(traces.len(), 2);
        let all = traces.join("\n");
        for secret in ["held-secret", "blocked-secret", "forged"] {
            assert!(!all.contains(secret));
        }
        let body = envelope::seal_body(
            &json!({"text":"encrypted-secret"}),
            &[(id.addr(), id.root_key().verifying_key())],
        )
        .unwrap();
        let encrypted = Stored {
            env: envelope::Envelope::seal(
                "topic".into(),
                body,
                id.addr(),
                "note".into(),
                vec![],
                vec![id.addr()],
                1,
                &id.agent_key(),
            ),
            ..own.clone()
        };
        observe(&home, &id, &[encrypted]);
        let all = queued(&home).join("\n");
        assert!(all.contains("<encrypted>"));
        assert!(!all.contains("encrypted-secret"));
        assert!(!all.contains("x25519-sealed"));
        configure(&home, None).unwrap();
        observe(&home, &id, &[make(&id.addr(), "disabled-secret")]);
        assert_eq!(queued(&home).len(), 3);
        // A fresh root at the same address cannot drain the old identity's uploads.
        let previous = Outbox::open(&home, "http://localhost:9".into())
            .unwrap()
            .dir;
        Identity::generate("alice", "https://relay.test", None)
            .save(&home)
            .unwrap();
        assert_ne!(
            Outbox::open(&home, "http://localhost:9".into())
                .unwrap()
                .dir,
            previous
        );
        fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn a_rejected_trace_does_not_block_other_or_concurrently_queued_uploads() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let api = format!("http://{}", server.server_addr());
        let home = home();
        configure(&home, Some(&api)).unwrap();
        let queue = Outbox::open(&home, api.clone()).unwrap();
        queue.enqueue("ecco-native-v1", "bad").unwrap();
        queue.enqueue("ecco-trace-v1", "first").unwrap();
        let worker_home = home.clone();
        let worker = std::thread::spawn(move || {
            let queue = Outbox::open(&worker_home, api).unwrap();
            let mut bodies = Vec::new();
            for _ in 0..3 {
                let mut request = server
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .expect("request");
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body).unwrap();
                if body == "first" {
                    queue.enqueue("ecco-trace-v1", "later").unwrap();
                }
                let code = if body == "bad" { 400 } else { 200 };
                request
                    .respond(
                        tiny_http::Response::from_string(r#"{"hash":"sha256:test"}"#)
                            .with_status_code(code),
                    )
                    .unwrap();
                bodies.push(body);
            }
            bodies.sort();
            assert_eq!(bodies, ["bad", "first", "later"]);
        });
        assert!(queue.flush(10, false).is_err());
        worker.join().unwrap();
        assert_eq!(queue.files().unwrap().len(), 1);
        configure(&home, None).unwrap();
        assert_eq!(queue.flush(10, true).unwrap(), 1); // opt-out stops pending background work
        fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn signed_upload_retries_survive_restart_and_require_an_acknowledgement() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let api = format!("http://{}", server.server_addr());
        let home = std::env::temp_dir().join(format!("ecco-reporting-{}", rand::random::<u64>()));
        let id = Identity::generate("alice", "https://relay.test", None);
        id.save(&home).unwrap();
        configure(&home, Some(&api)).unwrap();
        let key = id.agent_key().verifying_key();
        let worker = std::thread::spawn(move || {
            for (code, response) in [(503, "{}"), (200, "{}"), (200, r#"{"hash":"sha256:abc"}"#)] {
                let mut request = server
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .expect("request");
                assert_eq!(request.url(), "/api/traces");
                let header = |name: &str| {
                    request
                        .headers()
                        .iter()
                        .find(|h| h.field.to_string().eq_ignore_ascii_case(name))
                        .unwrap()
                        .value
                        .to_string()
                };
                let ts = header("x-ecco-ts");
                let sig = header("x-ecco-sig");
                assert_eq!(header("x-ecco-addr"), "alice@relay.test");
                assert_eq!(header("x-trace-format"), "ecco-native-v1");
                assert_eq!(header("x-trace-visibility"), "private");
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body).unwrap();
                assert_eq!(body, "native");
                let sig = Signature::from_slice(
                    &hex::decode(sig.strip_prefix("ed25519:").unwrap()).unwrap(),
                )
                .unwrap();
                key.verify(
                    format!("POST\n/api/traces\n{ts}\n{}", local::sha256(&body)).as_bytes(),
                    &sig,
                )
                .unwrap();
                request
                    .respond(tiny_http::Response::from_string(response).with_status_code(code))
                    .unwrap();
            }
        });
        let queue = Outbox::open(&home, api.clone()).unwrap();
        queue.enqueue("ecco-native-v1", "native").unwrap();
        queue.enqueue("ecco-native-v1", "native").unwrap();
        assert_eq!(
            fs::read_dir(&queue.dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|e| e == "json"))
                .count(),
            1
        );
        assert!(queue.flush(3, false).is_err());
        let restarted = Outbox::open(&home, api.clone()).unwrap();
        assert!(restarted.flush(3, false).is_err());
        assert_eq!(
            fs::read_dir(&queue.dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|e| e == "json"))
                .count(),
            1
        );
        assert_ne!(
            Outbox::open(&home, "https://other.test".into())
                .unwrap()
                .dir,
            queue.dir
        );
        assert_eq!(restarted.flush(3, false).unwrap(), 0);
        assert_eq!(
            fs::read_dir(&queue.dir)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.path().extension().is_some_and(|e| e == "json"))
                .count(),
            0
        );
        worker.join().unwrap();
        fs::remove_dir_all(home).unwrap();
    }
}
