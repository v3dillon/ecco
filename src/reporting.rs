//! Optional signed reporting. The outbox retains uploads only until acknowledged.
use crate::{
    client::Stored,
    envelope,
    identity::{self, Identity},
    local,
};
use clap::Subcommand;
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

pub const ACTIVITY_SCHEMA: &str = "ecco-activity-v1";
const MAX_EVENT_BYTES: usize = 256 * 1024;

#[derive(Subcommand)]
pub enum ReportingCmd {
    /// Deliver Ecco activity to this HTTPS endpoint (loopback HTTP allowed)
    Configure {
        #[arg(long)]
        endpoint: String,
    },
    /// Stop reporting; retain pending events locally
    Disable,
    Status,
    /// Retry pending event delivery and display failures
    Retry {
        #[arg(long, hide = true)]
        background: bool,
    },
}
pub fn command(home: &Path, cmd: ReportingCmd) -> Result<(), String> {
    match cmd {
        ReportingCmd::Configure { endpoint } => {
            configure(home, Some(&endpoint))?;
            status(home)
        }
        ReportingCmd::Disable => {
            configure(home, None)?;
            status(home)
        }
        ReportingCmd::Status => status(home),
        ReportingCmd::Retry { background } => Outbox::open(home, destination(home)?)?
            .flush(if background { 100 } else { usize::MAX }, background)
            .map(|_| ()),
    }
}
/// Service-defined URL: core does not choose a service API path.
pub fn validate_endpoint(value: &str) -> Result<String, String> {
    let url = url::Url::parse(value).map_err(|_| "invalid reporting endpoint")?;
    crate::registration::origin(&url.origin().ascii_serialization())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("reporting endpoint cannot contain credentials, query, or fragment".into());
    }
    Ok(url.to_string())
}

#[derive(Serialize, Deserialize)]
struct Config {
    endpoint: Option<String>,
}
pub fn config_path(home: &Path) -> PathBuf {
    home.join("reporting.json")
}
pub fn configure(home: &Path, endpoint: Option<&str>) -> Result<(), String> {
    Identity::load(home)?;
    let endpoint = endpoint.map(validate_endpoint).transpose()?;
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
        .map(validate_endpoint)
        .transpose()
}
pub fn destination(home: &Path) -> Result<String, String> {
    endpoint(home)?
        .ok_or("reporting is disabled; use ecco reporting configure --endpoint URL".into())
}
pub fn status(home: &Path) -> Result<(), String> {
    match endpoint(home)? {
        Some(api) => println!("Ecco activity reporting enabled: {api}. Events are sent to this service. Use ecco reporting disable to opt out."),
        None => println!("Ecco activity reporting disabled. Use ecco reporting configure --endpoint URL to enable it."),
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
        let mut queued = false;
        for stored in messages {
            if identity::standing(&contacts, &id.addr(), &stored.env.from)
                != identity::Standing::Trusted
                || stored.received_at > 253_402_300_799
                || stored.env.verify().is_err()
            {
                continue;
            }
            queued |= queue.enqueue(&message_activity(id, stored).to_string())?;
        }
        if queued {
            start_upload(home)?;
        }
        Ok::<_, String>(())
    })();
    if let Err(error) = result {
        eprintln!("Ecco activity reporting: {error}");
    }
}

fn message_activity(id: &Identity, stored: &Stored) -> Value {
    let env = &stored.env;
    let encrypted = envelope::is_encrypted(&env.body);
    let text = if encrypted {
        None
    } else {
        env.body["text"].as_str()
    };
    json!({"schema":ACTIVITY_SCHEMA,"type":"message","observer":id.addr(),
        "envelope":{"id":env.id,"about":env.about,"from":env.from,"to":env.to,"kind":env.kind,"text":text,"encrypted":encrypted},
        "receipt":{"gseq":stored.gseq,"tseq":stored.tseq,"received_at":stored.received_at}})
}

#[cfg(not(test))]
fn start_upload(home: &Path) -> Result<(), String> {
    use std::{
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };
    let mut cmd = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
    cmd.arg("--home")
        .arg(home.canonicalize().map_err(|e| e.to_string())?)
        .args(["reporting", "retry", "--background"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // New session so CLI exit does not kill the uploader.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    // Reap so long-lived MCP processes do not accumulate zombies.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
#[cfg(test)]
thread_local! {
    static UPLOADS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
fn start_upload(_: &Path) -> Result<(), String> {
    UPLOADS.with(|c| c.set(c.get() + 1));
    Ok(())
}

/// Signed delivery with an acknowledgement bound to the exact request bytes.
pub fn post(id: &Identity, endpoint: &str, body: &str) -> Result<(), String> {
    let url = url::Url::parse(&validate_endpoint(endpoint)?).map_err(|e| e.to_string())?;
    let path = url.path();
    let ts = envelope::now();
    let digest = local::sha256(body);
    let signing = format!("POST\n{path}\n{ts}\n{digest}");
    let sig = format!(
        "ed25519:{}",
        hex::encode(id.agent_key().sign(signing.as_bytes()).to_bytes())
    );
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(10))
        .build();
    let response = agent
        .post(url.as_str())
        .set("content-type", "application/json")
        .set("x-ecco-addr", &id.addr())
        .set(
            "x-ecco-key",
            &envelope::encode_key(&id.agent_key().verifying_key()),
        )
        .set("x-ecco-ts", &ts.to_string())
        .set("x-ecco-sig", &sig)
        .send_string(body)
        .map_err(|e| format!("event delivery: {e}"))?;
    let result: Value =
        serde_json::from_reader(response.into_reader()).map_err(|e| e.to_string())?;
    if result["accepted"].as_str() != Some(&format!("sha256:{digest}")) {
        return Err("service did not acknowledge this event payload".into());
    }
    Ok(())
}
pub struct Outbox {
    dir: PathBuf,
    home: PathBuf,
    api: String,
    id: Identity,
}
impl Outbox {
    pub fn open(home: &Path, api: String) -> Result<Self, String> {
        let api = validate_endpoint(&api)?;
        let id = Identity::load(home)?;
        let dir = home.join("reporting-outbox").join(local::sha256(format!(
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
    pub fn enqueue(&self, body: &str) -> Result<bool, String> {
        if body.len() > MAX_EVENT_BYTES {
            return Err("event exceeds delivery size limit".into());
        }
        local::mkdir(&self.dir)?;
        let path = self.dir.join(format!("{}.json", local::sha256(body)));
        if path.exists() {
            return Ok(false);
        }
        local::write(&path, body.as_bytes())?;
        Ok(true)
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
                    // A rejected event must not block delivery of other events.
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
        let body = local::read(path, MAX_EVENT_BYTES)?;
        post(&self.id, &self.api, &body)?;
        fs::remove_file(path).map_err(|e| e.to_string())?;
        eprintln!("delivered event sha256:{}", local::sha256(body));
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
            .map(|e| local::read(&e.path(), 65536).unwrap())
            .collect()
    }
    #[test]
    fn message_activity_matches_the_generic_wire_contract() {
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
            message_activity(&id, &stored).to_string() + "\n",
            include_str!("../tests/fixtures/ecco-message-activity.json")
        );
    }
    #[test]
    fn init_discovers_reporting_without_overriding_an_opt_out_or_endpoint() {
        let home = home();
        let before = local::read(&home.join("identity.json"), 4096).unwrap();
        setup(&home, None, Some("https://ops.test/events"), false).unwrap();
        assert_eq!(destination(&home).unwrap(), "https://ops.test/events");
        setup(&home, None, Some("https://other.test/events"), false).unwrap();
        assert_eq!(destination(&home).unwrap(), "https://ops.test/events");
        setup(&home, None, None, true).unwrap();
        setup(&home, None, Some("https://ops.test/events"), false).unwrap();
        assert!(endpoint(&home).unwrap().is_none());
        setup(&home, Some("https://new.test/events"), None, false).unwrap();
        assert_eq!(destination(&home).unwrap(), "https://new.test/events");
        assert_eq!(
            local::read(&home.join("identity.json"), 4096).unwrap(),
            before
        );
        fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn records_only_trusted_verified_messages_and_redacts_encrypted_bodies() {
        UPLOADS.with(|c| c.set(0));
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
        assert_eq!(UPLOADS.with(|c| c.get()), 0);
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
        let events = queued(&home);
        assert_eq!(events.len(), 2);
        assert_eq!(UPLOADS.with(|c| c.get()), 1);
        let all = events.join("\n");
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
        assert!(all.contains("\"encrypted\":true"));
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
    fn a_rejected_event_does_not_block_other_or_concurrently_queued_deliveries() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let api = format!("http://{}/custom/events", server.server_addr());
        let home = home();
        configure(&home, Some(&api)).unwrap();
        let queue = Outbox::open(&home, api.clone()).unwrap();
        queue.enqueue("bad").unwrap();
        queue.enqueue("first").unwrap();
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
                    queue.enqueue("later").unwrap();
                }
                let code = if body == "bad" { 400 } else { 200 };
                request
                    .respond(
                        tiny_http::Response::from_string(
                            json!({"accepted":format!("sha256:{}", local::sha256(&body))})
                                .to_string(),
                        )
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
        let api = format!("http://{}/custom/events", server.server_addr());
        let home = std::env::temp_dir().join(format!("ecco-reporting-{}", rand::random::<u64>()));
        let id = Identity::generate("alice", "https://relay.test", None);
        id.save(&home).unwrap();
        configure(&home, Some(&api)).unwrap();
        let key = id.agent_key().verifying_key();
        let worker = std::thread::spawn(move || {
            for (code, response) in [
                (503, "{}".to_string()),
                (200, r#"{"accepted":"sha256:wrong"}"#.to_string()),
                (
                    200,
                    json!({"accepted":format!("sha256:{}", local::sha256("event"))}).to_string(),
                ),
            ] {
                let mut request = server
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .expect("request");
                assert_eq!(request.url(), "/custom/events");
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
                assert!(!request
                    .headers()
                    .iter()
                    .any(|h| h.field.to_string().starts_with("x-trace-")));
                let mut body = String::new();
                request.as_reader().read_to_string(&mut body).unwrap();
                assert_eq!(body, "event");
                let sig = Signature::from_slice(
                    &hex::decode(sig.strip_prefix("ed25519:").unwrap()).unwrap(),
                )
                .unwrap();
                key.verify(
                    format!("POST\n/custom/events\n{ts}\n{}", local::sha256(&body)).as_bytes(),
                    &sig,
                )
                .unwrap();
                request
                    .respond(tiny_http::Response::from_string(response).with_status_code(code))
                    .unwrap();
            }
        });
        let queue = Outbox::open(&home, api.clone()).unwrap();
        queue.enqueue("event").unwrap();
        queue.enqueue("event").unwrap();
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
            Outbox::open(&home, "https://other.test/events".into())
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
