//! End to end through the binary: a relay reporting to an operator endpoint,
//! and a dispatcher answering trusted requests with a local handler.
use serde_json::{json, Value};
use std::{
    fs,
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const ECCO: &str = env!("CARGO_BIN_EXE_ecco");

struct Relay(Child);
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait_until(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn ecco(home: &Path, env: &[(&str, &str)], args: &[&str]) -> Result<String, String> {
    let output = Command::new(ECCO)
        .arg("--home")
        .arg(home)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    if output.status.success() {
        Ok(String::from_utf8(output.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

fn thread(home: &Path, about: &str) -> Vec<Value> {
    let log: Value =
        serde_json::from_str(&ecco(home, &[], &["log", about, "--json"]).unwrap()).unwrap();
    log["messages"].as_array().unwrap().clone()
}

/// The operator's endpoint: records each event and acknowledges by digest.
fn collector() -> (String, Arc<Mutex<Vec<Value>>>) {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let url = format!("http://{}/collector", server.server_addr());
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&events);
    std::thread::spawn(move || {
        while let Ok(mut request) = server.recv() {
            let mut body = String::new();
            request.as_reader().read_to_string(&mut body).unwrap();
            assert!(request.headers().iter().any(|h| h
                .field
                .as_str()
                .as_str()
                .eq_ignore_ascii_case("x-ecco-sig")));
            seen.lock()
                .unwrap()
                .push(serde_json::from_str(&body).unwrap());
            let ack = json!({"accepted": format!("b3:{}", blake3::hash(body.as_bytes()).to_hex())});
            request
                .respond(tiny_http::Response::from_string(ack.to_string()))
                .unwrap();
        }
    });
    (url, events)
}

fn handler(dir: &Path, calls: &Path) -> PathBuf {
    let path = dir.join("adapter");
    fs::write(
        &path,
        format!(
            r#"#!/bin/sh
set -e
input=$(cat)
case "$input" in *'"schema":"ecco-dispatch-v1"'*) ;; *) echo "bad input: $input" >&2; exit 1;; esac
[ "$WORKER_TEST_SETTING" = configured ] || {{ echo "missing env" >&2; exit 1; }}
[ -z "$UNRELATED_SECRET" ] || {{ echo "leaked env" >&2; exit 1; }}
printf x >> {calls}
printf '%s' '{{"kind":"finding","text":"pong","follow_up":"one clarification"}}'
"#,
            calls = calls.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn relay_reports_stored_envelopes_and_the_dispatcher_answers_trusted_requests() {
    let root = std::env::temp_dir().join(format!("ecco-runtime-{}", rand::random::<u64>()));
    fs::create_dir_all(&root).unwrap();
    let (url, events) = collector();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _relay = Relay(
        Command::new(ECCO)
            .args(["relay", "--port", &port.to_string(), "--signed", "--data"])
            .arg(root.join("relay"))
            .env("ECCO_REPORTING_URL", &url)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_until("relay", || TcpStream::connect(("127.0.0.1", port)).is_ok());
    let relay = format!("http://localhost:{port}");
    let authority = format!("localhost:{port}");
    let (alice, bob) = (root.join("alice"), root.join("bob"));
    for (home, name) in [(&alice, "alice"), (&bob, "bob")] {
        ecco(home, &[], &["init", "--name", name, "--relay", &relay]).unwrap();
    }
    let before = fs::read(alice.join("identity.json")).unwrap();
    ecco(&alice, &[], &["init"]).unwrap();
    assert_eq!(fs::read(alice.join("identity.json")).unwrap(), before);
    let bob_addr = format!("bob@{authority}");
    let alice_addr = format!("alice@{authority}");

    // Every stored envelope reaches the endpoint once, whoever reads it.
    let request: Value = serde_json::from_str(
        &ecco(
            &bob,
            &[],
            &[
                "send",
                "--to",
                &alice_addr,
                "--about",
                "smoke",
                "--kind",
                "request",
                "ping",
            ],
        )
        .unwrap(),
    )
    .unwrap();
    let reported = |id: &str| {
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e["msg"]["env"]["id"] == id)
            .count()
    };
    wait_until("report", || reported(request["id"].as_str().unwrap()) == 1);
    for _ in 0..3 {
        ecco(&alice, &[], &["log", "smoke", "--json"]).unwrap();
    }
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(reported(request["id"].as_str().unwrap()), 1);
    let event = events.lock().unwrap()[0].clone();
    assert_eq!(event["schema"], "ecco-activity-v1");
    assert_eq!(event["relay"], authority);
    assert_eq!(event["msg"]["env"]["from"], bob_addr);

    // Configure trusts the allowed sender; the handler sees only listed env.
    let calls = root.join("calls");
    let adapter = handler(&root, &calls);
    let held = ecco(&alice, &[], &["inbox", "--json", "--since", "0"]).unwrap();
    assert!(held.contains("\"held\":[{"));
    ecco(
        &alice,
        &[],
        &[
            "dispatcher",
            "configure",
            "--handler",
            adapter.to_str().unwrap(),
            "--handler-env",
            "WORKER_TEST_SETTING",
            "--allow",
            &bob_addr,
            "--workdir",
            root.to_str().unwrap(),
        ],
    )
    .unwrap();
    ecco(&alice, &[], &["dispatcher", "run", "--once"]).unwrap(); // handler fails: job retries
    let worker = [
        ("WORKER_TEST_SETTING", "configured"),
        ("UNRELATED_SECRET", "do not inherit"),
    ];
    let db = rusqlite::Connection::open(alice.join("dispatcher.sqlite")).unwrap();
    let status = || -> Vec<(String, i64)> {
        db.prepare("SELECT status,attempts FROM jobs ORDER BY rowid")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(status(), vec![("retrying".to_string(), 1)]);
    db.execute("UPDATE jobs SET next_at=0", []).unwrap();
    ecco(&alice, &worker, &["dispatcher", "run", "--once"]).unwrap();
    assert_eq!(fs::read_to_string(&calls).unwrap(), "x");
    assert_eq!(status(), vec![("completed".to_string(), 2)]);
    let messages = thread(&bob, "smoke");
    let replies: Vec<&Value> = messages
        .iter()
        .filter(|m| m["env"]["from"] == alice_addr)
        .collect();
    assert_eq!(replies.len(), 2, "{messages:?}");
    assert!(replies
        .iter()
        .all(|m| m["env"]["body"]["in_reply_to"] == request["id"]));
    assert_eq!(replies[0]["env"]["kind"], "finding");
    assert_eq!(replies[0]["env"]["body"]["text"], "pong");
    assert_eq!(replies[1]["env"]["kind"], "request");

    // A restart after a crash reuses the saved result and never replies twice.
    db.execute("UPDATE jobs SET status='running'", []).unwrap();
    ecco(&alice, &worker, &["dispatcher", "run", "--once"]).unwrap();
    assert_eq!(fs::read_to_string(&calls).unwrap(), "x");
    assert_eq!(thread(&bob, "smoke").len(), 3);

    // An encrypted request gets an encrypted reply; the endpoint sees ciphertext only.
    ecco(
        &bob,
        &[],
        &[
            "send",
            "--to",
            &alice_addr,
            "--about",
            "private",
            "--kind",
            "request",
            "--encrypt",
            "secret-dispatch",
        ],
    )
    .unwrap();
    ecco(&alice, &worker, &["dispatcher", "run", "--once"]).unwrap();
    assert_eq!(fs::read_to_string(&calls).unwrap(), "xx");
    let private = thread(&bob, "private");
    let reply = private
        .iter()
        .find(|m| m["env"]["kind"] == "finding")
        .unwrap();
    assert_eq!(reply["env"]["encrypted"], true);
    assert_eq!(reply["env"]["body"]["text"], "pong");
    wait_until("private reports", || {
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e["msg"]["env"]["about"] == "private")
            .count()
            >= 2
    });
    let private_events: Vec<Value> = events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e["msg"]["env"]["about"] == "private")
        .cloned()
        .collect();
    let seen = serde_json::to_string(&private_events).unwrap();
    assert!(!seen.contains("secret-dispatch") && !seen.contains("pong"));

    let status_text = ecco(&alice, &[], &["dispatcher", "status"]).unwrap();
    assert!(status_text.contains("completed: 2"), "{status_text}");
    drop(db);
    fs::remove_dir_all(root).unwrap();
}
