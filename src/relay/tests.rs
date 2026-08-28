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
        allow_roots: false,
        allowed_roots: Mutex::new(None),
        limiter: Limiter {
            buckets: Mutex::new(HashMap::new()),
        },
        wakes: Mutex::new(HashMap::new()),
        blocking: Arc::new(Semaphore::new(16)),
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

fn spawn(r: Relay) -> (u16, std::sync::Arc<Relay>) {
    let relay = std::sync::Arc::new(r);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let rel = relay.clone();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let app = router(rel);
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
    });
    (port, relay)
}

fn signed_get(port: u16, path: &str, id: &Identity) -> u16 {
    use ed25519_dalek::Signer;
    let ts = envelope::now();
    let sig = id
        .agent_key()
        .sign(&crate::identity::request_signing_bytes("GET", path, ts));
    match ureq::get(&format!("http://127.0.0.1:{port}{path}"))
        .timeout(Duration::from_secs(2))
        .set("x-ecco-addr", &id.addr())
        .set("x-ecco-key", &encode_key(&id.agent_key().verifying_key()))
        .set("x-ecco-ts", &ts.to_string())
        .set(
            "x-ecco-sig",
            &format!("ed25519:{}", hex::encode(sig.to_bytes())),
        )
        .call()
    {
        Ok(resp) => resp.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(_) => 0,
    }
}

fn query(key: &str, wait: u64) -> HashMap<String, String> {
    HashMap::from([
        ("addr".into(), key.into()),
        ("since".into(), "0".into()),
        ("wait".into(), wait.to_string()),
    ])
}

#[test]
fn more_than_sixteen_http_long_polls_do_not_starve_posts() {
    let mut relay = relay();
    relay.signed = false;
    let alice = Identity::generate("alice", "http://localhost:4200", None);
    let bob = Identity::generate("bob", "http://localhost:4200", None);
    relay.store.register(alice.profile()).unwrap();
    relay.store.register(bob.profile()).unwrap();
    let (port, relay) = spawn(relay);
    let path = format!("/inbox?addr={}&since=0&wait=2", bob.addr());
    let mut polls = Vec::new();
    for _ in 0..24 {
        let path = path.clone();
        polls.push(std::thread::spawn(move || {
            ureq::get(&format!("http://127.0.0.1:{port}{path}"))
                .timeout(Duration::from_secs(3))
                .call()
                .unwrap()
                .into_string()
                .unwrap()
        }));
    }
    for _ in 0..100 {
        if relay.wakes.lock().unwrap().len() == 1 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(relay.wakes.lock().unwrap().len(), 1);
    let env = Envelope::seal(
        "topic".into(),
        json!({ "text": "hello" }),
        alice.addr(),
        "note".into(),
        vec![],
        vec![bob.addr()],
        envelope::now(),
        &alice.agent_key(),
    );
    let start = std::time::Instant::now();
    let posted = ureq::post(&format!("http://127.0.0.1:{port}/msgs"))
        .timeout(Duration::from_secs(2))
        .send_string(&serde_json::to_string(&env).unwrap())
        .unwrap();
    assert_eq!(posted.status(), 200);
    assert!(start.elapsed() < Duration::from_secs(1));
    for poll in polls {
        let body = poll.join().unwrap();
        assert!(body.contains(&env.id));
    }
    assert!(relay.wakes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn thread_signal_does_not_wake_inbox_waiter() {
    let relay = Arc::new(relay());
    let task = tokio::spawn({
        let relay = relay.clone();
        async move { poll(relay, query("alice@localhost:4200", 2), false).await }
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    relay.signal("thread:topic");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!task.is_finished());
    relay.signal("inbox:alice@localhost:4200");
    assert_eq!(task.await.unwrap().unwrap(), "{\"msgs\":[]}");
    assert!(relay.wakes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn one_time_poll_releases_its_waiter_key() {
    let relay = Arc::new(relay());
    poll(relay.clone(), query("arbitrary@localhost:4200", 0), false)
        .await
        .unwrap();
    assert!(relay.wakes.lock().unwrap().is_empty());
}

#[test]
fn signal_removes_a_stale_waiter_key() {
    let relay = Arc::new(relay());
    let waiter = Waiter::subscribe(relay.clone(), "inbox:alice".into());
    let stale = Arc::downgrade(&waiter.notify);
    drop(waiter);
    relay
        .wakes
        .lock()
        .unwrap()
        .insert("inbox:alice".into(), stale);

    relay.signal("inbox:alice");

    assert!(relay.wakes.lock().unwrap().is_empty());
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
    let (port, _) = spawn(r);
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
fn http_rejects_body_over_64_kib() {
    let mut r = relay();
    r.signed = false;
    let (port, _) = spawn(r);
    let body = "x".repeat(MAX_BODY_BYTES as usize + 1);
    match ureq::post(&format!("http://127.0.0.1:{port}/msgs"))
        .timeout(Duration::from_secs(2))
        .send_string(&body)
    {
        Err(ureq::Error::Status(413, _)) => {}
        other => panic!("expected 413 for an oversized body, got {other:?}"),
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
    r.allow_roots = true;
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

fn root(n: u8) -> String {
    format!("ed25519:{:064x}", n)
}

#[test]
fn parse_limits_distinguishes_missing_malformed_and_empty_allowed_roots() {
    let good = root(1);
    let w = parse_limits(&json!({
        "allowedRoots": [good],
        "addresses": { "alice@x": { "retentionDays": 7 } },
        "plans": { "guest": { "retentionDays": 3 } }
    }));
    assert_eq!(w.allowed_roots, Some(vec![root(1)]));
    assert_eq!(w.guest_days, Some(3));
    assert_eq!(w.per_sender, vec![("alice@x".into(), 7)]);

    let missing = parse_limits(&json!({
        "addresses": { "alice@x": { "retentionDays": 7 } }
    }));
    assert!(missing.allowed_roots.is_none());
    assert_eq!(missing.per_sender.len(), 1);

    let not_array = parse_limits(&json!({ "allowedRoots": "ed25519:nope" }));
    assert!(not_array.allowed_roots.is_none());

    let bad_format = parse_limits(&json!({ "allowedRoots": ["ed25519:AA"] }));
    assert!(bad_format.allowed_roots.is_none());

    let uppercase = parse_limits(&json!({
        "allowedRoots": [format!("ed25519:{}", "A".repeat(64))]
    }));
    assert!(uppercase.allowed_roots.is_none());

    let mixed = parse_limits(&json!({ "allowedRoots": [root(1), "ed25519:zz"] }));
    assert!(mixed.allowed_roots.is_none());

    let empty = parse_limits(&json!({ "allowedRoots": [] }));
    assert_eq!(empty.allowed_roots, Some(vec![]));
}

#[test]
fn malformed_allowed_roots_keep_last_good_and_empty_locks() {
    let alice = Identity::generate("alice", "http://localhost:4200", None);
    let alice_body = serde_json::to_string(&alice.profile()).unwrap();
    let mut r = relay();
    r.allow_roots = true;
    *r.allowed_roots.lock().unwrap() = Some(HashSet::from([alice.profile().root]));
    let malformed = parse_limits(&json!({
        "allowedRoots": ["not-a-root"],
        "addresses": { "alice@x": { "retentionDays": 7 } }
    }));
    assert!(malformed.allowed_roots.is_none());
    r.post_addr(&alice_body, "1.1.1.1").unwrap();

    let locked = parse_limits(&json!({ "allowedRoots": [] }));
    if let Some(roots) = locked.allowed_roots {
        *r.allowed_roots.lock().unwrap() = Some(roots.into_iter().collect());
    }
    let (code, _) = r.post_addr(&alice_body, "1.1.1.1").unwrap_err();
    assert_eq!(code, 403);
}

#[test]
fn allow_roots_requires_limits_url_before_listen() {
    let dir = std::env::temp_dir().join(format!(
        "ecco-relay-cfg-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let err = super::run(
        1,
        dir,
        None,
        false,
        "localhost:1".into(),
        true,
        Retention::default(),
    )
    .unwrap_err();
    assert!(err.contains("limits-url") || err.contains("LIMITS_URL"));
}

#[test]
fn allow_roots_requires_signed_reads_before_listen() {
    let dir = std::env::temp_dir().join(format!(
        "ecco-relay-signed-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let err = super::run(
        1,
        dir,
        None,
        false,
        "localhost:1".into(),
        true,
        Retention {
            limits_url: Some("https://example.invalid/limits.json".into()),
            default_days: None,
        },
    )
    .unwrap_err();
    assert!(err.contains("--signed") || err.contains("ECCO_RELAY_SIGNED"));
}

#[test]
fn allowlist_removal_blocks_signed_read() {
    let alice = Identity::generate("alice", "http://localhost:4200", None);
    let mut r = relay();
    r.allow_roots = true;
    *r.allowed_roots.lock().unwrap() = Some(HashSet::from([alice.profile().root.clone()]));
    r.post_addr(&serde_json::to_string(&alice.profile()).unwrap(), "1.1.1.1")
        .unwrap();
    post(&r, &alice, "gh:x", &[], "hi").unwrap();
    let (port, relay) = spawn(r);

    let path = "/threads?about=gh%3Ax&since=0&wait=0";
    assert_eq!(signed_get(port, path, &alice), 200);
    *relay.allowed_roots.lock().unwrap() = Some(HashSet::new());
    assert_eq!(signed_get(port, path, &alice), 403);
}
