//! Account authorization for hosted names. The identity is saved before this
//! flow begins. Only public profiles and purpose-bound root signatures leave it.
use ed25519_dalek::Signer;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

use crate::{envelope, identity::Identity};

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 31
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        && name.as_bytes()[0] != b'-'
}

pub(crate) fn origin(value: &str) -> Result<String, String> {
    validate_origin(value, true)
}

fn validate_origin(value: &str, secure: bool) -> Result<String, String> {
    let url = url::Url::parse(value).map_err(|_| "invalid dashboard URL")?;
    let host = url.host_str().ok_or("dashboard URL needs a host")?;
    if !matches!(url.scheme(), "http" | "https")
        || (secure
            && url.scheme() != "https"
            && !(url.scheme() == "http"
                && (host == "localhost" || host == "127.0.0.1" || host == "[::1]")))
    {
        return Err(
            "dashboard URL must use HTTPS (HTTP is allowed on loopback for development)".into(),
        );
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || url.path() != "/"
    {
        return Err("dashboard URL must be an origin without credentials, path, or query".into());
    }
    Ok(value.trim_end_matches('/').into())
}

#[derive(Default, Deserialize)]
pub struct Services {
    pub registration_url: Option<String>,
    pub reporting_url: Option<String>,
}
impl Services {
    fn decode(value: serde_json::Value) -> Result<Self, String> {
        let mut services: Self =
            serde_json::from_value(value).map_err(|_| "invalid relay service metadata")?;
        services.registration_url = services
            .registration_url
            .as_deref()
            .map(origin)
            .transpose()?;
        services.reporting_url = services
            .reporting_url
            .as_deref()
            .filter(|url| !url.is_empty())
            .and_then(|url| crate::reporting::validate_endpoint(url).ok());
        Ok(services)
    }
}
/// Optional deployment metadata. Relays without it retain ordinary registration.
pub fn discover(relay: &str) -> Result<Services, String> {
    let mut services = metadata(relay)?;
    if services.reporting_url.is_none() {
        if let Some(origin) = &services.registration_url {
            if let Ok(extra) = metadata(origin) {
                services.reporting_url = extra.reporting_url;
            }
        }
    }
    Ok(services)
}
fn metadata(relay: &str) -> Result<Services, String> {
    let relay = validate_origin(relay, false)?;
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(15))
        .build();
    let response = match agent.get(&format!("{relay}/.well-known/ecco")).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(404 | 401, _)) => return Ok(Services::default()),
        Err(e) => return Err(format!("could not discover relay services: {e}")),
    };
    let metadata = serde_json::from_reader(response.into_reader())
        .map_err(|_| "invalid relay service metadata")?;
    Services::decode(metadata)
}

#[derive(Serialize)]
struct ConnectionRequest {
    addr: String,
    profile: crate::identity::Profile,
    nonce: String,
    ts: u64,
    sig: String,
}

fn request(id: &Identity) -> ConnectionRequest {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let nonce = hex::encode(bytes);
    let ts = envelope::now();
    let profile = id.profile();
    let message = format!(
        "ecco-connect-v1\n{}\n{}\n{nonce}\n{ts}\n{}",
        id.addr(),
        profile.root,
        profile.sig
    );
    let sig = format!(
        "ed25519:{}",
        hex::encode(id.root_key().sign(message.as_bytes()).to_bytes())
    );
    ConnectionRequest {
        addr: id.addr(),
        profile,
        nonce,
        ts,
        sig,
    }
}

#[derive(Deserialize)]
struct Started {
    id: String,
    device_token: String,
}
#[derive(Deserialize)]
struct Status {
    status: String,
}

fn post<T: for<'de> Deserialize<'de>>(
    api: &str,
    path: &str,
    body: &impl Serialize,
) -> Result<T, String> {
    let client = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(20))
        .build();
    let response = client
        .post(&format!("{api}{path}"))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::to_string(body).map_err(|e| e.to_string())?)
        .map_err(|e| match e {
            ureq::Error::Status(code, response) => format!(
                "dashboard returned {code}: {}",
                response.into_string().unwrap_or_default()
            ),
            e => format!("could not reach dashboard: {e}"),
        })?;
    serde_json::from_reader(response.into_reader())
        .map_err(|e| format!("invalid dashboard response: {e}"))
}

pub fn authorize(id: &Identity, api: &str, no_browser: bool) -> Result<(), String> {
    let api = origin(api)?;
    let started: Started = post(&api, "/api/connections", &request(id))?;
    if started.id.len() != 32 || !started.id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid connection identifier from dashboard".into());
    }
    let url = format!("{api}/connect?request={}", started.id);
    println!("Open this link to authorize {}:\n{url}", id.addr());
    if !no_browser {
        let (program, args): (&str, Vec<&str>) = if cfg!(target_os = "macos") {
            ("open", vec![&url])
        } else if cfg!(target_os = "windows") {
            ("rundll32", vec!["url.dll,FileProtocolHandler", &url])
        } else {
            ("xdg-open", vec![&url])
        };
        let _ = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    let deadline = Instant::now() + Duration::from_secs(15 * 60);
    while Instant::now() < deadline {
        let status: Status = post(
            &api,
            "/api/connections/poll",
            &serde_json::json!({"deviceToken": started.device_token}),
        )?;
        match status.status.as_str() {
            "approved" => {
                println!("connected {}", id.addr());
                return Ok(());
            }
            "pending" => std::thread::sleep(Duration::from_secs(2)),
            _ => return Err(
                "authorization expired; run this command again (your saved keys will be reused)"
                    .into(),
            ),
        }
    }
    Err("authorization timed out; run this command again (your saved keys will be reused)".into())
}

pub fn transfer(id: &Identity, to: &str) -> Result<(), String> {
    envelope::decode_key(to)?;
    let ts = envelope::now();
    let message = format!("ecco-transfer-v1\n{}\n{to}\n{ts}", id.addr());
    let sig = format!(
        "ed25519:{}",
        hex::encode(id.root_key().sign(message.as_bytes()).to_bytes())
    );
    let client = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(Duration::from_secs(20))
        .build();
    let mut request = client
        .post(&format!("{}/addr/transfer", id.relay))
        .set("Content-Type", "application/json");
    if let Some(token) = &id.token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    request.send_string(&serde_json::json!({ "name": id.name, "root": id.profile().root, "to": to, "ts": ts, "sig": sig }).to_string())
        .map_err(|e| match e { ureq::Error::Status(code, r) => format!("relay returned {code}: {}", r.into_string().unwrap_or_default()), e => e.to_string() })?;
    println!("Transfer offered for {}. The recipient must run ecco init using the identity with root key {to}. Your old keys lose access when they accept.", id.addr());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovers_a_service_defined_reporting_path_through_an_existing_relay() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", server.server_addr());
        let response_origin = origin.clone();
        let worker = std::thread::spawn(move || {
            for body in [
                serde_json::json!({"registration_url":response_origin}),
                serde_json::json!({"reporting_url":format!("{response_origin}/custom/events")}),
            ] {
                let request = server
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .expect("discovery request");
                assert_eq!(request.url(), "/.well-known/ecco");
                request
                    .respond(tiny_http::Response::from_string(body.to_string()))
                    .unwrap();
            }
        });
        let services = discover(&origin).unwrap();
        assert_eq!(services.registration_url.as_deref(), Some(origin.as_str()));
        assert_eq!(
            services.reporting_url,
            Some(format!("{origin}/custom/events"))
        );
        worker.join().unwrap();
        let empty = Services::decode(serde_json::json!({})).unwrap();
        assert!(empty.registration_url.is_none() && empty.reporting_url.is_none());
        let mixed = Services::decode(serde_json::json!({
            "registration_url":"https://dash.test",
            "reporting_url":"http://remote.test/events"
        }))
        .unwrap();
        assert_eq!(mixed.registration_url.as_deref(), Some("https://dash.test"));
        assert!(mixed.reporting_url.is_none());
        for url in [
            "",
            "http://remote.test/events",
            "https://user:secret@service.test/events",
            "https://service.test/events?token=secret",
            "https://service.test/events#fragment",
        ] {
            let decoded = Services::decode(serde_json::json!({"reporting_url":url})).unwrap();
            assert!(decoded.reporting_url.is_none(), "{url}");
        }
    }
    #[test]
    fn reporting_discovery_failures_do_not_block_registration() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", server.server_addr());
        let response_origin = origin.clone();
        let worker = std::thread::spawn(move || {
            let request = server
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .expect("relay discovery");
            request
                .respond(tiny_http::Response::from_string(
                    serde_json::json!({"registration_url":response_origin}).to_string(),
                ))
                .unwrap();
            let request = server
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .expect("registration-origin discovery");
            request.respond(tiny_http::Response::empty(500)).unwrap();
        });
        let services = discover(&origin).unwrap();
        assert_eq!(services.registration_url.as_deref(), Some(origin.as_str()));
        assert!(services.reporting_url.is_none());
        worker.join().unwrap();
    }
    #[test]
    fn accepts_only_safe_origins_and_names() {
        for name in ["alice", "agent-1", &"a".repeat(31)] {
            assert!(valid_name(name));
        }
        for name in ["", "Alice", "-flag", "a/b", &"a".repeat(32)] {
            assert!(!valid_name(name));
        }
        for url in [
            "https://dashboard.example",
            "http://localhost:3000",
            "https://app.example/",
        ] {
            assert!(origin(url).is_ok(), "{url}");
        }
        for url in [
            "http://app.example",
            "https://a@b",
            "https://app.example/path",
            "https://app.example/?secret=x",
        ] {
            assert!(origin(url).is_err(), "{url}");
        }
    }
}
