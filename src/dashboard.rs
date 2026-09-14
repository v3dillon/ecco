//! Signed dashboard requests and one durable trace outbox per identity.
use crate::{identity::Identity, local};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub api: String,
}
pub fn configure(home: &Path, api: &str) -> Result<(), String> {
    let api = crate::registration::origin(api)?;
    local::write(
        &home.join("dashboard.json"),
        &serde_json::to_vec(&Config { api }).unwrap(),
    )
}
pub fn api(home: &Path, override_url: Option<&str>) -> Result<String, String> {
    if let Some(api) = override_url {
        return crate::registration::origin(api);
    }
    let config: Config = serde_json::from_str(&local::read(&home.join("dashboard.json"), 4096)?)
        .map_err(|e| e.to_string())?;
    crate::registration::origin(&config.api)
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
        .map_err(|e| format!("dashboard upload: {e}"))?;
    serde_json::from_reader(response.into_reader()).map_err(|e| e.to_string())
}
#[derive(Serialize, Deserialize)]
struct Pending {
    format: String,
    body: String,
}
pub struct Outbox {
    dir: PathBuf,
    api: String,
    id: Identity,
}
impl Outbox {
    pub fn open(home: &Path, api: String) -> Result<Self, String> {
        let id = Identity::load(home)?;
        let dir = home
            .join("trace-outbox")
            .join(local::sha256(format!("{api}\n{}", id.addr())));
        Ok(Self { dir, api, id })
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
        local::write(
            &self.dir.join(format!("{}.json", local::sha256(&data))),
            &data,
        )
    }
    pub fn flush(&self, limit: usize) -> Result<usize, String> {
        if !self.dir.exists() {
            return Ok(0);
        }
        let mut files: Vec<_> = fs::read_dir(&self.dir)
            .map_err(|e| e.to_string())?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        files.sort();
        let count = files.len();
        for path in files.iter().take(limit) {
            let content = match local::read(path, 32 * 1024 * 1024) {
                Ok(c) => c,
                Err(_) if !path.exists() => continue,
                Err(e) => return Err(e),
            };
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
                .ok_or("dashboard returned no trace hash")?;
            let _ = fs::remove_file(path);
            eprintln!("uploaded {}/traces/{hash}", self.api);
        }
        Ok(count.saturating_sub(limit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    #[test]
    fn signed_upload_retries_survive_restart_and_require_an_acknowledgement() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let api = format!("http://{}", server.server_addr());
        let home = std::env::temp_dir().join(format!("ecco-dashboard-{}", rand::random::<u64>()));
        let id = Identity::generate("alice", "https://relay.test", None);
        id.save(&home).unwrap();
        configure(&home, &api).unwrap();
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
        assert_eq!(fs::read_dir(&queue.dir).unwrap().count(), 1);
        assert!(queue.flush(3).is_err());
        let restarted = Outbox::open(&home, api.clone()).unwrap();
        assert!(restarted.flush(3).is_err());
        assert_eq!(fs::read_dir(&queue.dir).unwrap().count(), 1);
        assert_ne!(
            Outbox::open(&home, "https://other.test".into())
                .unwrap()
                .dir,
            queue.dir
        );
        assert_eq!(restarted.flush(3).unwrap(), 0);
        assert_eq!(fs::read_dir(&queue.dir).unwrap().count(), 0);
        worker.join().unwrap();
        fs::remove_dir_all(home).unwrap();
    }
}
