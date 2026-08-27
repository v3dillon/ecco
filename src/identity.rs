//! Identity: root key (human), delegated agent subkeys, profile documents. PROTOCOL.md §1.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::envelope::{self, decode_key, decode_prefixed, encode_key};

/// Kinds an agent subkey may sign. Everything except `decision`.
pub const AGENT_KINDS: &[&str] = &["note", "claim", "release", "request", "finding", "proposal"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    pub addr: String,
    pub exp: u64,
    pub key: String,
    pub kinds: Vec<String>,
    pub sig: String,
}

#[derive(Serialize)]
struct DelegationSigningView<'a> {
    addr: &'a str,
    exp: u64,
    key: &'a str,
    kinds: &'a [String],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub kind: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    pub delegations: Vec<Delegation>,
    pub endpoints: Vec<Endpoint>,
    pub name: String,
    pub root: String,
    pub sig: String,
    pub v: u8,
}

#[derive(Serialize)]
struct ProfileSigningView<'a> {
    delegations: &'a [Delegation],
    endpoints: &'a [Endpoint],
    name: &'a str,
    root: &'a str,
    v: u8,
}

impl Profile {
    fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&ProfileSigningView {
            delegations: &self.delegations,
            endpoints: &self.endpoints,
            name: &self.name,
            root: &self.root,
            v: self.v,
        })
        .expect("canonical encoding")
    }

    pub fn verify(&self) -> Result<(), String> {
        let root = decode_key(&self.root)?;
        let sig: [u8; 64] = decode_prefixed(&self.sig, "ed25519:")?
            .try_into()
            .map_err(|_| "bad signature length".to_string())?;
        root.verify(&self.signing_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| "bad profile signature".to_string())
    }

    /// PROTOCOL.md §2 verification steps 3–4: is `key` allowed to sign `kind` as this identity?
    pub fn authorizes(&self, key: &str, kind: &str, at: u64) -> Result<(), String> {
        if key == self.root {
            return Ok(());
        }
        if kind == "decision" {
            return Err("decision requires the root (human) key".into());
        }
        let d = self
            .delegations
            .iter()
            .find(|d| d.key == key)
            .ok_or("key not delegated by this identity")?;
        if d.exp <= at {
            return Err("delegation expired".into());
        }
        if !d.kinds.iter().any(|k| k == kind) {
            return Err(format!("delegation does not permit kind '{kind}'"));
        }
        let root = decode_key(&self.root)?;
        let sig: [u8; 64] = decode_prefixed(&d.sig, "ed25519:")?
            .try_into()
            .map_err(|_| "bad delegation signature length".to_string())?;
        let bytes = serde_json::to_vec(&DelegationSigningView {
            addr: &d.addr,
            exp: d.exp,
            key: &d.key,
            kinds: &d.kinds,
        })
        .expect("canonical encoding");
        root.verify(&bytes, &Signature::from_bytes(&sig))
            .map_err(|_| "bad delegation signature".to_string())
    }
}

/// Local identity file: both secrets in v0. The root secret should eventually
/// live somewhere colder than the agent's disk; v0 optimizes for two people
/// getting started in two minutes.
#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub name: String,
    pub relay: String,
    pub root_secret: String,
    pub agent_secret: String,
    /// Transport-level bearer token for a private relay (PROTOCOL.md §5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl Identity {
    pub fn addr(&self) -> String {
        format!("{}@{}", self.name, authority(&self.relay))
    }

    pub fn root_key(&self) -> SigningKey {
        signing_key(&self.root_secret)
    }

    pub fn agent_key(&self) -> SigningKey {
        signing_key(&self.agent_secret)
    }

    pub fn generate(name: &str, relay: &str, token: Option<String>) -> Identity {
        let mut rng = rand::rngs::OsRng;
        Identity {
            name: name.to_string(),
            relay: relay.trim_end_matches('/').to_string(),
            root_secret: hex::encode(SigningKey::generate(&mut rng).to_bytes()),
            agent_secret: hex::encode(SigningKey::generate(&mut rng).to_bytes()),
            token,
        }
    }

    /// Build the signed profile: one delegation for the agent key, one relay endpoint.
    pub fn profile(&self) -> Profile {
        let root = self.root_key();
        let addr = self.addr();
        let kinds: Vec<String> = AGENT_KINDS.iter().map(|s| s.to_string()).collect();
        let agent_pub = encode_key(&self.agent_key().verifying_key());
        let exp = envelope::now() + 365 * 24 * 3600;
        let bytes = serde_json::to_vec(&DelegationSigningView {
            addr: &addr,
            exp,
            key: &agent_pub,
            kinds: &kinds,
        })
        .expect("canonical encoding");
        let dsig = root.sign(&bytes);
        let mut profile = Profile {
            delegations: vec![Delegation {
                addr,
                exp,
                key: agent_pub,
                kinds,
                sig: format!("ed25519:{}", hex::encode(dsig.to_bytes())),
            }],
            endpoints: vec![Endpoint {
                kind: "relay".into(),
                url: self.relay.clone(),
            }],
            name: self.name.clone(),
            root: encode_key(&root.verifying_key()),
            sig: String::new(),
            v: 0,
        };
        let sig = root.sign(&profile.signing_bytes());
        profile.sig = format!("ed25519:{}", hex::encode(sig.to_bytes()));
        profile
    }

    pub fn save(&self, home: &Path) -> Result<(), String> {
        fs::create_dir_all(home).map_err(|e| e.to_string())?;
        let path = home.join("identity.json");
        fs::write(&path, serde_json::to_string_pretty(self).unwrap()).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn load(home: &Path) -> Result<Identity, String> {
        let raw = fs::read_to_string(home.join("identity.json"))
            .map_err(|_| format!("no identity at {} — run `ecco init` first", home.display()))?;
        serde_json::from_str(&raw).map_err(|e| e.to_string())
    }
}

fn signing_key(secret_hex: &str) -> SigningKey {
    let bytes: [u8; 32] = hex::decode(secret_hex)
        .expect("valid secret hex")
        .try_into()
        .expect("32-byte secret");
    SigningKey::from_bytes(&bytes)
}

/// `https://relay.ecco.to` -> `relay.ecco.to`; `http://localhost:4200` -> `localhost:4200`
pub fn authority(url: &str) -> String {
    url.trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string()
}

/// `name@localhost:4200` -> `http://localhost:4200`; otherwise https.
pub fn addr_relay_url(addr: &str) -> Result<String, String> {
    let authority = addr
        .split_once('@')
        .ok_or_else(|| format!("'{addr}' is not name@authority"))?
        .1;
    let scheme = if authority.starts_with("localhost") || authority.starts_with("127.") {
        "http"
    } else {
        "https"
    };
    Ok(format!("{scheme}://{authority}"))
}

pub fn default_home() -> PathBuf {
    if let Ok(h) = std::env::var("ECCO_HOME") {
        return PathBuf::from(h);
    }
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".ecco")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Envelope;
    use serde_json::json;

    fn seal(id: &Identity, kind: &str, key: &SigningKey) -> Envelope {
        Envelope::seal(
            "gh:acme/app/pull/13".into(),
            json!({"text": "x"}),
            id.addr(),
            kind.into(),
            vec![],
            vec![],
            envelope::now(),
            key,
        )
    }

    #[test]
    fn agent_key_can_propose_but_not_decide() {
        let id = Identity::generate("alice", "http://localhost:4200", None);
        let profile = id.profile();
        profile.verify().unwrap();
        let now = envelope::now();

        let proposal = seal(&id, "proposal", &id.agent_key());
        proposal.verify().unwrap();
        profile.authorizes(&proposal.key, "proposal", now).unwrap();

        // The human-in-the-loop rule: a decision signed by the agent subkey is invalid.
        let forged = seal(&id, "decision", &id.agent_key());
        forged.verify().unwrap(); // structurally fine...
        assert!(profile.authorizes(&forged.key, "decision", now).is_err());

        let real = seal(&id, "decision", &id.root_key());
        profile.authorizes(&real.key, "decision", now).unwrap();
    }

    #[test]
    fn tampered_envelope_fails_verification() {
        let id = Identity::generate("alice", "http://localhost:4200", None);
        let mut env = seal(&id, "finding", &id.agent_key());
        env.body = json!({"text": "reworded after signing"});
        assert!(env.verify().is_err());
    }

    #[test]
    fn expired_delegation_is_rejected() {
        let id = Identity::generate("alice", "http://localhost:4200", None);
        let profile = id.profile();
        let past_expiry = profile.delegations[0].exp + 1;
        let env = seal(&id, "note", &id.agent_key());
        assert!(profile.authorizes(&env.key, "note", past_expiry).is_err());
    }

    #[test]
    fn foreign_key_is_rejected() {
        let alice = Identity::generate("alice", "http://localhost:4200", None);
        let mallory = Identity::generate("mallory", "http://localhost:4200", None);
        let env = seal(&alice, "note", &mallory.agent_key());
        env.verify().unwrap(); // signature is internally consistent...
        // ...but mallory's key holds no delegation from alice's root.
        assert!(alice.profile().authorizes(&env.key, "note", envelope::now()).is_err());
    }
}
