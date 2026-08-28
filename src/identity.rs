//! Identity: root key (human), delegated agent subkeys, profile documents. README §1.

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

    /// README §2 verification steps 3–4: is `key` allowed to sign `kind` as this identity?
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
        self.verify_delegation(d)
    }

    /// auth-v0 (README §5): may `key` read as this identity? Root, or any
    /// unexpired delegated subkey — kind scoping is a write concern.
    pub fn authorizes_read(&self, key: &str, at: u64) -> Result<(), String> {
        if key == self.root {
            return Ok(());
        }
        let d = self
            .delegations
            .iter()
            .find(|d| d.key == key)
            .ok_or("key not delegated by this identity")?;
        if d.exp <= at {
            return Err("delegation expired".into());
        }
        self.verify_delegation(d)
    }

    fn verify_delegation(&self, d: &Delegation) -> Result<(), String> {
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

/// auth-v0 canonical request string: `{METHOD}\n{path-and-query}\n{ts}`.
pub fn request_signing_bytes(method: &str, path_query: &str, ts: u64) -> Vec<u8> {
    format!("{method}\n{path_query}\n{ts}").into_bytes()
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
    /// Transport-level bearer token for a private relay (README §5).
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

    /// Load this home's identity, or generate and save a new one.
    /// Same-name retry is allowed so a failed registration can run again
    /// without losing keys. A different name or relay in this home is an
    /// error. A file that exists but does not parse is not overwritten.
    pub fn prepare(
        home: &Path,
        name: &str,
        relay: &str,
        token: Option<String>,
    ) -> Result<Identity, String> {
        let path = home.join("identity.json");
        if path.exists() {
            let mut existing = Self::load(home).map_err(|e| {
                format!(
                    "identity at {} is unreadable ({e}); not overwritten",
                    path.display()
                )
            })?;
            if existing.name != name {
                return Err(format!(
                    "identity already exists at {} as {} (use --home for another)",
                    home.display(),
                    existing.name
                ));
            }
            let relay = relay.trim_end_matches('/');
            if existing.relay != relay {
                return Err(format!(
                    "identity already exists at {} for {} (use --home for another)",
                    home.display(),
                    existing.relay
                ));
            }
            if token.is_some() && existing.token != token {
                existing.token = token;
                existing.save(home)?;
            }
            return Ok(existing);
        }
        let id = Self::generate(name, relay, token);
        id.save(home)?;
        Ok(id)
    }

    /// Build the signed profile: one delegation for the agent key, one relay endpoint.
    pub fn profile(&self) -> Profile {
        self.sign_profile(
            vec![self.agent_delegation()],
            vec![Endpoint {
                kind: "relay".into(),
                url: self.relay.clone(),
            }],
        )
    }

    /// Deactivation: no delegations, no endpoints. The agent key stops
    /// working everywhere; the root key still owns the name (README §1).
    pub fn profile_revoked(&self) -> Profile {
        self.sign_profile(vec![], vec![])
    }

    fn agent_delegation(&self) -> Delegation {
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
        let dsig = self.root_key().sign(&bytes);
        Delegation {
            addr,
            exp,
            key: agent_pub,
            kinds,
            sig: format!("ed25519:{}", hex::encode(dsig.to_bytes())),
        }
    }

    fn sign_profile(&self, delegations: Vec<Delegation>, endpoints: Vec<Endpoint>) -> Profile {
        let root = self.root_key();
        let mut profile = Profile {
            delegations,
            endpoints,
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

/// Client-side contact policy (README §4): addr -> "approved" | "blocked".
/// This gates what reaches the *agent*; the relay stores envelopes regardless.
pub type Contacts = std::collections::HashMap<String, String>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Standing {
    Trusted,
    Unknown,
    Blocked,
}

pub fn contacts_load(home: &Path) -> Contacts {
    fs::read_to_string(home.join("contacts.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn contacts_set(home: &Path, addr: &str, status: &str) -> Result<(), String> {
    let mut contacts = contacts_load(home);
    contacts.insert(addr.to_string(), status.to_string());
    fs::create_dir_all(home).map_err(|e| e.to_string())?;
    fs::write(
        home.join("contacts.json"),
        serde_json::to_string_pretty(&contacts).unwrap(),
    )
    .map_err(|e| e.to_string())
}

pub fn standing(contacts: &Contacts, self_addr: &str, from: &str) -> Standing {
    if from == self_addr {
        return Standing::Trusted;
    }
    match contacts.get(from).map(String::as_str) {
        Some("approved") => Standing::Trusted,
        Some("blocked") => Standing::Blocked,
        _ => Standing::Unknown,
    }
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    fn temp_home() -> PathBuf {
        std::env::temp_dir().join(format!(
            "ecco-id-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ))
    }

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
    fn revoked_profile_keeps_the_name_and_rejects_the_agent_key() {
        let id = Identity::generate("alice", "http://localhost:4200", None);
        let revoked = id.profile_revoked();
        revoked.verify().unwrap();
        assert_eq!(revoked.name, id.profile().name);
        assert_eq!(revoked.root, id.profile().root);
        assert!(revoked.delegations.is_empty());
        let now = envelope::now();
        let agent_pub = encode_key(&id.agent_key().verifying_key());
        assert!(revoked.authorizes(&agent_pub, "note", now).is_err());
        assert!(revoked.authorizes_read(&agent_pub, now).is_err());
        // The human can still act, and the same root can republish later.
        let root_pub = encode_key(&id.root_key().verifying_key());
        revoked.authorizes(&root_pub, "decision", now).unwrap();
    }

    #[test]
    fn contact_standing_rules() {
        let mut c = Contacts::new();
        c.insert("bob@x".into(), "approved".into());
        c.insert("eve@x".into(), "blocked".into());
        assert_eq!(standing(&c, "alice@x", "alice@x"), Standing::Trusted); // self always
        assert_eq!(standing(&c, "alice@x", "bob@x"), Standing::Trusted);
        assert_eq!(standing(&c, "alice@x", "eve@x"), Standing::Blocked);
        assert_eq!(standing(&c, "alice@x", "stranger@x"), Standing::Unknown);
    }

    #[test]
    fn auth_v0_read_authorization() {
        let id = Identity::generate("alice", "http://localhost:4200", None);
        let profile = id.profile();
        let now = envelope::now();
        let agent_pub = encode_key(&id.agent_key().verifying_key());
        let root_pub = encode_key(&id.root_key().verifying_key());
        profile.authorizes_read(&agent_pub, now).unwrap();
        profile.authorizes_read(&root_pub, now).unwrap();
        assert!(profile
            .authorizes_read(&agent_pub, profile.delegations[0].exp + 1)
            .is_err()); // expired delegation
        let mallory = Identity::generate("mallory", "http://localhost:4200", None);
        let mk = encode_key(&mallory.agent_key().verifying_key());
        assert!(profile.authorizes_read(&mk, now).is_err()); // undelegated key

        // request signature binds method, path+query, and timestamp
        let path = "/inbox?addr=alice%40localhost%3A4200&since=0&wait=0";
        let sig = id
            .agent_key()
            .sign(&request_signing_bytes("GET", path, now));
        let vk = id.agent_key().verifying_key();
        vk.verify(&request_signing_bytes("GET", path, now), &sig)
            .unwrap();
        assert!(vk
            .verify(&request_signing_bytes("GET", path, now + 1), &sig)
            .is_err());
        assert!(vk
            .verify(
                &request_signing_bytes("GET", "/inbox?addr=other", now),
                &sig
            )
            .is_err());
    }

    #[test]
    fn sealed_body_roundtrip() {
        let alice = Identity::generate("alice", "http://localhost:4200", None);
        let bob = Identity::generate("bob", "http://localhost:4200", None);
        let body = json!({ "text": "secret finding" });
        let sealed = envelope::seal_body(
            &body,
            &[
                (alice.addr(), alice.root_key().verifying_key()),
                (bob.addr(), bob.root_key().verifying_key()),
            ],
        )
        .unwrap();
        assert!(envelope::is_encrypted(&sealed));
        // both recipients (sender sealed to itself) recover the body
        assert_eq!(
            envelope::open_body(&sealed, &alice.addr(), &alice.root_key()),
            Some(body.clone())
        );
        assert_eq!(
            envelope::open_body(&sealed, &bob.addr(), &bob.root_key()),
            Some(body)
        );
        // wrong key, and an address it was never sealed to, both fail closed
        assert_eq!(
            envelope::open_body(&sealed, &bob.addr(), &alice.root_key()),
            None
        );
        assert_eq!(
            envelope::open_body(&sealed, "carol@localhost:4200", &bob.root_key()),
            None
        );
    }

    #[test]
    fn foreign_key_is_rejected() {
        let alice = Identity::generate("alice", "http://localhost:4200", None);
        let mallory = Identity::generate("mallory", "http://localhost:4200", None);
        let env = seal(&alice, "note", &mallory.agent_key());
        env.verify().unwrap(); // signature is internally consistent...
                               // ...but mallory's key holds no delegation from alice's root.
        assert!(alice
            .profile()
            .authorizes(&env.key, "note", envelope::now())
            .is_err());
    }

    #[test]
    fn prepare_saves_keys_before_register_and_retries_the_same_name() {
        let home = temp_home();
        let first = Identity::prepare(&home, "alice", "http://localhost:4200", None).unwrap();
        assert!(home.join("identity.json").exists());
        let again = Identity::prepare(&home, "alice", "http://localhost:4200", None).unwrap();
        assert_eq!(first.root_secret, again.root_secret);
        assert_eq!(first.agent_secret, again.agent_secret);
        let err = Identity::prepare(&home, "bob", "http://localhost:4200", None)
            .err()
            .expect("different name must fail");
        assert!(err.contains("already exists"));
        let with_token = Identity::prepare(
            &home,
            "alice",
            "http://localhost:4200",
            Some("s3cret".into()),
        )
        .unwrap();
        assert_eq!(with_token.token.as_deref(), Some("s3cret"));
        assert_eq!(with_token.root_secret, first.root_secret);
        let err = Identity::prepare(&home, "alice", "http://localhost:9999", None)
            .err()
            .expect("different relay must fail");
        assert!(err.contains("already exists"));
        assert_eq!(
            Identity::load(&home).unwrap().root_secret,
            first.root_secret
        );
    }

    #[test]
    fn prepare_does_not_overwrite_a_corrupt_identity() {
        let home = temp_home();
        std::fs::create_dir_all(&home).unwrap();
        let path = home.join("identity.json");
        std::fs::write(&path, "{not-json").unwrap();
        let err = Identity::prepare(&home, "alice", "http://localhost:4200", None)
            .err()
            .expect("corrupt identity must fail");
        assert!(err.contains("not overwritten"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{not-json");
    }
}
