//! The envelope: signed, content-addressed, transport-independent. README §2–§4.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const KINDS: &[&str] = &[
    "note", "claim", "release", "request", "finding", "proposal", "decision",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub id: String,
    pub about: String,
    pub body: Value,
    pub from: String,
    pub key: String,
    pub kind: String,
    pub prev: Vec<String>,
    pub sig: String,
    pub to: Vec<String>,
    pub ts: u64,
    pub v: u8,
}

// Canonical views: serde_json emits struct fields in declaration order, and these
// are declared alphabetically, satisfying README §3.
#[derive(Serialize)]
struct SigningView<'a> {
    about: &'a str,
    body: &'a Value,
    from: &'a str,
    key: &'a str,
    kind: &'a str,
    prev: &'a [String],
    to: &'a [String],
    ts: u64,
    v: u8,
}

#[derive(Serialize)]
struct IdView<'a> {
    about: &'a str,
    body: &'a Value,
    from: &'a str,
    key: &'a str,
    kind: &'a str,
    prev: &'a [String],
    sig: &'a str,
    to: &'a [String],
    ts: u64,
    v: u8,
}

impl Envelope {
    fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&SigningView {
            about: &self.about,
            body: &self.body,
            from: &self.from,
            key: &self.key,
            kind: &self.kind,
            prev: &self.prev,
            to: &self.to,
            ts: self.ts,
            v: self.v,
        })
        .expect("canonical encoding")
    }

    fn computed_id(&self) -> String {
        let bytes = serde_json::to_vec(&IdView {
            about: &self.about,
            body: &self.body,
            from: &self.from,
            key: &self.key,
            kind: &self.kind,
            prev: &self.prev,
            sig: &self.sig,
            to: &self.to,
            ts: self.ts,
            v: self.v,
        })
        .expect("canonical encoding");
        format!("b3:{}", hex::encode(blake3::hash(&bytes).as_bytes()))
    }

    /// Build and sign an envelope. The parameters mirror the wire fields in
    /// README §2 one-to-one; a params struct would only rename them.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        about: String,
        body: Value,
        from: String,
        kind: String,
        prev: Vec<String>,
        to: Vec<String>,
        ts: u64,
        signing_key: &SigningKey,
    ) -> Envelope {
        let mut env = Envelope {
            id: String::new(),
            about,
            body,
            from,
            key: encode_key(&signing_key.verifying_key()),
            kind,
            prev,
            sig: String::new(),
            to,
            ts,
            v: 0,
        };
        let sig: Signature = signing_key.sign(&env.signing_bytes());
        env.sig = format!("ed25519:{}", hex::encode(sig.to_bytes()));
        env.id = env.computed_id();
        env
    }

    /// Structural verification: id and signature (README §2 steps 1–2).
    /// Delegation rules (steps 3–4) need a Profile and live in identity.rs.
    pub fn verify(&self) -> Result<(), String> {
        if !KINDS.contains(&self.kind.as_str()) {
            return Err(format!("unknown kind '{}'", self.kind));
        }
        if self.about.is_empty() {
            return Err("empty about".into());
        }
        if self.computed_id() != self.id {
            return Err("id does not match content".into());
        }
        let key = decode_key(&self.key)?;
        let sig_bytes: [u8; 64] = decode_prefixed(&self.sig, "ed25519:")?
            .try_into()
            .map_err(|_| "bad signature length".to_string())?;
        key.verify(&self.signing_bytes(), &Signature::from_bytes(&sig_bytes))
            .map_err(|_| "bad signature".to_string())
    }
}

pub fn encode_key(key: &VerifyingKey) -> String {
    format!("ed25519:{}", hex::encode(key.to_bytes()))
}

pub fn decode_key(s: &str) -> Result<VerifyingKey, String> {
    let bytes: [u8; 32] = decode_prefixed(s, "ed25519:")?
        .try_into()
        .map_err(|_| "bad key length".to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "invalid key".into())
}

pub fn decode_prefixed(s: &str, prefix: &str) -> Result<Vec<u8>, String> {
    let hex_part = s
        .strip_prefix(prefix)
        .ok_or_else(|| format!("expected '{prefix}' prefix"))?;
    hex::decode(hex_part).map_err(|_| "bad hex".into())
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_secs()
}

// ---- enc-v0 (README §6) ----
// Libsodium-compatible sealed boxes over X25519 keys derived from the existing
// Ed25519 root keys (standard birational map). The encrypted object replaces
// `body`; signing, ids, and the relay are untouched — the relay stores
// ciphertext it cannot read.

pub fn is_encrypted(body: &Value) -> bool {
    body.get("enc").and_then(Value::as_str) == Some("enc-v0")
}

/// Seal `body` to each (addr, ed25519 root key). The sender includes itself
/// so it can re-read its own messages.
pub fn seal_body(body: &Value, recipients: &[(String, VerifyingKey)]) -> Result<Value, String> {
    let plaintext = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let mut sealed = serde_json::Map::new();
    for (addr, ed_pk) in recipients {
        let x_pk = crypto_box::PublicKey::from(ed_pk.to_montgomery().to_bytes());
        let ct = x_pk
            .seal(&mut rand::rngs::OsRng, &plaintext)
            .map_err(|_| "sealing failed".to_string())?;
        sealed.insert(
            addr.clone(),
            Value::String(format!("x25519-sealed:{}", hex::encode(ct))),
        );
    }
    Ok(serde_json::json!({ "enc": "enc-v0", "sealed": sealed }))
}

/// Open an enc-v0 body with our Ed25519 root key. None if it isn't sealed to
/// `self_addr` or the ciphertext doesn't open with this key.
pub fn open_body(body: &Value, self_addr: &str, ed_sk: &SigningKey) -> Option<Value> {
    let ct_str = body.get("sealed")?.get(self_addr)?.as_str()?;
    let ct = decode_prefixed(ct_str, "x25519-sealed:").ok()?;
    let x_sk = crypto_box::SecretKey::from(ed_sk.to_scalar_bytes());
    let pt = x_sk.unseal(&ct).ok()?;
    serde_json::from_slice(&pt).ok()
}
