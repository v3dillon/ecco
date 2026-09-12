//! A relay's attributable acceptance of an envelope under a particular profile.
//! Callers must supply trusted root/relay bindings; embedded keys are not trust anchors.
use crate::{
    client::Receipt,
    envelope::{self, Envelope},
    identity::Profile,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};

pub const SCHEMA: &str = "ecco.evidence/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub schema: String,
    pub env: Envelope,
    pub profile: Profile,
    pub receipt: Receipt,
    pub acceptance_sig: String,
}

impl Bundle {
    fn signing_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "envelope": self.env.id,
            "profile": format!("b3:{}", blake3::hash(&serde_json::to_vec(&self.profile).unwrap()).to_hex()),
            "receipt": self.receipt,
            "schema": SCHEMA,
        })).unwrap()
    }

    pub fn sign(env: Envelope, profile: Profile, receipt: Receipt, relay_key: &SigningKey) -> Self {
        let mut bundle = Self {
            schema: SCHEMA.into(),
            env,
            profile,
            receipt,
            acceptance_sig: String::new(),
        };
        bundle.acceptance_sig = format!(
            "ed25519:{}",
            hex::encode(relay_key.sign(&bundle.signing_bytes()).to_bytes())
        );
        bundle
    }

    /// Verify intrinsic integrity and the relay's historical authorization assertion.
    /// This does not verify domain ownership, current revocation, or statement truth.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != SCHEMA || self.env.v != 0 || self.profile.v != 0 {
            return Err("unsupported evidence schema".into());
        }
        self.env.verify()?;
        self.profile.verify()?;
        sender_bound(&self.env, &self.profile, self.receipt.received_at)?;
        self.receipt.verify(&self.env)?;
        let sig: [u8; 64] = envelope::decode_prefixed(&self.acceptance_sig, "ed25519:")?
            .try_into()
            .map_err(|_| "bad acceptance signature length")?;
        envelope::decode_key(&self.receipt.relay)?
            .verify(&self.signing_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| "invalid acceptance signature".to_string())
    }

    pub fn verify_trusted(&self, root: &str, relay: &str) -> Result<(), String> {
        self.verify()?;
        if self.profile.root != root || self.receipt.relay != relay {
            return Err("evidence does not match trusted root and relay".into());
        }
        Ok(())
    }
}

/// `profile` names the sender and authorizes `env.key` for this kind at `at`.
pub fn sender_bound(env: &Envelope, profile: &Profile, at: u64) -> Result<(), String> {
    let (name, _) = env.from.split_once('@').ok_or("invalid sender address")?;
    if profile.name != name {
        return Err("profile does not bind sender name".into());
    }
    if env.key != profile.root
        && !profile
            .delegations
            .iter()
            .any(|d| d.key == env.key && d.addr == env.from)
    {
        return Err("delegation does not bind sender address".into());
    }
    profile.authorizes(&env.key, &env.kind, at)
}

/// An independently pinned sender: address, root key and accepting relay key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Origin {
    pub address: String,
    pub root: String,
    pub relay: String,
}

impl Origin {
    pub fn matches(&self, bundle: &Bundle) -> bool {
        self.address == bundle.env.from
            && self.root == bundle.profile.root
            && self.relay == bundle.receipt.relay
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    #[test]
    fn acceptance_binds_original_profile_and_requires_external_trust() {
        let id = Identity::generate("alice", "https://relay.example", None);
        let relay = SigningKey::from_bytes(&[3; 32]);
        let env = Envelope::seal(
            "work".into(),
            serde_json::json!({"text":"delivered"}),
            id.addr(),
            "finding".into(),
            vec![],
            vec![],
            envelope::now(),
            &id.agent_key(),
        );
        let receipt = Receipt::sign(&env, 1, 1, envelope::now(), &relay);
        let bundle = Bundle::sign(env, id.profile(), receipt, &relay);
        bundle
            .verify_trusted(&bundle.profile.root, &bundle.receipt.relay)
            .unwrap();
        assert!(bundle
            .verify_trusted("other", &bundle.receipt.relay)
            .is_err());
        let mut changed = bundle.clone();
        changed.profile = id.profile_revoked();
        assert!(changed.verify().is_err());
        changed = bundle;
        changed.env.body = serde_json::json!({"text":"accepted"});
        assert!(changed.verify().is_err());
    }
}
