//! Explicit, audience-bound exchange of economic evidence. No foreign work enters an inbox.
use crate::{
    economic, envelope,
    evidence::{Bundle, Origin},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const DELIVERY_SCHEMA: &str = "ecco.evidence-delivery/v1";
pub const RECEIPT_SCHEMA: &str = "ecco.delivery-receipt/v1";

/// Canonical bytes: the `Value` round trip sorts object keys.
fn bytes<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(&serde_json::to_value(value).expect("serializable evidence")).unwrap()
}

pub fn digest<T: Serialize>(value: &T) -> String {
    format!("b3:{}", blake3::hash(&bytes(value)).to_hex())
}

pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `b3:` or `sha256:` followed by 64 lowercase hex digits.
pub fn is_digest(s: &str) -> bool {
    ["b3:", "sha256:"]
        .iter()
        .any(|p| s.strip_prefix(p).is_some_and(is_hex64))
}

fn sign(value: &Value, key: &SigningKey) -> String {
    format!(
        "ed25519:{}",
        hex::encode(key.sign(&bytes(value)).to_bytes())
    )
}

pub fn verify(value: &Value, key: &str, sig: &str) -> Result<(), String> {
    let raw: [u8; 64] = envelope::decode_prefixed(sig, "ed25519:")?
        .try_into()
        .map_err(|_| "bad signature length")?;
    envelope::decode_key(key)?
        .verify(&bytes(value), &Signature::from_bytes(&raw))
        .map_err(|_| "bad document signature".into())
}

/// Verify a document whose `sig` field signs the rest of the object.
pub fn verify_signed(document: &Value, key: &str) -> Result<(), String> {
    let mut statement = document.clone();
    let sig = statement
        .as_object_mut()
        .ok_or("signed document must be an object")?
        .remove("sig")
        .ok_or("document signature required")?;
    verify(
        &statement,
        key,
        sig.as_str().ok_or("invalid document signature")?,
    )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Audience {
    pub addr: String,
    pub root: String,
    pub relay: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Delivery {
    pub schema: String,
    pub bundle: Bundle,
    pub audience: Audience,
    pub expires_at: u64,
    pub purpose: String,
    pub sig: String,
}
impl Delivery {
    fn statement(&self) -> Value {
        json!({
            "schema": self.schema,
            "bundle": digest(&self.bundle),
            "audience": self.audience,
            "expires_at": self.expires_at,
            "purpose": self.purpose,
        })
    }
    pub fn new(
        bundle: Bundle,
        audience: Audience,
        expires_at: u64,
        purpose: String,
        key: &SigningKey,
    ) -> Result<Self, String> {
        let mut value = Self {
            schema: DELIVERY_SCHEMA.into(),
            bundle,
            audience,
            expires_at,
            purpose,
            sig: String::new(),
        };
        value.sig = sign(&value.statement(), key);
        value.verify()?;
        Ok(value)
    }
    pub fn verify(&self) -> Result<(), String> {
        self.bundle.verify()?;
        if self.schema != DELIVERY_SCHEMA || self.purpose.is_empty() || self.purpose.len() > 256 {
            return Err("invalid evidence disclosure".into());
        }
        if economic::event(&self.bundle.env).is_none() {
            return Err("only explicit economic evidence may be federated".into());
        }
        if !self.bundle.env.to.contains(&self.audience.addr) {
            return Err("disclosure audience must be an original addressed recipient".into());
        }
        envelope::decode_key(&self.audience.root)?;
        envelope::decode_key(&self.audience.relay)?;
        verify(&self.statement(), &self.bundle.profile.root, &self.sig)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    pub schema: String,
    pub delivery: String,
    pub relay: String,
    pub received_at: u64,
    pub retain_until: u64,
    pub sig: String,
}
impl DeliveryReceipt {
    fn statement(&self) -> Value {
        json!({
            "schema": self.schema,
            "delivery": self.delivery,
            "relay": self.relay,
            "received_at": self.received_at,
            "retain_until": self.retain_until,
        })
    }
    pub fn new(delivery: &Delivery, received_at: u64, retain_until: u64, key: &SigningKey) -> Self {
        let mut r = Self {
            schema: RECEIPT_SCHEMA.into(),
            delivery: digest(delivery),
            relay: envelope::encode_key(&key.verifying_key()),
            received_at,
            retain_until,
            sig: String::new(),
        };
        r.sig = sign(&r.statement(), key);
        r
    }
    pub fn verify(&self, delivery: &Delivery) -> Result<(), String> {
        if self.schema != RECEIPT_SCHEMA
            || self.delivery != digest(delivery)
            || self.relay != delivery.audience.relay
            || self.retain_until <= self.received_at
        {
            return Err("wrong delivery receipt scope".into());
        }
        verify(&self.statement(), &self.relay, &self.sig)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceivedEvidence {
    pub delivery: Delivery,
    pub receipt: DeliveryReceipt,
}

/// An origin the receiving operator admits, pinned independently of any uploaded proof.
#[derive(Clone, Deserialize)]
pub struct Peer {
    #[serde(flatten)]
    pub origin: Origin,
    pub retain_days: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{client::Receipt, envelope::Envelope, identity::Identity};
    #[test]
    fn disclosure_and_destination_receipt_are_bound_to_original_evidence() {
        let source = Identity::generate("alice", "https://source.test", None);
        let destination = Identity::generate("bob", "https://destination.test", None);
        let relay = SigningKey::generate(&mut rand::rngs::OsRng);
        let env = Envelope::seal(
            "contract".into(),
            json!({"economic":{"schema":"ecco.economic-event/v1"}}),
            source.addr(),
            "finding".into(),
            vec![],
            vec![destination.addr()],
            100,
            &source.root_key(),
        );
        let bundle = Bundle::sign(
            env.clone(),
            source.profile(),
            Receipt::sign(&env, 1, 1, 100, &relay),
            &relay,
        );
        let audience = Audience {
            addr: destination.addr(),
            root: envelope::encode_key(&destination.root_key().verifying_key()),
            relay: envelope::encode_key(&relay.verifying_key()),
        };
        let mut delivery = Delivery::new(
            bundle,
            audience,
            200,
            "counterparty evidence".into(),
            &source.root_key(),
        )
        .unwrap();
        let receipt = DeliveryReceipt::new(&delivery, 110, 1000, &relay);
        receipt.verify(&delivery).unwrap();
        delivery.audience.addr = "stranger@destination.test".into();
        assert!(delivery.verify().is_err());
        assert!(receipt.verify(&delivery).is_err());
    }
}
