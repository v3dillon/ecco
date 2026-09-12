//! Conformance against the JSON vectors shared with ecco-ops (`test-vectors/`).
use ecco::{
    checkpoint,
    economic_history::{self, Pin},
    envelope::Envelope,
    evidence::Bundle,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

fn vector<T: DeserializeOwned>(name: &str) -> T {
    let path = format!("{}/test-vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn cases(name: &str) -> Vec<Value> {
    let corpus: Value = vector(name);
    corpus["cases"].as_array().unwrap().clone()
}

#[test]
fn evidence_bundle() {
    let bundle: Bundle = vector("evidence-v1.json");
    bundle
        .verify_trusted(&bundle.profile.root, &bundle.receipt.relay)
        .unwrap();
    bundle.env.validate().unwrap();
    let mut bad = bundle.env.clone();
    bad.v = 1;
    assert!(bad.validate().is_err());
    bad = bundle.env.clone();
    bad.body = json!({"nested":[1.5]});
    assert!(bad.validate().is_err());
    // Verification keeps the historical byte rules; admission is stricter.
    let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
    let legacy = Envelope::seal(
        "legacy".into(),
        json!({"number":1.5}),
        "alice@relay.example".into(),
        "note".into(),
        vec![],
        vec![],
        1,
        &key,
    );
    legacy.verify().unwrap();
    assert!(legacy.validate().is_err());
}

#[test]
fn economic_semantics() {
    for case in cases("economic-semantics-v1.json") {
        let bundles: Vec<Bundle> = serde_json::from_value(case["bundles"].clone()).unwrap();
        let pins: Vec<Pin> = serde_json::from_value(case["pins"].clone()).unwrap();
        assert_eq!(
            economic_history::project(&bundles, &pins).unwrap(),
            case["expected"],
            "{}",
            case["name"]
        );
        assert!(economic_history::project(&bundles, &[]).is_err());
        let mut changed = bundles;
        changed[0].env.body = json!({"economic":{"tampered":true}});
        assert!(economic_history::project(&changed, &pins).is_err());
    }
}

#[test]
fn checkpoints() {
    for case in cases("checkpoints-v1.json") {
        let key = case["key"].as_str().unwrap();
        let previous = case.get("previous").filter(|v| !v.is_null());
        assert_eq!(
            checkpoint::verify(&case["checkpoint"], key, previous).is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(
            checkpoint::verify_statement(&case["checkpoint"], key).is_ok(),
            case["statementValid"].as_bool().unwrap(),
            "{} statement",
            case["name"]
        );
    }
}

#[test]
fn witnesses() {
    for case in cases("witnesses-v1.json") {
        assert_eq!(
            checkpoint::verify_witness(
                &case["checkpoint"],
                &case["receipt"],
                &case["policy"],
                case["now"].as_u64().unwrap()
            )
            .is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}
