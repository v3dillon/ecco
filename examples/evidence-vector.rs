use ecco::{client::Receipt, envelope::Envelope, evidence::Bundle, identity::Identity};
use ed25519_dalek::SigningKey;
fn main() {
    // Public test seeds, never production credentials.
    let id = Identity {
        name: "alice".into(),
        relay: "https://relay.example".into(),
        root_secret: hex::encode([1; 32]),
        agent_secret: hex::encode([2; 32]),
        token: None,
    };
    let relay = SigningKey::from_bytes(&[3; 32]);
    let env = Envelope::seal(
        "vectors".into(),
        serde_json::json!({"text":"portable","nested":{"2":2,"10":10,"\u{10000}":1,"\u{e000}":2},"safe":9007199254740991u64}),
        id.addr(),
        "note".into(),
        vec![],
        vec!["bob@relay.example".into()],
        1700000000,
        &id.root_key(),
    );
    let receipt = Receipt::sign(&env, 1, 1, 1700000001, &relay);
    println!(
        "{}",
        serde_json::to_string_pretty(&Bundle::sign(env, id.profile_revoked(), receipt, &relay))
            .unwrap()
    );
}
