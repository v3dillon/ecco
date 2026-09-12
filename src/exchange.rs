//! A small durable outbox for explicitly authorized evidence disclosures.
use crate::client;
use crate::envelope::now;
use crate::federation::{digest, Delivery, DeliveryReceipt};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::time::Duration;

const SCHEMA: &str = "
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS deliveries (
  id TEXT PRIMARY KEY,
  url TEXT NOT NULL,
  doc TEXT NOT NULL,
  receipt TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_at INTEGER NOT NULL DEFAULT 0,
  error TEXT
);
";

fn open(home: &Path) -> Result<Connection, String> {
    std::fs::create_dir_all(home).map_err(|e| e.to_string())?;
    let conn = Connection::open(home.join("evidence-outbox.db")).map_err(|e| e.to_string())?;
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
    Ok(conn)
}

/// `url` must be the origin of the audience's own relay.
fn destination(delivery: &Delivery, url: &str) -> Result<url::Url, String> {
    let parsed = client::origin(url)?;
    let authority = delivery
        .audience
        .addr
        .split_once('@')
        .ok_or("bad audience")?
        .1;
    if parsed[url::Position::BeforeHost..url::Position::AfterPort] != *authority {
        return Err("destination must be the audience relay origin".into());
    }
    Ok(parsed)
}

pub fn queue(home: &Path, delivery: &Delivery, url: &str) -> Result<String, String> {
    delivery.verify()?;
    destination(delivery, url)?;
    let conn = open(home)?;
    let id = digest(delivery);
    conn.execute(
        "INSERT OR IGNORE INTO deliveries(id,url,doc) VALUES(?1,?2,?3)",
        params![id, url, serde_json::to_string(delivery).unwrap()],
    )
    .map_err(|e| e.to_string())?;
    Ok(id)
}

/// Repeated delivery is safe even across overlapping workers: the receiving store deduplicates.
pub fn flush(home: &Path) -> Result<serde_json::Value, String> {
    let conn = open(home)?;
    let mut stmt = conn
        .prepare(
            "SELECT id,url,doc,attempts FROM deliveries
             WHERE receipt IS NULL AND next_at<=?1 ORDER BY id LIMIT 32",
        )
        .map_err(|e| e.to_string())?;
    let pending = stmt
        .query_map([now()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, u32>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let agent = client::http_agent();
    let mut delivered = 0;
    for (id, url, doc, attempts) in pending {
        let result = (|| -> Result<DeliveryReceipt, String> {
            let d: Delivery = serde_json::from_str(&doc).map_err(|e| e.to_string())?;
            d.verify()?;
            let endpoint = destination(&d, &url)?.join("federation/evidence").unwrap();
            if d.expires_at <= now() {
                return Err("disclosure expired; obtain a new signed disclosure".into());
            }
            let response = agent
                .post(endpoint.as_str())
                .timeout(Duration::from_secs(15))
                .set("content-type", "application/json")
                .send_string(&doc)
                .map_err(|e| e.to_string())?;
            let raw = response.into_string().map_err(|e| e.to_string())?;
            let receipt: DeliveryReceipt = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
            receipt.verify(&d)?;
            Ok(receipt)
        })();
        match result {
            Ok(receipt) => {
                conn.execute(
                    "UPDATE deliveries SET receipt=?2,error=NULL WHERE id=?1",
                    params![id, serde_json::to_string(&receipt).unwrap()],
                )
                .map_err(|e| e.to_string())?;
                delivered += 1;
            }
            Err(error) => {
                conn.execute(
                    "UPDATE deliveries SET attempts=attempts+1,next_at=?2,error=?3 WHERE id=?1",
                    params![id, now() + 2u64.pow(attempts.min(10) + 1).min(3600), error],
                )
                .map_err(|e| e.to_string())?;
            }
        }
    }
    let pending: u64 = conn
        .query_row(
            "SELECT COUNT(*) FROM deliveries WHERE receipt IS NULL",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"delivered":delivered,"pending":pending}))
}

pub fn status(home: &Path, id: &str) -> Result<Option<serde_json::Value>, String> {
    open(home)?
        .query_row(
            "SELECT receipt,attempts,error FROM deliveries WHERE id=?1",
            [id],
            |r| {
                Ok(serde_json::json!({
                    "receipt": r.get::<_, Option<String>>(0)?,
                    "attempts": r.get::<_, u32>(1)?,
                    "error": r.get::<_, Option<String>>(2)?,
                }))
            },
        )
        .optional()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        client::Receipt,
        envelope::{self, Envelope},
        evidence::Bundle,
        federation::Audience,
        identity::Identity,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    #[test]
    fn lost_destination_ack_retries_original_disclosure_after_reopening_outbox() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr().to_ip().unwrap());
        let source = Identity::generate("alice", "https://source.test", None);
        let target = Identity::generate("bob", &url, None);
        let origin_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let destination_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let now = envelope::now();
        let env = Envelope::seal(
            "contract".into(),
            json!({"economic":{"schema":"ecco.economic-event/v1","type":"external_attestation","payload":{"claim":"delivery"},"links":[]}}),
            source.addr(),
            "finding".into(),
            vec![],
            vec![target.addr()],
            now,
            &source.root_key(),
        );
        let bundle = Bundle::sign(
            env.clone(),
            source.profile(),
            Receipt::sign(&env, 1, 1, now, &origin_key),
            &origin_key,
        );
        let disclosure = Delivery::new(
            bundle,
            Audience {
                addr: target.addr(),
                root: target.profile().root,
                relay: envelope::encode_key(&destination_key.verifying_key()),
            },
            now + 300,
            "contract review".into(),
            &source.root_key(),
        )
        .unwrap();
        let expected = serde_json::to_string(&disclosure).unwrap();
        let worker = std::thread::spawn(move || {
            let mut first = None;
            for attempt in 0..2 {
                let mut request = server
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap()
                    .expect("retry request");
                assert_eq!(request.url(), "/federation/evidence");
                assert!(!request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("Authorization")));
                let mut raw = String::new();
                request.as_reader().read_to_string(&mut raw).unwrap();
                assert_eq!(raw, expected);
                let d: Delivery = serde_json::from_str(&raw).unwrap();
                d.verify().unwrap();
                let receipt = first.get_or_insert_with(|| {
                    DeliveryReceipt::new(&d, now, now + 86400, &destination_key)
                });
                let response = if attempt == 0 {
                    tiny_http::Response::from_string("ack lost").with_status_code(503)
                } else {
                    tiny_http::Response::from_string(serde_json::to_string(receipt).unwrap())
                };
                request.respond(response).unwrap();
            }
        });
        let home =
            std::env::temp_dir().join(format!("ecco-delivery-test-{}", rand::random::<u64>()));
        let id = queue(&home, &disclosure, &url).unwrap();
        assert_eq!(flush(&home).unwrap()["pending"], 1);
        assert_eq!(status(&home, &id).unwrap().unwrap()["attempts"], 1);
        // Each public operation closes its connection. Advance retry eligibility without sleeping.
        open(&home)
            .unwrap()
            .execute("UPDATE deliveries SET next_at=0", [])
            .unwrap();
        assert_eq!(queue(&home, &disclosure, &url).unwrap(), id);
        assert_eq!(flush(&home).unwrap(), json!({"delivered":1,"pending":0}));
        assert!(!status(&home, &id).unwrap().unwrap()["receipt"].is_null());
        assert_eq!(flush(&home).unwrap()["delivered"], 0);
        worker.join().unwrap();
        std::fs::remove_dir_all(home).unwrap();
    }
}
