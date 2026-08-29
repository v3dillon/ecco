//! Durable idempotency reservations for correlated sends.
//!
//! Entries are retained for seven days. This is bounded, but it is longer than
//! the 24-hour maximum lifetime of a dispatcher thread.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::envelope::Envelope;

const RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_KEY_BYTES: usize = 128;
const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);

pub(crate) fn validate_key(key: &str) -> Result<(), String> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(format!(
            "idempotency key must contain 1 to {MAX_KEY_BYTES} bytes"
        ));
    }
    if !key
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b':'))
    {
        return Err(
            "idempotency key can contain only ASCII letters, digits, '-', '_', '.', and ':'".into(),
        );
    }
    Ok(())
}

pub(crate) fn parse_key(key: &str) -> Result<String, String> {
    validate_key(key)?;
    Ok(key.to_owned())
}

pub(crate) fn reserve<F>(
    home: &Path,
    key: &str,
    input_hash: &str,
    build: F,
) -> Result<Envelope, String>
where
    F: FnOnce() -> Result<Envelope, String>,
{
    validate_key(key)?;
    std::fs::create_dir_all(home).map_err(|e| e.to_string())?;
    let path = home.join("outbox.sqlite3");
    let deadline = Instant::now() + LOCK_TIMEOUT;
    let mut db = loop {
        let result = (|| {
            let db = Connection::open(&path).map_err(|e| e.to_string())?;
            db.busy_timeout(LOCK_TIMEOUT).map_err(|e| e.to_string())?;
            db.pragma_update(None, "journal_mode", "WAL")
                .map_err(|e| e.to_string())?;
            db.execute_batch(
                "CREATE TABLE IF NOT EXISTS sends (
           key TEXT PRIMARY KEY,
           input_hash TEXT NOT NULL,
           envelope TEXT NOT NULL,
           created_at INTEGER NOT NULL
         );",
            )
            .map_err(|e| e.to_string())?;
            Ok::<_, String>(db)
        })();
        match result {
            Ok(db) => break db,
            Err(error) if error.contains("database is locked") && Instant::now() < deadline => {
                std::thread::sleep(LOCK_RETRY_DELAY);
            }
            Err(error) => return Err(error),
        }
    };

    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let now = crate::envelope::now();
    tx.execute(
        "DELETE FROM sends WHERE created_at < ?1",
        params![now.saturating_sub(RETENTION_SECONDS) as i64],
    )
    .map_err(|e| e.to_string())?;
    let found: Option<(String, String)> = tx
        .query_row(
            "SELECT input_hash, envelope FROM sends WHERE key = ?1",
            params![key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let envelope = if let Some((saved_hash, raw)) = found {
        if saved_hash != input_hash {
            return Err("idempotency key was already used with different send input".into());
        }
        serde_json::from_str(&raw).map_err(|e| format!("invalid saved outbox envelope: {e}"))?
    } else {
        let envelope = build()?;
        let raw = serde_json::to_string(&envelope).map_err(|e| e.to_string())?;
        tx.execute(
            "INSERT INTO sends(key,input_hash,envelope,created_at) VALUES(?1,?2,?3,?4)",
            params![key, input_hash, raw, now as i64],
        )
        .map_err(|e| e.to_string())?;
        envelope
    };
    tx.commit().map_err(|e| e.to_string())?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use std::sync::{Arc, Barrier};

    fn temp_home() -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("ecco-outbox-test-{}-{}", std::process::id(), nonce))
    }

    fn envelope() -> Envelope {
        let id = Identity::generate("alice", "http://localhost:4200", None);
        Envelope::seal(
            "dm:test".into(),
            serde_json::json!({"text":"hello"}),
            id.addr(),
            "note".into(),
            vec![],
            vec![],
            crate::envelope::now(),
            &id.agent_key(),
        )
    }

    #[test]
    fn rejects_invalid_keys_and_mismatched_reuse() {
        assert!(validate_key("").is_err());
        assert!(validate_key("has space").is_err());
        assert!(validate_key(&"x".repeat(129)).is_err());
        let home = temp_home();
        let first = reserve(&home, "dispatch:1", "one", || Ok(envelope())).unwrap();
        let retry = reserve(&home, "dispatch:1", "one", || {
            Err("retry must not rebuild the envelope".into())
        })
        .unwrap();
        assert_eq!(first.id, retry.id);
        assert!(reserve(&home, "dispatch:1", "two", || Ok(envelope()))
            .unwrap_err()
            .contains("different send input"));
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn concurrent_reservation_builds_one_envelope() {
        let home = Arc::new(temp_home());
        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let home = Arc::clone(&home);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                reserve(&home, "dispatch:2", "same", || Ok(envelope())).unwrap()
            }));
        }
        let first = threads.remove(0).join().unwrap();
        let second = threads.remove(0).join().unwrap();
        assert_eq!(first.id, second.id);
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            serde_json::to_string(&second).unwrap()
        );
        let _ = std::fs::remove_dir_all(&*home);
    }
}
