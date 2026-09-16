//! Durable idempotency reservations for correlated sends.
//!
//! Entries are retained for seven days. This is bounded, but it is longer than
//! the 24-hour maximum lifetime of a dispatcher thread.

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::envelope::Envelope;

const RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
const LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);
/// Bumped when the table changes. Keys never match across versions, so an
/// older table is dropped rather than migrated.
const SCHEMA_VERSION: i64 = 1;

/// The envelope saved under `key`, or the one `build` makes, saved first.
pub(crate) fn reserve<F>(home: &Path, key: &str, build: F) -> Result<Envelope, String>
where
    F: FnOnce() -> Result<Envelope, String>,
{
    std::fs::create_dir_all(home).map_err(|e| e.to_string())?;
    let path = home.join("outbox.sqlite3");
    let deadline = Instant::now() + LOCK_TIMEOUT;
    let mut db = loop {
        let result = (|| {
            let db = Connection::open(&path).map_err(|e| e.to_string())?;
            db.busy_timeout(LOCK_TIMEOUT).map_err(|e| e.to_string())?;
            db.pragma_update(None, "journal_mode", "WAL")
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
    let version: i64 = tx
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| e.to_string())?;
    if version != SCHEMA_VERSION {
        tx.execute_batch(&format!(
            "DROP TABLE IF EXISTS sends;
             CREATE TABLE sends (
               key TEXT PRIMARY KEY,
               envelope TEXT NOT NULL,
               created_at INTEGER NOT NULL
             );
             PRAGMA user_version = {SCHEMA_VERSION};"
        ))
        .map_err(|e| e.to_string())?;
    }
    let now = crate::envelope::now();
    tx.execute(
        "DELETE FROM sends WHERE created_at < ?1",
        params![now.saturating_sub(RETENTION_SECONDS) as i64],
    )
    .map_err(|e| e.to_string())?;
    let saved: Option<String> = tx
        .query_row(
            "SELECT envelope FROM sends WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let envelope = match saved {
        Some(raw) => {
            serde_json::from_str(&raw).map_err(|e| format!("invalid saved outbox envelope: {e}"))?
        }
        None => {
            let envelope = build()?;
            let raw = serde_json::to_string(&envelope).map_err(|e| e.to_string())?;
            tx.execute(
                "INSERT INTO sends(key,envelope,created_at) VALUES(?1,?2,?3)",
                params![key, raw, now as i64],
            )
            .map_err(|e| e.to_string())?;
            envelope
        }
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
    fn a_retry_reuses_the_saved_envelope() {
        let home = temp_home();
        let first = reserve(&home, "one", || Ok(envelope())).unwrap();
        let retry = reserve(&home, "one", || {
            Err("retry must not rebuild the envelope".into())
        })
        .unwrap();
        assert_eq!(first.id, retry.id);
        let other = reserve(&home, "two", || Ok(envelope())).unwrap();
        assert_ne!(first.id, other.id);
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn an_older_table_is_replaced() {
        let home = temp_home();
        std::fs::create_dir_all(&home).unwrap();
        Connection::open(home.join("outbox.sqlite3"))
            .unwrap()
            .execute_batch(
                "CREATE TABLE sends (
                   key TEXT PRIMARY KEY,
                   input_hash TEXT NOT NULL,
                   envelope TEXT NOT NULL,
                   created_at INTEGER NOT NULL
                 );
                 INSERT INTO sends VALUES ('old', 'hash', 'not an envelope', strftime('%s', 'now'));",
            )
            .unwrap();
        let first = reserve(&home, "old", || Ok(envelope())).unwrap();
        let retry = reserve(&home, "old", || {
            Err("retry must not rebuild the envelope".into())
        })
        .unwrap();
        assert_eq!(first.id, retry.id);
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
                reserve(&home, "same", || Ok(envelope())).unwrap()
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
