//! Relay storage: one SQLite file in WAL mode, zero config. Storage is
//! relay-internal — the protocol only ever sees envelopes, seqs, and receipts.

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use crate::envelope::Envelope;
use crate::identity::Profile;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stored {
    pub gseq: u64,
    pub tseq: u64,
    pub received_at: u64,
    pub env: Envelope,
}

pub enum ThreadAccess {
    Empty,
    Participant,
    NotParticipant,
}

type Res<T> = Result<T, (u16, String)>;

/// Rows per sweep transaction. Each batch takes the store lock once and
/// briefly, so requests interleave with a long sweep.
pub const SWEEP_BATCH: usize = 1000;

/// One batch of expired gseqs. Parameter 1 is `now`, 2 the default window in
/// days, 3 the bound `now - min_window`: nothing newer can be expired, and
/// `msgs_received` turns the scan into a range read of the old tail. The
/// per-sender test after it is exact. ORDER BY makes the batch deterministic
/// across the two DELETEs in one transaction.
const SQLITE_BATCH: &str = "SELECT gseq FROM msgs WHERE msgs.received_at < ?3
     AND COALESCE((SELECT days FROM retention r WHERE r.sender = msgs.sender), ?2) > 0
     AND msgs.received_at < ?1 - COALESCE((SELECT days FROM retention r WHERE r.sender = msgs.sender), ?2) * 86400
     ORDER BY gseq LIMIT 1000";

/// The smallest positive window in play, or None when nothing can expire.
fn min_window(default_days: u32, min_entry_days: Option<i64>) -> Option<u64> {
    [Some(default_days as i64), min_entry_days]
        .into_iter()
        .flatten()
        .filter(|d| *d > 0)
        .map(|d| d as u64)
        .min()
}

const SQLITE_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS profiles (name TEXT PRIMARY KEY, root TEXT NOT NULL, doc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS threads (about TEXT PRIMARY KEY, last_tseq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS msgs (
  gseq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT UNIQUE NOT NULL,
  about TEXT NOT NULL,
  sender TEXT NOT NULL,
  tseq INTEGER NOT NULL,
  received_at INTEGER NOT NULL,
  env TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS msgs_about ON msgs(about, tseq);
CREATE INDEX IF NOT EXISTS msgs_received ON msgs(received_at);
CREATE TABLE IF NOT EXISTS msg_to (gseq INTEGER NOT NULL, addr TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS msg_to_addr ON msg_to(addr, gseq);
CREATE TABLE IF NOT EXISTS retention (sender TEXT PRIMARY KEY, days INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS participants (
  about TEXT NOT NULL,
  addr TEXT NOT NULL,
  PRIMARY KEY (about, addr)
);
";

/// Upgrade path for stores that existed before `participants`.
const SQLITE_BACKFILL_PARTICIPANTS: &str = "
INSERT OR IGNORE INTO participants(about, addr) SELECT DISTINCT about, sender FROM msgs;
INSERT OR IGNORE INTO participants(about, addr)
  SELECT DISTINCT m.about, t.addr FROM msgs m JOIN msg_to t ON t.gseq=m.gseq;
";

pub struct Store {
    conn: Mutex<rusqlite::Connection>,
}

impl Store {
    /// Opens (or creates) `relay.db` in `data`. The busy timeout lets
    /// `ecco admin` share the file with a running relay.
    pub fn open(data: &Path) -> Result<Store, String> {
        fs::create_dir_all(data).map_err(|e| e.to_string())?;
        let conn = rusqlite::Connection::open(data.join("relay.db")).map_err(|e| e.to_string())?;
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        let _ = conn.busy_timeout(Duration::from_secs(5));
        conn.execute_batch(SQLITE_SCHEMA)
            .map_err(|e| e.to_string())?;
        conn.execute_batch(SQLITE_BACKFILL_PARTICIPANTS)
            .map_err(|e| e.to_string())?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }
}

fn sq<T>(r: Result<T, rusqlite::Error>) -> Res<T> {
    r.map_err(|e| (500, format!("storage error: {e}")))
}

fn sqlite_row_to_stored(row: &rusqlite::Row) -> rusqlite::Result<(i64, i64, i64, String)> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn build_stored((gseq, tseq, received_at, env_json): (i64, i64, i64, String)) -> Res<Stored> {
    let env: Envelope = serde_json::from_str(&env_json)
        .map_err(|e| (500, format!("corrupt stored envelope: {e}")))?;
    Ok(Stored {
        gseq: gseq as u64,
        tseq: tseq as u64,
        received_at: received_at as u64,
        env,
    })
}

impl Store {
    /// First-write-wins per name; the same root key may update its document.
    pub fn register(&self, profile: Profile) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        let existing: Option<String> = sq(conn
            .query_row(
                "SELECT root FROM profiles WHERE name=?1",
                [&profile.name],
                |r| r.get(0),
            )
            .optional())?;
        if let Some(root) = existing {
            if root != profile.root {
                return Err((409, format!("name '{}' is taken", profile.name)));
            }
        }
        let doc = serde_json::to_string(&profile).unwrap();
        sq(conn.execute(
            "INSERT INTO profiles(name,root,doc) VALUES(?1,?2,?3)
             ON CONFLICT(name) DO UPDATE SET root=excluded.root, doc=excluded.doc",
            rusqlite::params![profile.name, profile.root, doc],
        ))?;
        Ok(())
    }

    pub fn profile(&self, name: &str) -> Res<Option<Profile>> {
        let conn = self.conn.lock().unwrap();
        let doc: Option<String> = sq(conn
            .query_row("SELECT doc FROM profiles WHERE name=?1", [name], |r| {
                r.get(0)
            })
            .optional())?;
        match doc {
            Some(d) => serde_json::from_str(&d)
                .map(Some)
                .map_err(|e| (500, format!("corrupt profile: {e}"))),
            None => Ok(None),
        }
    }

    /// Idempotent by envelope id: resubmission returns the stored copy.
    pub fn append(&self, env: Envelope, received_at: u64) -> Res<Stored> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sq(conn.transaction())?;
        if let Some(row) = sq(tx
            .query_row(
                "SELECT gseq,tseq,received_at,env FROM msgs WHERE id=?1",
                [&env.id],
                sqlite_row_to_stored,
            )
            .optional())?
        {
            return build_stored(row);
        }
        let tseq: i64 = sq(tx.query_row(
            "INSERT INTO threads(about,last_tseq) VALUES(?1,1)
             ON CONFLICT(about) DO UPDATE SET last_tseq=threads.last_tseq+1
             RETURNING last_tseq",
            [&env.about],
            |r| r.get(0),
        ))?;
        let env_json = serde_json::to_string(&env).unwrap();
        sq(tx.execute(
            "INSERT INTO msgs(id,about,sender,tseq,received_at,env) VALUES(?1,?2,?3,?4,?5,?6)",
            rusqlite::params![
                env.id,
                env.about,
                env.from,
                tseq,
                received_at as i64,
                env_json
            ],
        ))?;
        let gseq = tx.last_insert_rowid();
        for addr in &env.to {
            sq(tx.execute(
                "INSERT INTO msg_to(gseq,addr) VALUES(?1,?2)",
                rusqlite::params![gseq, addr],
            ))?;
        }
        sq(tx.execute(
            "INSERT OR IGNORE INTO participants(about,addr) VALUES(?1,?2)",
            rusqlite::params![env.about, env.from],
        ))?;
        for addr in &env.to {
            sq(tx.execute(
                "INSERT OR IGNORE INTO participants(about,addr) VALUES(?1,?2)",
                rusqlite::params![env.about, addr],
            ))?;
        }
        sq(tx.commit())?;
        Ok(Stored {
            gseq: gseq as u64,
            tseq: tseq as u64,
            received_at,
            env,
        })
    }

    pub fn thread(&self, about: &str, since: u64) -> Res<Vec<Stored>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sq(conn.prepare(
            "SELECT gseq,tseq,received_at,env FROM msgs WHERE about=?1 AND tseq>?2 ORDER BY tseq",
        ))?;
        let rows = sq(stmt
            .query_map(rusqlite::params![about, since as i64], sqlite_row_to_stored)
            .and_then(|r| r.collect::<Result<Vec<_>, _>>()))?;
        rows.into_iter().map(build_stored).collect()
    }

    pub fn inbox(&self, addr: &str, since: u64) -> Res<Vec<Stored>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sq(conn.prepare(
            "SELECT DISTINCT m.gseq,m.tseq,m.received_at,m.env
             FROM msgs m JOIN msg_to t ON t.gseq=m.gseq
             WHERE t.addr=?1 AND m.gseq>?2 ORDER BY m.gseq",
        ))?;
        let rows = sq(stmt
            .query_map(rusqlite::params![addr, since as i64], sqlite_row_to_stored)
            .and_then(|r| r.collect::<Result<Vec<_>, _>>()))?;
        rows.into_iter().map(build_stored).collect()
    }

    pub fn access(&self, about: &str, addr: &str) -> Res<ThreadAccess> {
        let conn = self.conn.lock().unwrap();
        let (any, participant): (bool, bool) = sq(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM threads WHERE about=?1),
                    EXISTS(SELECT 1 FROM participants WHERE about=?1 AND addr=?2)",
            rusqlite::params![about, addr],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        Ok(match (any, participant) {
            (false, _) => ThreadAccess::Empty,
            (true, true) => ThreadAccess::Participant,
            (true, false) => ThreadAccess::NotParticipant,
        })
    }

    /// Replaces the per-sender retention table. Days; 0 keeps forever.
    pub fn set_retention(&self, entries: &[(String, u32)]) -> Res<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sq(conn.transaction())?;
        sq(tx.execute("DELETE FROM retention", []))?;
        for (sender, days) in entries {
            sq(tx.execute(
                "INSERT INTO retention(sender,days) VALUES(?1,?2)",
                rusqlite::params![sender, *days as i64],
            ))?;
        }
        sq(tx.commit())
    }

    /// Deletes envelopes older than their sender's retention window, in
    /// batches. Senders without an entry use `default_days`; 0 keeps forever.
    /// Returns the count.
    pub fn sweep(&self, now: u64, default_days: u32) -> Res<u64> {
        let min_entry: Option<i64> = {
            let conn = self.conn.lock().unwrap();
            sq(
                conn.query_row("SELECT MIN(days) FROM retention WHERE days > 0", [], |r| {
                    r.get(0)
                }),
            )?
        };
        let Some(window) = min_window(default_days, min_entry) else {
            return Ok(0);
        };
        let bound = now.saturating_sub(window * 86_400) as i64;
        let mut total = 0u64;
        loop {
            let n = {
                let mut conn = self.conn.lock().unwrap();
                let tx = sq(conn.transaction())?;
                let params = rusqlite::params![now as i64, default_days as i64, bound];
                sq(tx.execute(
                    &format!("DELETE FROM msg_to WHERE gseq IN ({SQLITE_BATCH})"),
                    params,
                ))?;
                let n = sq(tx.execute(
                    &format!("DELETE FROM msgs WHERE gseq IN ({SQLITE_BATCH})"),
                    params,
                ))?;
                sq(tx.commit())?;
                n
            };
            total += n as u64;
            if n < SWEEP_BATCH {
                return Ok(total);
            }
        }
    }

    /// Operator takedown of one envelope by id. Not protocol: peers keep
    /// their signed copies. Returns whether a row existed.
    pub fn remove(&self, id: &str) -> Res<bool> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sq(conn.transaction())?;
        sq(tx.execute(
            "DELETE FROM msg_to WHERE gseq IN (SELECT gseq FROM msgs WHERE id=?1)",
            [id],
        ))?;
        let n = sq(tx.execute("DELETE FROM msgs WHERE id=?1", [id]))?;
        sq(tx.commit())?;
        Ok(n > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    fn fresh_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "ecco-store-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ))
    }

    fn fresh() -> Store {
        Store::open(&fresh_dir()).unwrap()
    }

    fn note(from: &Identity, to: &Identity, text: &str, ts: u64) -> Envelope {
        Envelope::seal(
            "gh:acme/app/pull/1".into(),
            json!({ "text": text }),
            from.addr(),
            "note".into(),
            vec![],
            vec![to.addr()],
            ts,
            &from.agent_key(),
        )
    }

    const DAY: u64 = 86_400;

    #[test]
    fn sweep_uses_per_sender_windows_then_the_default() {
        let store = fresh();
        let alice = Identity::generate("alice", "http://localhost:4200", None);
        let bob = Identity::generate("bob", "http://localhost:4200", None);
        store.register(alice.profile()).unwrap();
        store.register(bob.profile()).unwrap();
        let now = 100 * DAY;
        store
            .append(note(&alice, &bob, "a-old", 1), now - 20 * DAY)
            .unwrap();
        store
            .append(note(&alice, &bob, "a-new", 2), now - DAY)
            .unwrap();
        store
            .append(note(&bob, &alice, "b-old", 3), now - 20 * DAY)
            .unwrap();

        // Nothing configured for alice; default 0 keeps everything.
        assert_eq!(store.sweep(now, 0).unwrap(), 0);

        // Alice gets a 30-day window; the 7-day default only hits bob.
        store.set_retention(&[(alice.addr(), 30)]).unwrap();
        assert_eq!(store.sweep(now, 7).unwrap(), 1);
        assert_eq!(store.thread("gh:acme/app/pull/1", 0).unwrap().len(), 2);
        assert!(store.inbox(&alice.addr(), 0).unwrap().is_empty());

        // Alice tightened to 10 days: her 20-day-old note expires too.
        store.set_retention(&[(alice.addr(), 10)]).unwrap();
        assert_eq!(store.sweep(now, 7).unwrap(), 1);
        let left = store.thread("gh:acme/app/pull/1", 0).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].env.body["text"], "a-new");
        assert_eq!(store.inbox(&bob.addr(), 0).unwrap().len(), 1);

        // Thread seq keeps counting; nothing is reused after a sweep.
        let s = store.append(note(&alice, &bob, "a-next", 4), now).unwrap();
        assert_eq!(s.tseq, 4);
    }

    #[test]
    fn min_window_picks_the_smallest_positive_days() {
        assert_eq!(min_window(0, None), None);
        assert_eq!(min_window(0, Some(0)), None);
        assert_eq!(min_window(7, None), Some(7));
        assert_eq!(min_window(0, Some(14)), Some(14));
        assert_eq!(min_window(30, Some(14)), Some(14));
        assert_eq!(min_window(7, Some(14)), Some(7));
    }

    #[test]
    fn sweep_works_in_batches_and_leaves_fresh_rows() {
        let store = fresh();
        let alice = Identity::generate("alice", "http://localhost:4200", None);
        let bob = Identity::generate("bob", "http://localhost:4200", None);
        let now = 100 * DAY;
        let old = 2 * SWEEP_BATCH + 5;
        for i in 0..old {
            store
                .append(
                    note(&alice, &bob, &format!("old-{i}"), i as u64),
                    now - 10 * DAY,
                )
                .unwrap();
        }
        store
            .append(note(&alice, &bob, "fresh", 9_999), now - DAY)
            .unwrap();
        assert_eq!(store.sweep(now, 7).unwrap(), old as u64);
        assert_eq!(store.sweep(now, 7).unwrap(), 0);
        let left = store.inbox(&bob.addr(), 0).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].env.body["text"], "fresh");
    }

    #[test]
    fn participants_survive_sweep_and_remove() {
        let store = fresh();
        let alice = Identity::generate("alice", "http://localhost:4200", None);
        let bob = Identity::generate("bob", "http://localhost:4200", None);
        let mallory = Identity::generate("mallory", "http://localhost:4200", None);
        let now = 100 * DAY;
        let about = "gh:acme/app/pull/1";
        store
            .append(note(&alice, &bob, "old", 1), now - 20 * DAY)
            .unwrap();
        assert!(matches!(
            store.access(about, &alice.addr()).unwrap(),
            ThreadAccess::Participant
        ));
        assert!(matches!(
            store.access(about, &bob.addr()).unwrap(),
            ThreadAccess::Participant
        ));
        assert!(matches!(
            store.access(about, &mallory.addr()).unwrap(),
            ThreadAccess::NotParticipant
        ));
        assert!(matches!(
            store.access("gh:never", &alice.addr()).unwrap(),
            ThreadAccess::Empty
        ));

        assert_eq!(store.sweep(now, 7).unwrap(), 1);
        assert!(store.thread(about, 0).unwrap().is_empty());
        assert!(matches!(
            store.access(about, &alice.addr()).unwrap(),
            ThreadAccess::Participant
        ));
        assert!(matches!(
            store.access(about, &bob.addr()).unwrap(),
            ThreadAccess::Participant
        ));
        assert!(matches!(
            store.access(about, &mallory.addr()).unwrap(),
            ThreadAccess::NotParticipant
        ));

        let again = store.append(note(&alice, &bob, "again", 2), now).unwrap();
        assert_eq!(again.tseq, 2);
        assert!(store.remove(&again.env.id).unwrap());
        assert!(matches!(
            store.access(about, &alice.addr()).unwrap(),
            ThreadAccess::Participant
        ));
        assert!(matches!(
            store.access(about, &bob.addr()).unwrap(),
            ThreadAccess::Participant
        ));
    }

    #[test]
    fn open_backfills_participants_from_existing_msgs() {
        let dir = fresh_dir();
        let store = Store::open(&dir).unwrap();
        let alice = Identity::generate("alice", "http://localhost:4200", None);
        let bob = Identity::generate("bob", "http://localhost:4200", None);
        store.append(note(&alice, &bob, "hello", 1), 10).unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute("DELETE FROM participants", []).unwrap();
        }
        assert!(matches!(
            store.access("gh:acme/app/pull/1", &alice.addr()).unwrap(),
            ThreadAccess::NotParticipant
        ));
        drop(store);
        let store = Store::open(&dir).unwrap();
        assert!(matches!(
            store.access("gh:acme/app/pull/1", &alice.addr()).unwrap(),
            ThreadAccess::Participant
        ));
        assert!(matches!(
            store.access("gh:acme/app/pull/1", &bob.addr()).unwrap(),
            ThreadAccess::Participant
        ));
    }

    #[test]
    fn remove_takes_down_one_envelope_and_its_inbox_rows() {
        let store = fresh();
        let alice = Identity::generate("alice", "http://localhost:4200", None);
        let bob = Identity::generate("bob", "http://localhost:4200", None);
        let keep = store.append(note(&alice, &bob, "keep", 1), 10).unwrap();
        let gone = store.append(note(&alice, &bob, "gone", 2), 11).unwrap();
        assert!(store.remove(&gone.env.id).unwrap());
        assert!(!store.remove(&gone.env.id).unwrap());
        let inbox = store.inbox(&bob.addr(), 0).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].env.id, keep.env.id);
    }
}
