//! Relay storage behind one trait. Storage is relay-internal — the protocol
//! only ever sees envelopes, seqs, and receipts — so backends are swappable:
//! `SqliteStore` for self-hosted and dedicated relays (single file, WAL, zero
//! config), `PgStore` (Postgres) for the shared multi-tenant tier.

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

pub trait Store: Send + Sync {
    fn register(&self, profile: Profile) -> Res<()>;
    fn profile(&self, name: &str) -> Res<Option<Profile>>;
    /// Idempotent by envelope id: resubmission returns the stored copy.
    fn append(&self, env: Envelope, received_at: u64) -> Res<Stored>;
    fn thread(&self, about: &str, since: u64) -> Res<Vec<Stored>>;
    fn inbox(&self, addr: &str, since: u64) -> Res<Vec<Stored>>;
    fn access(&self, about: &str, addr: &str) -> Res<ThreadAccess>;
    /// Replaces the per-sender retention table. Days; 0 keeps forever.
    fn set_retention(&self, entries: &[(String, u32)]) -> Res<()>;
    /// Deletes envelopes older than their sender's retention window. Senders
    /// without an entry use `default_days`; 0 keeps forever. Returns the count.
    fn sweep(&self, now: u64, default_days: u32) -> Res<u64>;
    /// Operator takedown of one envelope by id. Not protocol: peers keep
    /// their signed copies. Returns whether a row existed.
    fn remove(&self, id: &str) -> Res<bool>;
}

/// The per-envelope expiry test, shared by the sweep statements. Parameter 1
/// is `now`, parameter 2 the default window in days.
const SQLITE_EXPIRED: &str = "COALESCE((SELECT days FROM retention r WHERE r.sender = msgs.sender), ?2) > 0
     AND msgs.received_at < ?1 - COALESCE((SELECT days FROM retention r WHERE r.sender = msgs.sender), ?2) * 86400";
const PG_EXPIRED: &str = "COALESCE((SELECT days FROM retention r WHERE r.sender = msgs.sender), $2) > 0
     AND msgs.received_at < $1 - COALESCE((SELECT days FROM retention r WHERE r.sender = msgs.sender), $2)::bigint * 86400";

// ---- SqliteStore: single file, WAL mode — self-hosted and dedicated relays ----

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
CREATE TABLE IF NOT EXISTS msg_to (gseq INTEGER NOT NULL, addr TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS msg_to_addr ON msg_to(addr, gseq);
CREATE TABLE IF NOT EXISTS retention (sender TEXT PRIMARY KEY, days INTEGER NOT NULL);
";

pub struct SqliteStore {
    conn: Mutex<rusqlite::Connection>,
}

impl SqliteStore {
    pub fn open(data: &Path) -> Result<SqliteStore, String> {
        fs::create_dir_all(data).map_err(|e| e.to_string())?;
        let conn = rusqlite::Connection::open(data.join("relay.db")).map_err(|e| e.to_string())?;
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        let _ = conn.busy_timeout(Duration::from_secs(5));
        conn.execute_batch(SQLITE_SCHEMA)
            .map_err(|e| e.to_string())?;
        Ok(SqliteStore {
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

impl Store for SqliteStore {
    fn register(&self, profile: Profile) -> Res<()> {
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

    fn profile(&self, name: &str) -> Res<Option<Profile>> {
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

    fn append(&self, env: Envelope, received_at: u64) -> Res<Stored> {
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
        sq(tx.commit())?;
        Ok(Stored {
            gseq: gseq as u64,
            tseq: tseq as u64,
            received_at,
            env,
        })
    }

    fn thread(&self, about: &str, since: u64) -> Res<Vec<Stored>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = sq(conn.prepare(
            "SELECT gseq,tseq,received_at,env FROM msgs WHERE about=?1 AND tseq>?2 ORDER BY tseq",
        ))?;
        let rows = sq(stmt
            .query_map(rusqlite::params![about, since as i64], sqlite_row_to_stored)
            .and_then(|r| r.collect::<Result<Vec<_>, _>>()))?;
        rows.into_iter().map(build_stored).collect()
    }

    fn inbox(&self, addr: &str, since: u64) -> Res<Vec<Stored>> {
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

    fn access(&self, about: &str, addr: &str) -> Res<ThreadAccess> {
        let conn = self.conn.lock().unwrap();
        let (any, participant): (bool, bool) = sq(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM msgs WHERE about=?1),
                    EXISTS(SELECT 1 FROM msgs m LEFT JOIN msg_to t ON t.gseq=m.gseq
                           WHERE m.about=?1 AND (m.sender=?2 OR t.addr=?2))",
            rusqlite::params![about, addr],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        Ok(match (any, participant) {
            (false, _) => ThreadAccess::Empty,
            (true, true) => ThreadAccess::Participant,
            (true, false) => ThreadAccess::NotParticipant,
        })
    }

    fn set_retention(&self, entries: &[(String, u32)]) -> Res<()> {
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

    fn sweep(&self, now: u64, default_days: u32) -> Res<u64> {
        let mut conn = self.conn.lock().unwrap();
        let tx = sq(conn.transaction())?;
        let params = rusqlite::params![now as i64, default_days as i64];
        sq(tx.execute(
            &format!(
                "DELETE FROM msg_to WHERE gseq IN (SELECT gseq FROM msgs WHERE {SQLITE_EXPIRED})"
            ),
            params,
        ))?;
        let n = sq(tx.execute(&format!("DELETE FROM msgs WHERE {SQLITE_EXPIRED}"), params))?;
        sq(tx.commit())?;
        Ok(n as u64)
    }

    fn remove(&self, id: &str) -> Res<bool> {
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

// ---- PgStore: Postgres, for the shared multi-tenant tier ----

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS profiles (
  name TEXT PRIMARY KEY,
  root TEXT NOT NULL,
  doc  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS threads (
  about TEXT PRIMARY KEY,
  last_tseq BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS msgs (
  gseq BIGSERIAL PRIMARY KEY,
  id TEXT UNIQUE NOT NULL,
  about TEXT NOT NULL,
  sender TEXT NOT NULL,
  tseq BIGINT NOT NULL,
  received_at BIGINT NOT NULL,
  env TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS msgs_about ON msgs(about, tseq);
CREATE TABLE IF NOT EXISTS msg_to (
  gseq BIGINT NOT NULL REFERENCES msgs(gseq),
  addr TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS msg_to_addr ON msg_to(addr, gseq);
CREATE TABLE IF NOT EXISTS retention (
  sender TEXT PRIMARY KEY,
  days INTEGER NOT NULL
);
";

pub struct PgStore {
    client: Mutex<postgres::Client>,
}

impl PgStore {
    pub fn open(url: &str) -> Result<PgStore, String> {
        let mut client = postgres::Client::connect(url, postgres::NoTls)
            .map_err(|e| format!("postgres connect: {e}"))?;
        client
            .batch_execute(SCHEMA)
            .map_err(|e| format!("postgres schema: {e}"))?;
        Ok(PgStore {
            client: Mutex::new(client),
        })
    }
}

fn db<T>(r: Result<T, postgres::Error>) -> Res<T> {
    r.map_err(|e| (500, format!("storage error: {e}")))
}

fn row_to_stored(row: &postgres::Row) -> Res<Stored> {
    let env_json: String = row.get(3);
    let env: Envelope = serde_json::from_str(&env_json)
        .map_err(|e| (500, format!("corrupt stored envelope: {e}")))?;
    Ok(Stored {
        gseq: row.get::<_, i64>(0) as u64,
        tseq: row.get::<_, i64>(1) as u64,
        received_at: row.get::<_, i64>(2) as u64,
        env,
    })
}

impl Store for PgStore {
    fn register(&self, profile: Profile) -> Res<()> {
        let mut c = self.client.lock().unwrap();
        if let Some(row) =
            db(c.query_opt("SELECT root FROM profiles WHERE name=$1", &[&profile.name]))?
        {
            let root: String = row.get(0);
            if root != profile.root {
                return Err((409, format!("name '{}' is taken", profile.name)));
            }
        }
        let doc = serde_json::to_string(&profile).unwrap();
        db(c.execute(
            "INSERT INTO profiles(name,root,doc) VALUES($1,$2,$3)
             ON CONFLICT(name) DO UPDATE SET root=EXCLUDED.root, doc=EXCLUDED.doc",
            &[&profile.name, &profile.root, &doc],
        ))?;
        Ok(())
    }

    fn profile(&self, name: &str) -> Res<Option<Profile>> {
        let mut c = self.client.lock().unwrap();
        match db(c.query_opt("SELECT doc FROM profiles WHERE name=$1", &[&name]))? {
            Some(row) => {
                let doc: String = row.get(0);
                serde_json::from_str(&doc)
                    .map(Some)
                    .map_err(|e| (500, format!("corrupt profile: {e}")))
            }
            None => Ok(None),
        }
    }

    fn append(&self, env: Envelope, received_at: u64) -> Res<Stored> {
        let mut c = self.client.lock().unwrap();
        let mut tx = db(c.transaction())?;
        if let Some(row) = db(tx.query_opt(
            "SELECT gseq,tseq,received_at,env FROM msgs WHERE id=$1",
            &[&env.id],
        ))? {
            return row_to_stored(&row);
        }
        let tseq: i64 = db(tx.query_one(
            "INSERT INTO threads(about,last_tseq) VALUES($1,1)
             ON CONFLICT(about) DO UPDATE SET last_tseq=threads.last_tseq+1
             RETURNING last_tseq",
            &[&env.about],
        ))?
        .get(0);
        let env_json = serde_json::to_string(&env).unwrap();
        let gseq: i64 = db(tx.query_one(
            "INSERT INTO msgs(id,about,sender,tseq,received_at,env)
             VALUES($1,$2,$3,$4,$5,$6) RETURNING gseq",
            &[
                &env.id,
                &env.about,
                &env.from,
                &tseq,
                &(received_at as i64),
                &env_json,
            ],
        ))?
        .get(0);
        for addr in &env.to {
            db(tx.execute(
                "INSERT INTO msg_to(gseq,addr) VALUES($1,$2)",
                &[&gseq, &addr],
            ))?;
        }
        db(tx.commit())?;
        Ok(Stored {
            gseq: gseq as u64,
            tseq: tseq as u64,
            received_at,
            env,
        })
    }

    fn thread(&self, about: &str, since: u64) -> Res<Vec<Stored>> {
        let mut c = self.client.lock().unwrap();
        let rows = db(c.query(
            "SELECT gseq,tseq,received_at,env FROM msgs WHERE about=$1 AND tseq>$2 ORDER BY tseq",
            &[&about, &(since as i64)],
        ))?;
        rows.iter().map(row_to_stored).collect()
    }

    fn inbox(&self, addr: &str, since: u64) -> Res<Vec<Stored>> {
        let mut c = self.client.lock().unwrap();
        let rows = db(c.query(
            "SELECT DISTINCT m.gseq,m.tseq,m.received_at,m.env
             FROM msgs m JOIN msg_to t ON t.gseq=m.gseq
             WHERE t.addr=$1 AND m.gseq>$2 ORDER BY m.gseq",
            &[&addr, &(since as i64)],
        ))?;
        rows.iter().map(row_to_stored).collect()
    }

    fn access(&self, about: &str, addr: &str) -> Res<ThreadAccess> {
        let mut c = self.client.lock().unwrap();
        let row = db(c.query_one(
            "SELECT EXISTS(SELECT 1 FROM msgs WHERE about=$1),
                    EXISTS(SELECT 1 FROM msgs m LEFT JOIN msg_to t ON t.gseq=m.gseq
                           WHERE m.about=$1 AND (m.sender=$2 OR t.addr=$2))",
            &[&about, &addr],
        ))?;
        let (any, participant): (bool, bool) = (row.get(0), row.get(1));
        Ok(match (any, participant) {
            (false, _) => ThreadAccess::Empty,
            (true, true) => ThreadAccess::Participant,
            (true, false) => ThreadAccess::NotParticipant,
        })
    }

    fn set_retention(&self, entries: &[(String, u32)]) -> Res<()> {
        let mut c = self.client.lock().unwrap();
        let mut tx = db(c.transaction())?;
        db(tx.execute("DELETE FROM retention", &[]))?;
        for (sender, days) in entries {
            db(tx.execute(
                "INSERT INTO retention(sender,days) VALUES($1,$2)",
                &[sender, &(*days as i32)],
            ))?;
        }
        db(tx.commit())
    }

    fn sweep(&self, now: u64, default_days: u32) -> Res<u64> {
        let mut c = self.client.lock().unwrap();
        let mut tx = db(c.transaction())?;
        let now = now as i64;
        let days = default_days as i32;
        db(tx.execute(
            &format!("DELETE FROM msg_to WHERE gseq IN (SELECT gseq FROM msgs WHERE {PG_EXPIRED})"),
            &[&now, &days],
        ))?;
        let n = db(tx.execute(
            &format!("DELETE FROM msgs WHERE {PG_EXPIRED}"),
            &[&now, &days],
        ))?;
        db(tx.commit())?;
        Ok(n)
    }

    fn remove(&self, id: &str) -> Res<bool> {
        let mut c = self.client.lock().unwrap();
        let mut tx = db(c.transaction())?;
        db(tx.execute(
            "DELETE FROM msg_to WHERE gseq IN (SELECT gseq FROM msgs WHERE id=$1)",
            &[&id],
        ))?;
        let n = db(tx.execute("DELETE FROM msgs WHERE id=$1", &[&id]))?;
        db(tx.commit())?;
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

    fn fresh() -> SqliteStore {
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "ecco-store-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        SqliteStore::open(&dir).unwrap()
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
