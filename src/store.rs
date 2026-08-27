//! Relay storage behind one trait. Storage is relay-internal — the protocol
//! only ever sees envelopes, seqs, and receipts — so backends are swappable:
//! `SqliteStore` for self-hosted and dedicated relays (single file, WAL, zero
//! config), `PgStore` (Postgres) for the shared multi-tenant tier.

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
}

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
";

pub struct SqliteStore {
    conn: Mutex<rusqlite::Connection>,
}

impl SqliteStore {
    pub fn open(data: &Path) -> Result<SqliteStore, String> {
        fs::create_dir_all(data).map_err(|e| e.to_string())?;
        let conn = rusqlite::Connection::open(data.join("relay.db")).map_err(|e| e.to_string())?;
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        conn.execute_batch(SQLITE_SCHEMA).map_err(|e| e.to_string())?;
        let store = SqliteStore { conn: Mutex::new(conn) };
        store.import_jsonl(data)?;
        Ok(store)
    }

    /// One-shot migration: replay a pre-SQLite relay's jsonl files into the DB.
    fn import_jsonl(&self, data: &Path) -> Result<(), String> {
        let msgs_path = data.join("msgs.jsonl");
        let profiles_path = data.join("profiles.jsonl");
        if !msgs_path.exists() && !profiles_path.exists() {
            return Ok(());
        }
        let mut conn = self.conn.lock().unwrap();
        let empty: bool = conn
            .query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM msgs) AND NOT EXISTS(SELECT 1 FROM profiles)",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        if !empty {
            return Ok(());
        }
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let mut imported = 0u64;
        for line in read_lines(&profiles_path) {
            if let Ok(p) = serde_json::from_str::<Profile>(&line) {
                let doc = serde_json::to_string(&p).unwrap();
                tx.execute(
                    "INSERT INTO profiles(name,root,doc) VALUES(?1,?2,?3)
                     ON CONFLICT(name) DO UPDATE SET root=excluded.root, doc=excluded.doc",
                    rusqlite::params![p.name, p.root, doc],
                )
                .map_err(|e| e.to_string())?;
            }
        }
        for line in read_lines(&msgs_path) {
            if let Ok(s) = serde_json::from_str::<Stored>(&line) {
                let env_json = serde_json::to_string(&s.env).unwrap();
                tx.execute(
                    "INSERT OR IGNORE INTO msgs(gseq,id,about,sender,tseq,received_at,env)
                     VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    rusqlite::params![
                        s.gseq as i64, s.env.id, s.env.about, s.env.from,
                        s.tseq as i64, s.received_at as i64, env_json
                    ],
                )
                .map_err(|e| e.to_string())?;
                for addr in &s.env.to {
                    tx.execute(
                        "INSERT INTO msg_to(gseq,addr) VALUES(?1,?2)",
                        rusqlite::params![s.gseq as i64, addr],
                    )
                    .map_err(|e| e.to_string())?;
                }
                imported += 1;
            }
        }
        tx.execute_batch(
            "INSERT INTO threads(about,last_tseq)
             SELECT about, MAX(tseq) FROM msgs GROUP BY about
             ON CONFLICT(about) DO UPDATE SET last_tseq=excluded.last_tseq;",
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
        if imported > 0 {
            eprintln!("imported {imported} messages from jsonl into relay.db");
        }
        Ok(())
    }
}

fn read_lines(path: &PathBuf) -> Vec<String> {
    fs::read_to_string(path)
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default()
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
            .query_row("SELECT root FROM profiles WHERE name=?1", [&profile.name], |r| r.get(0))
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
            .query_row("SELECT doc FROM profiles WHERE name=?1", [name], |r| r.get(0))
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
            rusqlite::params![env.id, env.about, env.from, tseq, received_at as i64, env_json],
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
    let env: Envelope =
        serde_json::from_str(&env_json).map_err(|e| (500, format!("corrupt stored envelope: {e}")))?;
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
        if let Some(row) = db(c.query_opt("SELECT root FROM profiles WHERE name=$1", &[&profile.name]))? {
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
            &[&env.id, &env.about, &env.from, &tseq, &(received_at as i64), &env_json],
        ))?
        .get(0);
        for addr in &env.to {
            db(tx.execute("INSERT INTO msg_to(gseq,addr) VALUES($1,$2)", &[&gseq, &addr]))?;
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
}
