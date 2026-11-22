//! `signal-sqlite` reading an encrypted database that another process keeps
//! writing, the way Signal Desktop does: WAL mode, frequent commits, TRUNCATE
//! checkpoints, connections opened and closed.
//!
//! The writer is SQLCipher (the same engine `signal-sqlite` uses), run as a
//! separate process because file locks never conflict within one process.

#![cfg(feature = "sqlite")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rusqlite::Connection;

const BIN: &str = env!("CARGO_BIN_EXE_signal-sqlite");
const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const WRITER_DB: &str = "LIVE_READ_DB";
const WRITER_MODE: &str = "LIVE_READ_MODE";
const WRITER_LIMIT: Duration = Duration::from_secs(180);
const WRITER_PAUSE: Duration = Duration::from_millis(1);
const READS: usize = 25;
const PAD_ROWS: u32 = 2000; // about 8 MB between `a` and `b`

/// A temp directory that removes the files these tests create.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "signal_live_read_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        for entry in std::fs::read_dir(&self.0).into_iter().flatten().flatten() {
            std::fs::remove_file(entry.path()).ok();
        }
        std::fs::remove_dir(&self.0).ok();
    }
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn open_encrypted(db: &Path) -> Connection {
    let conn = Connection::open(db).expect("open");
    conn.execute_batch(&format!("PRAGMA key = \"x'{KEY}'\";")).expect("key");
    conn
}

/// `a` and `b` sit at opposite ends of the file and always change together.
fn seed(db: &Path) {
    open_encrypted(db)
        .execute_batch(&format!(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE a(v); INSERT INTO a VALUES(0);
             CREATE TABLE pad(x);
             INSERT INTO pad WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < {PAD_ROWS})
               SELECT zeroblob(3900) FROM n;
             CREATE TABLE b(v); INSERT INTO b VALUES(0);"
        ))
        .unwrap();
}

/// Not a test: the writer, started by `assert_consistent_under`. Any SQLite
/// error here means the reader disturbed the database's owner.
#[test]
#[ignore = "helper process for the live read tests"]
fn writer_process() {
    let (Ok(db), Ok(mode)) = (std::env::var(WRITER_DB), std::env::var(WRITER_MODE)) else {
        return;
    };
    let db = PathBuf::from(db);
    let connect = || {
        let conn = open_encrypted(&db);
        // A long-lived writer must never be made to wait. A connection being
        // opened may briefly wait, as it would for any other SQLite reader.
        let wait_ms = if mode == "reconnect" { 5000 } else { 0 };
        conn.busy_timeout(Duration::from_millis(wait_ms)).unwrap();
        conn.execute_batch("PRAGMA synchronous = OFF;").expect("writer: pragma");
        conn
    };
    let started = Instant::now();
    let mut conn = connect();
    let mut n = 0;
    while !suffixed(&db, ".stop").exists() && started.elapsed() < WRITER_LIMIT {
        n += 1;
        conn.execute_batch(&format!("BEGIN IMMEDIATE; UPDATE a SET v = {n}; UPDATE b SET v = {n}; COMMIT;"))
            .expect("writer: commit");
        match mode.as_str() {
            // A row saying "busy" is fine; an error is not.
            "truncate" => conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(())).expect("writer: checkpoint"),
            "reconnect" => {
                drop(conn);
                conn = connect();
            }
            _ => {} // "append": automatic checkpoints only
        }
        if n == 1 {
            std::fs::write(suffixed(&db, ".ready"), b"").unwrap();
        }
        // Like Signal, the writer has no busy timeout. Unpaced, it commits so
        // fast that a reader's brief WAL write lock (taken when it sees the
        // index header mid-update, as Signal's own readers do) can land on its
        // next BEGIN. 1000 commits/s is still far above Signal's rate.
        std::thread::sleep(WRITER_PAUSE);
    }
}

struct Writer(Option<Child>);

impl Writer {
    fn start(db: &Path, mode: &str) -> Self {
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["writer_process", "--exact", "--ignored", "--nocapture"])
            .env(WRITER_DB, db)
            .env(WRITER_MODE, mode)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let writer = Writer(Some(child));
        let started = Instant::now();
        while !suffixed(db, ".ready").exists() {
            assert!(started.elapsed() < Duration::from_secs(30), "the writer did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        writer
    }

    fn finish(mut self, db: &Path) -> Result<(), String> {
        std::fs::write(suffixed(db, ".stop"), b"").unwrap();
        let out = self.0.take().unwrap().wait_with_output().unwrap();
        if out.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).into_owned())
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            child.kill().ok();
            child.wait().ok();
        }
    }
}

/// One read through the real binary: both values, or why it failed.
fn read_pair(db: &Path) -> Result<(i64, i64), String> {
    let out = Command::new(BIN)
        .args(["-d", db.to_str().unwrap(), "-k", KEY, "query", "--csv", "SELECT (SELECT v FROM a) AS a, (SELECT v FROM b) AS b"])
        .output()
        .expect("spawn signal-sqlite");
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let last = stdout.trim().lines().last().unwrap_or_default().to_string();
    let (a, b) = last.split_once(',').ok_or_else(|| format!("unexpected output: {stdout}"))?;
    Ok((a.parse().map_err(|_| last.clone())?, b.parse().map_err(|_| last.clone())?))
}

fn assert_consistent_under(mode: &str) {
    let live = Scratch::new();
    let db = live.path("db.sqlite");
    seed(&db);
    let writer = Writer::start(&db, mode);

    let mut bad = Vec::new();
    let mut versions = std::collections::BTreeSet::new();
    for _ in 0..READS {
        match read_pair(&db) {
            Ok((a, b)) if a == b => {
                versions.insert(a);
            }
            Ok((a, b)) => bad.push(format!("mixed generations: a={a} b={b}")),
            Err(e) => bad.push(format!("read failed: {e}")),
        }
    }
    let writer_result = writer.finish(&db);

    assert!(bad.is_empty(), "{}/{READS} bad reads, first: {}", bad.len(), bad[0]);
    assert!(versions.len() > 1, "the writer made no progress, so nothing was exercised");
    assert_eq!(writer_result, Ok(()), "the reader disturbed the writer");
    let integrity: String = open_encrypted(&db).query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
    assert_eq!(integrity, "ok");
}

#[test]
fn consistent_while_a_writer_checkpoints_and_truncates() {
    assert_consistent_under("truncate");
}

#[test]
fn consistent_while_a_writer_appends() {
    assert_consistent_under("append");
}

#[test]
fn consistent_while_connections_open_and_close() {
    assert_consistent_under("reconnect");
}
