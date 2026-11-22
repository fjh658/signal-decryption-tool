//! Opening Signal's database: recover the key and open the database with
//! SQLCipher itself, read-only, as one more reader next to Signal's own
//! connections.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, ErrorCode, OpenFlags};
use signal_core::error::Error;
use signal_core::{platform, recover_key, Result};

/// How long a statement waits for a lock a writer holds. WAL readers rarely
/// wait; this covers a connection that is just recovering the WAL index.
const BUSY_TIMEOUT: Duration = Duration::from_secs(10);
const DB_HINT: &str = "start Signal Desktop once so it creates its database, or pass the right path with -d";

/// An open, decrypted Signal database.
///
/// The database is read in place by SQLCipher, whose page cache is the only
/// place plaintext exists. No plaintext is ever written to disk, so there is
/// nothing to clean up and no temp file another local user could read.
pub struct SignalDb {
    pub conn: Connection,
}

/// Opens Signal's database read-ready.
///
/// Resolves the config (recovering the key and locating the DB) and opens the
/// database with SQLCipher, read-only. SQLCipher handles the WAL, locking and
/// checkpoints itself, so a query sees one committed state even while Signal
/// writes. Like any SQLite reader it updates the -shm index; the database and
/// its WAL are never written.
/// Where it cannot create that index (a read-only directory) it keeps one in
/// memory instead; see `connect`.
///
/// # Arguments
///
/// * `config_path` - Signal Desktop's `config.json` (default location if `None`).
/// * `db_override`  - explicit database path (default `<config dir>/sql/db.sqlite`).
/// * `key_override` - the 64-hex key to use instead of recovering one.
pub fn open(
    config_path: Option<&str>,
    db_override: Option<&str>,
    key_override: Option<&str>,
) -> Result<SignalDb> {
    // The user never sees or handles the key.
    let key_hex = match key_override {
        Some(hex) => hex.to_string(),
        None => recover_key(Some(&resolve_config(config_path)?))?,
    };

    let db_path = match db_override {
        Some(path) => PathBuf::from(path),
        None => default_db_path(&resolve_config(config_path)?),
    };
    std::fs::metadata(&db_path).map_err(|e| Error::from_io(e, "database", &db_path, DB_HINT))?;
    let pragmas = key_pragmas(key_hex.trim())?;

    let (conn, first_read) = connect(&db_path, &pragmas)?;
    // The first read decrypts page 1: a wrong key fails here, not mid-query.
    if let Err(err) = first_read {
        return Err(match err.sqlite_error_code() {
            Some(ErrorCode::NotADatabase) => format!(
                "cannot decrypt {}: wrong key, or not a Signal database",
                db_path.display()
            )
            .into(),
            _ => err.into(),
        });
    }
    // Sorts and temporary b-trees stay in memory, so no plaintext-derived data
    // is ever written to disk; and no statement may write.
    conn.execute_batch("PRAGMA temp_store = MEMORY; PRAGMA query_only = ON;")?;
    // Signal's custom FTS5 tokenizer is registered so its full-text tables
    // (messages_fts, …) are queryable rather than erroring.
    crate::fts::register_signal_tokenizer(&conn);
    Ok(SignalDb { conn })
}

/// How a connection takes part in SQLite's file locking.
#[derive(Clone, Copy, PartialEq)]
enum Locking {
    /// Shared locks and the `-shm` index, like Signal's own readers.
    Shared,
    /// No file locks, and the WAL index in this process's memory.
    Private,
}

impl Locking {
    /// The SQLite VFS. On Windows the long-path one, so a `\\?\` path may
    /// exceed MAX_PATH; the `-none` variants take no file locks.
    fn vfs(self) -> Option<&'static str> {
        match (cfg!(windows), self) {
            (true, Locking::Shared) => Some("win32-longpath"),
            (true, Locking::Private) => Some("win32-longpath-none"),
            (false, Locking::Shared) => None,
            (false, Locking::Private) => Some("unix-none"),
        }
    }
}

/// Opens `path` read-only with the keying `pragmas` and runs the first read,
/// returning the connection and that read's outcome (`open` explains a wrong
/// key).
///
/// A WAL database whose `-shm` is missing and cannot be created (a read-only
/// mount or directory) cannot be opened the shared way; it is reopened with
/// `Locking::Private`. That is safe because a missing `-shm` means no
/// connection has the database open: every WAL connection keeps it.
fn connect(path: &Path, pragmas: &str) -> Result<(Connection, rusqlite::Result<()>)> {
    // Absolute and, on Windows, in `\\?\` form; symlinks resolved as SQLite does,
    // so the `-shm` checked below is the one SQLite would use.
    let path = std::fs::canonicalize(path).map_err(|e| Error::from_io(e, "database", path, DB_HINT))?;
    let shared = open_with(&path, pragmas, Locking::Shared)?;
    match first_read(&shared) {
        Err(err) if err.sqlite_error_code() == Some(ErrorCode::CannotOpen) && !shm_path(&path).exists() => {
            drop(shared);
            let private = open_with(&path, pragmas, Locking::Private)?;
            let read = first_read(&private);
            Ok((private, read))
        }
        read => Ok((shared, read)),
    }
}

fn open_with(path: &Path, pragmas: &str, locking: Locking) -> Result<Connection> {
    // `mode=ro` makes the database read-only while attached in-memory databases
    // stay writable (which `export` needs); a read-only connection flag would
    // make every attached database read-only too.
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(read_only_uri(path, locking.vfs())?, flags)?;
    conn.execute_batch(pragmas)?;
    if locking == Locking::Private {
        // Without locks SQLite keeps the WAL index in heap memory only in exclusive mode.
        conn.execute_batch("PRAGMA locking_mode = EXCLUSIVE;")?;
    }
    conn.busy_timeout(BUSY_TIMEOUT)?;
    Ok(conn)
}

fn first_read(conn: &Connection) -> rusqlite::Result<()> {
    conn.query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(()))
}

fn shm_path(db: &Path) -> PathBuf {
    let mut shm = db.as_os_str().to_owned();
    shm.push("-shm");
    PathBuf::from(shm)
}

/// A `file:` URI that opens `path` read-only, through `vfs` if given. `%`, `?`
/// and `#` are escaped, as SQLite's URI parser requires; everything else is
/// passed through as is.
fn read_only_uri(path: &Path, vfs: Option<&str>) -> Result<String> {
    let text = path.to_str().ok_or_else(|| format!("{} is not valid Unicode", path.display()))?;
    let escaped = text.replace('%', "%25").replace('?', "%3f").replace('#', "%23");
    Ok(match vfs {
        Some(vfs) => format!("file:{escaped}?mode=ro&vfs={vfs}"),
        None => format!("file:{escaped}?mode=ro"),
    })
}

/// The keying PRAGMA Signal Desktop issues for its database (the same one
/// src/testdata/gen_wal_fixtures.sh uses to create the fixtures). The key is
/// checked to be hex before it is put into the PRAGMA.
fn key_pragmas(key_hex: &str) -> Result<String> {
    if key_hex.len() != 64 || !key_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("desktop key must be 64 hex characters (32 bytes)".into());
    }
    Ok(format!("PRAGMA key = \"x'{key_hex}'\";"))
}

/// Resolves the config path, defaulting to the platform location.
fn resolve_config(config_path: Option<&str>) -> Result<String> {
    match config_path {
        Some(path) => Ok(path.to_string()),
        None => platform::default_config_path(),
    }
}

/// `<config dir>/sql/db.sqlite`.
fn default_db_path(config_path: &str) -> PathBuf {
    Path::new(config_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("sql")
        .join("db.sqlite")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_pragmas_take_only_hex_of_the_right_length() {
        let key = "ab".repeat(32);
        assert_eq!(key_pragmas(&key).unwrap(), format!("PRAGMA key = \"x'{key}'\";"));
        for bad in [&"ab".repeat(31), &format!("{}'z", "ab".repeat(31)), &"zz".repeat(32)] {
            assert!(key_pragmas(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    #[test]
    fn uri_escapes_what_sqlite_would_parse() {
        assert_eq!(read_only_uri(Path::new("/a b/100%?#.sqlite"), None).unwrap(), "file:/a b/100%25%3f%23.sqlite?mode=ro");
        assert_eq!(
            read_only_uri(Path::new(r"\\?\C:\d\db.sqlite"), Some("win32-longpath")).unwrap(),
            r"file:\\%3f\C:\d\db.sqlite?mode=ro&vfs=win32-longpath"
        );
    }

    #[test]
    fn the_database_itself_cannot_be_written() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/testdata/enc.sqlite");
        let dir = std::env::temp_dir().join(format!("db_readonly_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("enc.sqlite");
        std::fs::copy(&src, &copy).unwrap();
        let db = open(None, copy.to_str(), Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")).unwrap();
        // Even with query_only lifted, as `export` does, the source stays read-only.
        let write = db.conn.execute_batch("PRAGMA query_only = OFF; INSERT INTO items(name) VALUES ('x');");
        let before = std::fs::read(&src).unwrap();
        drop(db);
        let unchanged = std::fs::read(&copy).unwrap() == before;
        std::fs::remove_file(&copy).ok();
        std::fs::remove_dir(&dir).ok();
        assert!(write.is_err(), "the write must be refused");
        assert!(unchanged, "the file must be byte-identical");
    }
}
