//! Make Signal's FTS5 virtual tables openable by plain SQLite.
//!
//! Signal's full-text tables (`messages_fts`, …) are declared with
//! `tokenize = 'signal_tokenizer'`, a tokenizer Signal registers inside its own
//! process. A vanilla SQLite doesn't have it, so any access to those tables
//! fails with `no such tokenizer: signal_tokenizer`. We register that name as an
//! alias for the built-in `unicode61` tokenizer, which lets the tables open and
//! be read. (Full-text `MATCH` then uses unicode61 semantics, which differ
//! slightly from Signal's tokenizer but are close for ordinary text.)
//!
//! This uses the FTS5 C API via raw FFI, since rusqlite has no safe wrapper for
//! registering tokenizers.

use std::ffi::{c_char, c_int, c_void, CString};
use std::ptr;

use rusqlite::serialize::OwnedData;
use rusqlite::{ffi, Connection, MAIN_DB};
use signal_core::Result;

/// Opaque FTS5 tokenizer instance handle (we only ever pass pointers around).
#[repr(C)]
struct Fts5Tokenizer {
    _private: [u8; 0],
}

// C function-pointer types from fts5.h. We never call the tokenizer vtable
// members ourselves (SQLite does); they exist only to lay the structs out with
// the correct ABI so `xFindTokenizer` / `xCreateTokenizer` sit at the right
// offsets.
type XTokenCb =
    unsafe extern "C" fn(*mut c_void, c_int, *const c_char, c_int, c_int, c_int) -> c_int;
type XCreate =
    unsafe extern "C" fn(*mut c_void, *mut *const c_char, c_int, *mut *mut Fts5Tokenizer) -> c_int;
type XDelete = unsafe extern "C" fn(*mut Fts5Tokenizer);
type XTokenize = unsafe extern "C" fn(
    *mut Fts5Tokenizer,
    *mut c_void,
    c_int,
    *const c_char,
    c_int,
    Option<XTokenCb>,
) -> c_int;
type XDestroy = unsafe extern "C" fn(*mut c_void);
type XCreateTokenizer = unsafe extern "C" fn(
    *mut Fts5Api,
    *const c_char,
    *mut c_void,
    *mut Fts5TokenizerVtab,
    Option<XDestroy>,
) -> c_int;
type XFindTokenizer =
    unsafe extern "C" fn(*mut Fts5Api, *const c_char, *mut *mut c_void, *mut Fts5TokenizerVtab) -> c_int;

/// Mirror of the C `fts5_tokenizer` vtable, filled by `xFindTokenizer` and
/// copied by `xCreateTokenizer`.
#[repr(C)]
struct Fts5TokenizerVtab {
    x_create: Option<XCreate>,
    x_delete: Option<XDelete>,
    x_tokenize: Option<XTokenize>,
}

/// Prefix of the C `fts5_api` struct — only the two members we use. Accessed
/// through a pointer into SQLite's own allocation, so member offsets must match
/// (iVersion, then xCreateTokenizer, then xFindTokenizer).
#[repr(C)]
struct Fts5Api {
    i_version: c_int,
    x_create_tokenizer: Option<XCreateTokenizer>,
    x_find_tokenizer: Option<XFindTokenizer>,
}

/// Mounts the decrypted database image in memory (read-only) and registers
/// `signal_tokenizer`.
///
/// The plaintext never touches disk: the bytes are handed to SQLite via
/// `sqlite3_deserialize` (like Signal Desktop, which opens its SQLCipher
/// database in place rather than writing a decrypted copy). SQLite owns and
/// frees the backing buffer when the connection closes, and the mounted
/// database is read-only, so Signal's data cannot be modified through it.
pub fn open_in_memory(image: &[u8]) -> Result<Connection> {
    let mut conn = Connection::open_in_memory()?;

    // `sqlite3_deserialize` with the read-only flags rusqlite sets takes
    // ownership of the buffer (SQLITE_DESERIALIZE_FREEONCLOSE) and frees it with
    // `sqlite3_free`, so the image must live in an `sqlite3_malloc` block.
    // SAFETY: `ptr` is a fresh `sqlite3_malloc64` allocation of exactly `sz`
    // bytes that we fully initialize via `copy_nonoverlapping` before wrapping it
    // in `OwnedData`, which then owns it for SQLite to free on close.
    let data = unsafe {
        let sz = image.len();
        let ptr = ffi::sqlite3_malloc64(sz as u64) as *mut u8;
        let nn = ptr::NonNull::new(ptr).ok_or("sqlite3_malloc failed for the database image")?;
        ptr::copy_nonoverlapping(image.as_ptr(), ptr, sz);
        OwnedData::from_raw_nonnull(nn, sz)
    };
    conn.deserialize(MAIN_DB, data, /* read_only = */ true)?;

    // Keep any query spill (sorts, temporary b-trees) in memory too, so no
    // plaintext-derived data is ever written to disk.
    conn.execute_batch("PRAGMA temp_store = MEMORY;")?;

    register_signal_tokenizer(&conn);
    Ok(conn)
}

/// Registers `signal_tokenizer` (an alias for `unicode61`) on `conn`.
pub fn register_signal_tokenizer(conn: &Connection) {
    // Non-fatal: if this fails only the FTS tables are unavailable; every other
    // table still works.
    // SAFETY: `conn` is a live, open connection for the duration of this call.
    unsafe {
        if let Err(err) = register_alias(conn.handle(), "signal_tokenizer", "unicode61") {
            eprintln!("warning: could not register signal_tokenizer: {err}");
        }
    }
}

/// Registers tokenizer `new_name` as an alias for the built-in `base` tokenizer.
///
/// # Safety
/// `db` must be a valid open sqlite3 handle.
unsafe fn register_alias(db: *mut ffi::sqlite3, new_name: &str, base: &str) -> Result<()> {
    let api = fts5_api(db)?;
    let find = (*api).x_find_tokenizer.ok_or("fts5 xFindTokenizer missing")?;
    let create = (*api).x_create_tokenizer.ok_or("fts5 xCreateTokenizer missing")?;

    let base_c = CString::new(base)?;
    let mut context: *mut c_void = ptr::null_mut();
    let mut vtab: Fts5TokenizerVtab = std::mem::zeroed();
    if find(api, base_c.as_ptr(), &mut context, &mut vtab) != ffi::SQLITE_OK {
        return Err(format!("base tokenizer '{base}' not found").into());
    }

    let new_c = CString::new(new_name)?;
    if create(api, new_c.as_ptr(), context, &mut vtab, None) != ffi::SQLITE_OK {
        return Err(format!("failed to register tokenizer '{new_name}'").into());
    }
    Ok(())
}

/// Obtains the `fts5_api` pointer via the documented `SELECT fts5(?1)` handshake.
///
/// # Safety
/// `db` must be a valid open sqlite3 handle.
unsafe fn fts5_api(db: *mut ffi::sqlite3) -> Result<*mut Fts5Api> {
    let sql = CString::new("SELECT fts5(?1)")?;
    let mut stmt: *mut ffi::sqlite3_stmt = ptr::null_mut();
    if ffi::sqlite3_prepare_v2(db, sql.as_ptr(), -1, &mut stmt, ptr::null_mut()) != ffi::SQLITE_OK {
        return Err("fts5 extension is not available in this SQLite build".into());
    }

    let mut api: *mut Fts5Api = ptr::null_mut();
    let ptr_type = CString::new("fts5_api_ptr")?;
    // fts5() writes the fts5_api* into the bound pointer's target.
    ffi::sqlite3_bind_pointer(
        stmt,
        1,
        &mut api as *mut *mut Fts5Api as *mut c_void,
        ptr_type.as_ptr(),
        None,
    );
    ffi::sqlite3_step(stmt);
    ffi::sqlite3_finalize(stmt);

    if api.is_null() {
        return Err("could not obtain the fts5_api pointer".into());
    }
    Ok(api)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    // Reproduces the real-world path that a 0-row database never exercises:
    // register the alias, then CREATE an FTS5 table that actually uses
    // `signal_tokenizer`, insert content, and MATCH it. If the alias is not
    // truly registered, CREATE fails with "no such tokenizer".
    #[test]
    fn signal_tokenizer_alias_works_on_real_content() {
        let conn = Connection::open_in_memory().unwrap();
        unsafe {
            register_alias(conn.handle(), "signal_tokenizer", "unicode61").expect("register_alias");
        }
        conn.execute_batch(
            "CREATE VIRTUAL TABLE t USING fts5(body, tokenize='signal_tokenizer');\
             INSERT INTO t(body) VALUES ('hello world');",
        )
        .expect("create + insert with signal_tokenizer");
        let hits: i64 = conn
            .query_row("SELECT count(*) FROM t WHERE t MATCH 'hello'", [], |r| r.get(0))
            .expect("MATCH query");
        assert_eq!(hits, 1, "MATCH should find the inserted row");
    }

    // Faithful reproduction of the real Signal case: an FTS5 table shaped exactly
    // like Signal's `messages_fts` is created and populated, then its on-disk
    // image is read back and mounted READ-ONLY in memory through the production
    // `open_in_memory()` path and MATCHed. This is the scenario a 0-row database
    // never reached, and it also proves MATCH works on a deserialized image.
    #[test]
    fn signal_shaped_fts_table_matches_when_mounted_in_memory() {
        let mut path = std::env::temp_dir();
        path.push(format!("fts_probe_{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);

        // Phase 1: create + populate exactly like Signal (writable connection).
        {
            let conn = Connection::open(&path).unwrap();
            unsafe {
                register_alias(conn.handle(), "signal_tokenizer", "unicode61").expect("register");
            }
            conn.execute_batch(
                "CREATE VIRTUAL TABLE messages_fts USING fts5(body, tokenize = 'signal_tokenizer');\
                 INSERT INTO messages_fts(body) VALUES ('hello world from signal');",
            )
            .expect("create signal-shaped fts table");
        }

        // Phase 2: read the image and mount it through the real production path
        // (deserialize read-only + register) and MATCH.
        let image = std::fs::read(&path).expect("read db image");
        let _ = std::fs::remove_file(&path);
        let conn = open_in_memory(&image).expect("production open_in_memory()");
        let hits: i64 = conn
            .query_row(
                "SELECT count(*) FROM messages_fts WHERE messages_fts MATCH 'hello'",
                [],
                |r| r.get(0),
            )
            .expect("MATCH on in-memory read-only db");
        assert_eq!(hits, 1, "MATCH must work on an image mounted read-only in memory");
    }

}
