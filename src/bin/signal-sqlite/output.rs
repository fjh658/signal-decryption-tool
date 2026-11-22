//! Running SQL and rendering results as a table, JSON, or CSV.

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use rusqlite::types::ValueRef;
use rusqlite::Connection;
use signal_core::Result;

/// Output format for query results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    #[default]
    Table,
    Json,
    Csv,
}

/// How BLOB values are rendered. Binary is summarized by default (safe and
/// compact); `Hex` emits every byte as lowercase hex so the bytes can be
/// extracted losslessly (e.g. piped into `xxd -r -p`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum BlobFormat {
    /// `<N bytes>`, never dumping the content (default).
    #[default]
    Summary,
    /// Lowercase hex of the raw bytes.
    Hex,
}

/// A query result: column names plus string-rendered rows.
struct Rows {
    columns: Vec<String>,
    rows: Vec<Vec<Cell>>,
}

/// A rendered cell value, keeping SQL NULL distinct from an empty string and
/// text distinct from numbers (so JSON can quote appropriately).
enum Cell {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

/// Executes `sql` and prints the result in the requested format.
///
/// Only the first statement runs (see [`query`]); if more were given, warn on
/// stderr rather than discarding them silently.
pub fn run_query(conn: &Connection, sql: &str, format: Format, blob: BlobFormat) -> Result<()> {
    let sql = match first_statement_len(conn, sql) {
        Some(len) => {
            eprintln!(
                "warning: multiple statements were given; only the first runs and the rest \
                 are ignored. Run statements one at a time."
            );
            sql.get(..len).unwrap_or(sql)
        }
        None => sql,
    };
    let result = query(conn, sql)?;
    match format {
        Format::Table => print_table(&result, blob),
        Format::Json => print_json(&result, blob),
        Format::Csv => print_csv(&result, blob),
    }
    Ok(())
}

/// Lists the user tables in the requested format. (Table names are never blobs,
/// so blob rendering is irrelevant here.)
pub fn list_tables(conn: &Connection, format: Format) -> Result<()> {
    run_query(
        conn,
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        format,
        BlobFormat::Summary,
    )
}

/// Prints `CREATE` statements for all objects, or just the named table.
pub fn show_schema(conn: &Connection, table: Option<&str>) -> Result<()> {
    let result = match table {
        Some(name) => {
            let mut stmt = conn.prepare(
                "SELECT sql FROM sqlite_master WHERE name = ?1 AND sql IS NOT NULL",
            )?;
            let rows = stmt.query(rusqlite::params![name])?;
            collect(rows)?
        }
        None => {
            let mut stmt = conn.prepare(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name",
            )?;
            let rows = stmt.query([])?;
            collect(rows)?
        }
    };
    for row in &result.rows {
        if let Cell::Text(sql) = &row[0] {
            println!("{sql};");
        }
    }
    Ok(())
}

/// Writes the decrypted database to `path` as a plaintext SQLite file.
///
/// This is the one command that deliberately puts plaintext on disk (the user
/// asked to export it): the in-memory image is serialized straight to the file.
/// It is created owner-only (`0600` on Unix) and the destination must not
/// already exist unless `force` is set, so an export can't silently clobber a
/// file or leave a world-readable copy behind.
pub fn export_db(conn: &mut Connection, path: &str, force: bool) -> Result<()> {
    // SQLCipher's own export into a plaintext in-memory database (nothing on
    // disk yet); its bytes are then written owner-only. The source stays
    // read-only: `query_only` is lifted only for the in-memory copy.
    conn.execute_batch("PRAGMA query_only = OFF; ATTACH DATABASE ':memory:' AS plain KEY '';")?;
    // The serialized image borrows the connection, so it is written before the
    // DETACH rather than copied out (that would double the memory it takes).
    let written = conn
        .query_row("SELECT sqlcipher_export('plain')", [], |_| Ok(()))
        .map_err(Into::into)
        .and_then(|()| {
            let image = conn.serialize("plain")?;
            write_private_file(path, &image, force).map(|()| image.len())
        });
    conn.execute_batch("DETACH DATABASE plain; PRAGMA query_only = ON;")?;
    let size = written?;
    // A relative PATH is resolved against the current working directory; report
    // the absolute location so there is no doubt where the file landed.
    let shown = std::fs::canonicalize(path)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.to_string());
    eprintln!(
        "exported {size} bytes of decrypted (plaintext) SQLite to {shown}"
    );
    Ok(())
}

/// Writes `bytes` to `path` with owner-only permissions, refusing to overwrite
/// an existing file unless `force` is set.
///
/// With `force`, the existing file is never written into: its mode (say 0644)
/// would survive the truncate, and anyone already holding it open could read
/// the plaintext. A fresh owner-only file is written beside it instead and
/// atomically renamed over the target.
fn write_private_file(path: &str, bytes: &[u8], force: bool) -> Result<()> {
    if !force {
        return write_new_private(path, bytes).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!("{path} already exists (pass --force to overwrite)").into()
            } else {
                format!("cannot write {path}: {e}").into()
            }
        });
    }

    // A short sibling name: appending to the target's name could exceed the
    // 255-byte limit for a single name.
    // A leftover from an export that was killed (the same PID recurs, e.g. 1 in
    // a container) is skipped and left alone, so it can never block an export.
    for attempt in 0..TEMP_ATTEMPTS {
        let tmp_path = std::path::Path::new(path)
            .with_file_name(format!(".signal-sqlite.partial-{}-{attempt}", std::process::id()));
        let tmp = tmp_path.to_string_lossy().into_owned();
        match write_new_private(&tmp, bytes) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("cannot write {path} (temporary file {tmp}): {e}").into()),
            Ok(()) => {
                return std::fs::rename(&tmp, path)
                    .inspect_err(|_| {
                        std::fs::remove_file(&tmp).ok();
                    })
                    .map_err(|e| format!("cannot write {path}: {e}").into());
            }
        }
    }
    Err(format!("cannot write {path}: {TEMP_ATTEMPTS} leftover temporary files (.signal-sqlite.partial-*) sit beside it; remove them").into())
}

/// Temporary names tried beside an export target before giving up.
const TEMP_ATTEMPTS: u32 = 100;

/// Creates `path` (O_EXCL, owner-only on Unix) and writes `bytes`; removes the
/// file again if the write fails, so no partial plaintext is left behind.
fn write_new_private(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = create_private(path)?; // only from here on is the file ours to remove
    file.write_all(bytes).inspect_err(|_| {
        std::fs::remove_file(path).ok();
    })
}

/// Creates a new file (failing if it exists) readable only by its owner: mode
/// 0600 on Unix.
#[cfg(not(windows))]
fn create_private(path: &str) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true); // O_EXCL: fail rather than clobber
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Windows equivalent of 0600: the file is created (CREATE_NEW) with a protected
/// DACL holding a single ACE, full access for its owner, so it neither inherits
/// the folder's ACL nor grants anyone else access. Set at creation, not
/// afterwards, so no other handle can be opened on it first.
#[cfg(windows)]
fn create_private(path: &str) -> std::io::Result<std::fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{LocalFree, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE};

    // D:P = protected DACL (no inheritance); A;;FA;;;OW = allow full access to
    // OWNER RIGHTS (S-1-3-4), i.e. whoever owns the file: the creating user.
    const OWNER_ONLY_SDDL: &str = "D:P(A;;FA;;;OW)";
    let wide = |s: &str| std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect::<Vec<u16>>();
    // `\\?\` form: a raw CreateFileW is otherwise limited to MAX_PATH.
    let wide_path = signal_core::winpath::to_wide(path)?;

    let sddl = wide(OWNER_ONLY_SDDL);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated UTF-16; on success `sd` is a LocalAlloc'd
    // descriptor that is freed below.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut())
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    // SAFETY: valid NUL-terminated path and attributes that outlive the call.
    let handle = unsafe {
        CreateFileW(wide_path.as_ptr(), FILE_GENERIC_WRITE, 0, &attrs, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0)
    };
    let err = std::io::Error::last_os_error(); // read before LocalFree can clobber it
    // SAFETY: `sd` came from ConvertStringSecurityDescriptor…W and is freed once.
    unsafe { LocalFree(sd) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(err);
    }
    // SAFETY: a fresh, valid handle we own; the File closes it on drop.
    Ok(unsafe { std::fs::File::from_raw_handle(handle as _) })
}

/// Runs a query and collects all rows into memory.
fn query(conn: &Connection, sql: &str) -> Result<Rows> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query([])?;
    collect(rows)
}

/// Returns `true` when `sql` holds more than one statement. SQLite's own parser
/// decides the boundaries (so a `;` inside a string literal or comment does not
/// count), and trailing whitespace, comments, or empty `;` are not statements.
///
/// rusqlite's `prepare` refuses a multi-statement string outright, so the CLI
/// uses this to warn and run just the first statement, and the MCP server to
/// reject the string with a clear message.
pub(crate) fn has_multiple_statements(conn: &Connection, sql: &str) -> bool {
    first_statement_len(conn, sql).is_some()
}

/// When `sql` holds more than one statement (as [`has_multiple_statements`]
/// counts them), the byte length of the first one through its `;`; `None` when
/// it holds at most one.
fn first_statement_len(conn: &Connection, sql: &str) -> Option<usize> {
    // An interior NUL can never reach SQLite as a C string, so such input is not
    // a multi-statement script; treat it as single and let the real prepare
    // handle it.
    let Ok(csql) = CString::new(sql) else {
        return None;
    };

    // SAFETY: `conn` owns a live `sqlite3*` for the duration of this call. We
    // prepare and immediately finalize each statement, reading only the
    // NUL-terminated buffer we just built and the tail pointers SQLite hands
    // back into it; no statement handle or pointer escapes this function.
    unsafe {
        let db = conn.handle();
        let mut cursor: *const c_char = csql.as_ptr();
        // Where the first statement ends, once one has been seen.
        let mut first_end: Option<usize> = None;
        loop {
            let mut stmt: *mut rusqlite::ffi::sqlite3_stmt = ptr::null_mut();
            let mut tail: *const c_char = ptr::null();
            let rc = rusqlite::ffi::sqlite3_prepare_v2(db, cursor, -1, &mut stmt, &mut tail);
            if rc != rusqlite::ffi::SQLITE_OK {
                // A parse error in the first statement is left for the real run
                // to report; past the first, the leftover text is a further
                // (malformed) statement that would be dropped, so count it.
                return first_end;
            }
            if stmt.is_null() {
                // Only whitespace or comments remained: no further statement.
                return None;
            }
            rusqlite::ffi::sqlite3_finalize(stmt);
            if first_end.is_some() {
                return first_end;
            }
            first_end = Some(tail.offset_from(csql.as_ptr()) as usize);
            cursor = tail;
        }
    }
}

/// Materializes a running statement's columns and all rows.
fn collect(rows: rusqlite::Rows) -> Result<Rows> {
    Ok(collect_capped(rows, usize::MAX)?.0)
}

/// Materializes columns and up to `max` rows. The returned flag is `true` when
/// the statement had more rows than `max` (i.e. the result was truncated).
fn collect_capped(mut rows: rusqlite::Rows, max: usize) -> Result<(Rows, bool)> {
    let columns = rows
        .as_ref()
        .map(|s| s.column_names().map(str::to_owned).collect())
        .unwrap_or_default();

    let mut out = Vec::new();
    let mut truncated = false;
    while let Some(row) = rows.next()? {
        if out.len() >= max {
            truncated = true;
            break;
        }
        let width = row.as_ref().column_count();
        let mut cells = Vec::with_capacity(width);
        for i in 0..width {
            cells.push(cell(row.get_ref(i)?));
        }
        out.push(cells);
    }
    Ok((Rows { columns, rows: out }, truncated))
}

/// Runs `sql` with `params` and returns a JSON envelope
/// `{columns, rows, row_count, truncated}`, materializing at most `max_rows`.
/// Used by the MCP server so an agent receives typed, bounded JSON.
pub fn query_json<P: rusqlite::Params>(
    conn: &Connection,
    sql: &str,
    params: P,
    max_rows: usize,
    blob: BlobFormat,
) -> Result<serde_json::Value> {
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query(params)?;
    let (result, truncated) = collect_capped(rows, max_rows)?;

    let mut json_rows = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        let mut obj = serde_json::Map::new();
        for (name, value) in result.columns.iter().zip(row) {
            obj.insert(name.clone(), value.to_json(blob));
        }
        json_rows.push(serde_json::Value::Object(obj));
    }

    Ok(serde_json::json!({
        "columns": result.columns,
        "rows": json_rows,
        "row_count": result.rows.len(),
        "truncated": truncated,
    }))
}

/// Converts a SQLite value into a renderable cell.
fn cell(value: ValueRef) -> Cell {
    match value {
        ValueRef::Null => Cell::Null,
        ValueRef::Integer(i) => Cell::Int(i),
        ValueRef::Real(f) => Cell::Real(f),
        ValueRef::Text(t) => Cell::Text(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Cell::Blob(b.to_vec()),
    }
}

impl Cell {
    /// Plain display form (table / CSV), rendering blobs per `blob`.
    fn render(&self, blob: BlobFormat) -> String {
        match self {
            Cell::Null => String::new(),
            Cell::Int(i) => i.to_string(),
            Cell::Real(f) => f.to_string(),
            Cell::Text(t) => t.clone(),
            Cell::Blob(b) => blob_string(b, blob),
        }
    }

    /// Typed JSON form (for the MCP server), rendering blobs per `blob`
    /// (summarized by default, emitted as hex only when explicitly requested).
    fn to_json(&self, blob: BlobFormat) -> serde_json::Value {
        match self {
            Cell::Null => serde_json::Value::Null,
            Cell::Int(i) => serde_json::json!(i),
            Cell::Real(f) => serde_json::json!(f),
            Cell::Text(t) => serde_json::json!(t),
            Cell::Blob(b) => serde_json::json!(blob_string(b, blob)),
        }
    }
}

/// Renders blob bytes: a byte-count summary, or lossless lowercase hex.
fn blob_string(bytes: &[u8], blob: BlobFormat) -> String {
    match blob {
        BlobFormat::Summary => format!("<{} bytes>", bytes.len()),
        BlobFormat::Hex => bytes.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

/// Renders an aligned text table (the default).
fn print_table(result: &Rows, blob: BlobFormat) {
    if result.columns.is_empty() {
        return;
    }
    let mut widths: Vec<usize> = result.columns.iter().map(|c| c.chars().count()).collect();
    let cells: Vec<Vec<String>> = result
        .rows
        .iter()
        .map(|row| row.iter().map(|c| c.render(blob)).collect())
        .collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }

    let line = |cols: &[String]| {
        cols.iter()
            .enumerate()
            .map(|(i, c)| format!("{:<width$}", c, width = widths[i]))
            .collect::<Vec<_>>()
            .join(" | ")
    };

    println!("{}", line(&result.columns));
    println!("{}", widths.iter().map(|w| "-".repeat(*w)).collect::<Vec<_>>().join("-+-"));
    for row in &cells {
        println!("{}", line(row));
    }
    println!("({} row{})", result.rows.len(), if result.rows.len() == 1 { "" } else { "s" });
}

/// Renders rows as a JSON array of objects.
fn print_json(result: &Rows, blob: BlobFormat) {
    let mut objects = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        let fields: Vec<String> = result
            .columns
            .iter()
            .zip(row)
            .map(|(name, value)| format!("{}:{}", json_string(name), json_value(value, blob)))
            .collect();
        objects.push(format!("{{{}}}", fields.join(",")));
    }
    println!("[{}]", objects.join(","));
}

/// Renders rows as CSV (header + RFC-4180 quoting).
fn print_csv(result: &Rows, blob: BlobFormat) {
    println!("{}", result.columns.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(","));
    for row in &result.rows {
        println!("{}", row.iter().map(|c| csv_field(&c.render(blob))).collect::<Vec<_>>().join(","));
    }
}

/// JSON-encodes a value with correct typing (numbers unquoted, null bare).
fn json_value(cell: &Cell, blob: BlobFormat) -> String {
    match cell {
        Cell::Null => "null".to_string(),
        Cell::Int(i) => i.to_string(),
        // JSON has no Infinity; null matches what serde_json (the MCP path) emits.
        Cell::Real(f) if !f.is_finite() => "null".to_string(),
        Cell::Real(f) => f.to_string(),
        Cell::Text(t) => json_string(t),
        Cell::Blob(b) => json_string(&blob_string(b, blob)),
    }
}

/// JSON-escapes a string.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// CSV-quotes a field when it contains a comma, quote, or newline.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A temporary file left by an export that was killed (same PID, as in a
    // container) must neither block later exports nor be touched by them.
    #[test]
    fn force_export_survives_a_leftover_temporary_file() {
        let dir = std::env::temp_dir().join(format!("export_leftover_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pid = std::process::id();
        let leftovers = [dir.join(format!(".signal-sqlite.partial-{pid}")), dir.join(format!(".signal-sqlite.partial-{pid}-0"))];
        for leftover in &leftovers {
            std::fs::write(leftover, b"leftover").unwrap();
        }
        let target = dir.join("out.sqlite");
        let result = write_private_file(target.to_str().unwrap(), b"new", true);
        let written = std::fs::read(&target).unwrap_or_default();
        let kept = leftovers.iter().all(|l| std::fs::read(l).unwrap_or_default() == b"leftover");
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            std::fs::remove_file(entry.path()).ok();
        }
        std::fs::remove_dir(&dir).ok();
        assert!(result.is_ok(), "{:?}", result.err().map(|e| e.to_string()));
        assert_eq!(written, b"new");
        assert!(kept, "leftover files must be left alone");
    }

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE t(id INTEGER, name TEXT); INSERT INTO t VALUES (1, 'a');")
            .unwrap();
        c
    }

    #[test]
    fn single_statement_is_not_multiple() {
        let c = conn();
        assert!(!has_multiple_statements(&c, "SELECT * FROM t"));
        assert!(!has_multiple_statements(&c, "SELECT * FROM t;"));
        assert!(!has_multiple_statements(&c, "SELECT * FROM t;  -- trailing comment"));
        // A lone extra `;` is an empty statement, not a second one.
        assert!(!has_multiple_statements(&c, "SELECT * FROM t;;"));
    }

    #[test]
    fn trailing_statement_is_detected() {
        let c = conn();
        assert!(has_multiple_statements(&c, "SELECT 1; SELECT 2"));
        // The trailing write would be dropped (the CLI runs only the first); it still counts.
        assert!(has_multiple_statements(&c, "SELECT * FROM t; DROP TABLE t"));
    }

    #[test]
    fn first_statement_is_cut_after_its_semicolon() {
        let c = conn();
        let sql = "SELECT 'a; b' AS v; SELECT 2";
        assert_eq!(first_statement_len(&c, sql).map(|n| &sql[..n]), Some("SELECT 'a; b' AS v;"));
        assert_eq!(first_statement_len(&c, "SELECT 1;  -- note"), None);
        // A malformed second statement is still cut off after the first.
        assert_eq!(first_statement_len(&c, "SELECT 1; SELCT"), Some("SELECT 1;".len()));
    }

    #[test]
    fn a_semicolon_in_a_string_is_not_a_separator() {
        let c = conn();
        // The `;` is inside a string literal: one statement, not two.
        assert!(!has_multiple_statements(&c, "SELECT 'a; b' AS v"));
    }

    #[test]
    fn parse_error_in_first_statement_is_not_counted() {
        let c = conn();
        // Leave the error for the real prepare to report, don't pre-judge it.
        assert!(!has_multiple_statements(&c, "SELCT bad syntax"));
    }

    #[test]
    fn blob_renders_as_summary_by_default_and_hex_on_request() {
        let c = conn();
        c.execute_batch("CREATE TABLE b(x BLOB); INSERT INTO b VALUES (x'0a1b2c');")
            .unwrap();
        let summary = query_json(&c, "SELECT x FROM b", [], 10, BlobFormat::Summary).unwrap();
        assert_eq!(summary["rows"][0]["x"], "<3 bytes>");
        let hex = query_json(&c, "SELECT x FROM b", [], 10, BlobFormat::Hex).unwrap();
        assert_eq!(hex["rows"][0]["x"], "0a1b2c");
    }
}
