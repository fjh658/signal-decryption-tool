//! Binary-level tests for `signal-sqlite`: golden CLI behavior (help, version,
//! usage exit codes) and end-to-end `query`/`tables`/`schema` against the
//! committed SQLCipher fixture, driving the real binary as a subprocess.
//!
//! No new dependency: the binary path comes from Cargo's `CARGO_BIN_EXE_*` and
//! stdin/stdout are driven with `std::process::Command`. These run only with the
//! `sqlite` feature (the binary needs it); without the feature the file is empty.

#![cfg(feature = "sqlite")]

use std::path::PathBuf;
use std::process::{Command, Output};

/// The built `signal-sqlite` binary (Cargo sets this for integration tests).
const BIN: &str = env!("CARGO_BIN_EXE_signal-sqlite");

/// The raw key that decrypts the committed fixture — `KEY32` in
/// `src/testdata/gen_wal_fixtures.sh` (bytes 0x00..=0x1f). The fixture's `items` table holds
/// alpha/beta/gamma.
const FIXTURE_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// A private copy of a committed fixture (plus its `-wal`, if any) in a fresh
/// temp directory. SQLite may create a `-shm` beside a WAL database it opens,
/// and that must never land in src/testdata.
fn fixture_copy(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/testdata").join(name);
    let dir = std::env::temp_dir().join(format!("sqlite_fixture_{}_{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::create_dir_all(&dir).unwrap();
    for suffix in ["", "-wal"] {
        let from = PathBuf::from(format!("{}{suffix}", src.display()));
        if from.exists() {
            std::fs::copy(&from, dir.join(format!("{name}{suffix}"))).unwrap();
        }
    }
    dir.join(name)
}

/// A private copy of the committed encrypted fixture database (see `fixture_copy`).
fn fixture_db() -> PathBuf {
    fixture_copy("enc.sqlite")
}

/// Runs the binary against the fixture (explicit `-d`/`-k`, so no Signal config
/// or OS keychain is touched) with the given trailing arguments.
fn run_on_fixture(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(["-d", fixture_db().to_str().unwrap(), "-k", FIXTURE_KEY])
        .args(args)
        .output()
        .expect("spawn signal-sqlite")
}

// --- Golden CLI surface: help, version, usage exit codes -------------------

#[test]
fn help_lists_every_subcommand_and_exits_zero() {
    let out = Command::new(BIN).arg("--help").output().expect("spawn");
    assert!(out.status.success(), "--help should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Usage"), "help should show a usage line:\n{stdout}");
    for sub in ["query", "tables", "schema", "repl", "mcp"] {
        assert!(stdout.contains(sub), "help missing subcommand '{sub}':\n{stdout}");
    }
}

#[test]
fn version_names_the_binary() {
    let out = Command::new(BIN).arg("--version").output().expect("spawn");
    assert!(out.status.success(), "--version should exit 0");
    assert!(String::from_utf8_lossy(&out.stdout).contains("signal-sqlite"));
}

#[test]
fn unknown_subcommand_is_a_usage_error() {
    let out = Command::new(BIN).arg("frobnicate").output().expect("spawn");
    // clap reports usage errors with exit code 2, before any database is opened.
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn query_without_sql_is_a_usage_error() {
    let out = Command::new(BIN).arg("query").output().expect("spawn");
    assert_eq!(out.status.code(), Some(2));
}

// --- End to end against the fixture database -------------------------------

#[test]
fn query_reads_the_fixture_rows() {
    let out = run_on_fixture(&["query", "SELECT name FROM items ORDER BY id"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for name in ["alpha", "beta", "gamma"] {
        assert!(stdout.contains(name), "missing '{name}' in:\n{stdout}");
    }
}

#[test]
fn query_json_emits_a_json_array() {
    let out = run_on_fixture(&["query", "--json", "SELECT name FROM items ORDER BY id"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let trimmed = stdout.trim();
    assert!(trimmed.starts_with('[') && trimmed.ends_with(']'), "not a JSON array:\n{stdout}");
    assert!(trimmed.contains(r#"{"name":"alpha"}"#), "missing first row object:\n{stdout}");
}

#[test]
fn tables_lists_the_fixture_table() {
    let out = run_on_fixture(&["tables"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("items"));
}

#[test]
fn schema_prints_the_create_statement() {
    let out = run_on_fixture(&["schema", "items"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("CREATE TABLE") && stdout.contains("items"), "schema was:\n{stdout}");
}

// --- BLOB rendering: summary by default, hex on request --------------------

#[test]
fn blob_summarized_by_default_and_hex_on_request() {
    // A literal blob avoids needing a blob column in the fixture.
    let summary = run_on_fixture(&["query", "SELECT x'0a1b2c' AS b"]);
    assert!(summary.status.success(), "stderr: {}", String::from_utf8_lossy(&summary.stderr));
    assert!(String::from_utf8_lossy(&summary.stdout).contains("<3 bytes>"));

    let hex = run_on_fixture(&["query", "--blob", "hex", "SELECT x'0a1b2c' AS b"]);
    assert!(hex.status.success(), "stderr: {}", String::from_utf8_lossy(&hex.stderr));
    assert!(String::from_utf8_lossy(&hex.stdout).contains("0a1b2c"));
}

// --- Multi-statement guard (the CLI warns and runs only the first) ---------

#[test]
fn multi_statement_query_warns_and_runs_only_the_first() {
    let out = run_on_fixture(&["query", "SELECT name FROM items ORDER BY id; SELECT 999"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("alpha"), "first statement should still run:\n{stdout}");
    assert!(!stdout.contains("999"), "the second statement must not run:\n{stdout}");
    assert!(
        stderr.to_lowercase().contains("first"),
        "a warning naming that only the first statement runs is expected:\n{stderr}"
    );
}

// --- export: write the decrypted database to a plaintext SQLite file --------

#[test]
fn export_writes_a_plaintext_sqlite_file() {
    let out = std::env::temp_dir().join(format!("sqlite_export_{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&out);

    let result = run_on_fixture(&["export", out.to_str().unwrap()]);
    assert!(result.status.success(), "stderr: {}", String::from_utf8_lossy(&result.stderr));

    let bytes = std::fs::read(&out).expect("exported file exists");
    // Plaintext (not encrypted): it begins with the SQLite magic header...
    assert!(bytes.starts_with(b"SQLite format 3\0"), "not a plaintext SQLite file");
    // ...and carries the fixture's decrypted data as readable bytes.
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("items"), "table name missing from export");
    assert!(text.contains("alpha"), "row data missing from export");

    let _ = std::fs::remove_file(&out);
}

#[test]
fn export_refuses_to_clobber_without_force() {
    let out =
        std::env::temp_dir().join(format!("sqlite_export_clobber_{}.sqlite", std::process::id()));
    std::fs::write(&out, b"pre-existing").unwrap();

    // Without --force the export must fail and leave the file untouched.
    let refused = run_on_fixture(&["export", out.to_str().unwrap()]);
    assert!(!refused.status.success(), "should refuse to overwrite without --force");
    assert_eq!(std::fs::read(&out).unwrap(), b"pre-existing");

    // With --force it overwrites with the real export.
    let forced = run_on_fixture(&["export", "--force", out.to_str().unwrap()]);
    assert!(forced.status.success(), "stderr: {}", String::from_utf8_lossy(&forced.stderr));
    assert!(std::fs::read(&out).unwrap().starts_with(b"SQLite format 3\0"));

    let _ = std::fs::remove_file(&out);
}

// `--force` over an existing world-readable file must not inherit its mode:
// the plaintext export has to end up owner-only either way.
#[cfg(unix)]
#[test]
fn export_force_over_a_world_readable_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let out = std::env::temp_dir().join(format!("sqlite_export_perm_{}.sqlite", std::process::id()));
    std::fs::write(&out, b"pre-existing").unwrap();
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o644)).unwrap();

    let forced = run_on_fixture(&["export", "--force", out.to_str().unwrap()]);
    assert!(forced.status.success(), "stderr: {}", String::from_utf8_lossy(&forced.stderr));
    let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
    assert!(std::fs::read(&out).unwrap().starts_with(b"SQLite format 3\0"));
    let _ = std::fs::remove_file(&out);
    assert_eq!(mode, 0o600, "forced export must be owner-only, got {mode:o}");
}

// --- profiles as Signal leaves them ------------------------------------------

#[test]
fn never_launched_signal_is_explained() {
    let out = Command::new(BIN).args(["-c", "/nonexistent/Signal/config.json", "tables"]).output().expect("spawn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("/nonexistent/Signal/config.json") && stderr.contains("start Signal"), "{stderr}");
}

#[test]
fn plaintext_key_in_config_opens_the_default_database() {
    // Linux basic_text store: config.json has `key`, the database sits at sql/db.sqlite.
    let dir = std::env::temp_dir().join(format!("sqlite_plain_profile_{}", std::process::id()));
    std::fs::create_dir_all(dir.join("sql")).unwrap();
    std::fs::copy(fixture_db(), dir.join("sql/db.sqlite")).unwrap();
    std::fs::write(dir.join("config.json"), format!(r#"{{"key":"{FIXTURE_KEY}"}}"#)).unwrap();
    let out = Command::new(BIN)
        .args(["-c", dir.join("config.json").to_str().unwrap(), "tables"])
        .output()
        .expect("spawn");
    for name in ["sql/db.sqlite", "config.json"] {
        let _ = std::fs::remove_file(dir.join(name));
    }
    let _ = std::fs::remove_dir(dir.join("sql"));
    let _ = std::fs::remove_dir(&dir);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("items"));
}

// --- export paths at the limits ---------------------------------------------

/// A fresh directory for one export test, removed with its files afterwards.
fn export_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sqlite_export_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn remove_export_dir(dir: &std::path::Path) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let _ = std::fs::remove_file(entry.path());
    }
    let _ = std::fs::remove_dir(dir);
}

#[test]
fn force_export_works_for_the_longest_file_name() {
    // 255 bytes is the usual per-name limit; the temporary sibling must not
    // be longer than the target's name.
    let dir = export_dir("longname");
    let out = dir.join(format!("{}.sqlite", "n".repeat(255 - ".sqlite".len())));
    std::fs::write(&out, b"pre-existing").unwrap();
    let forced = run_on_fixture(&["export", "--force", out.to_str().unwrap()]);
    let written = std::fs::read(&out).unwrap_or_default();
    remove_export_dir(&dir);
    assert!(forced.status.success(), "stderr: {}", String::from_utf8_lossy(&forced.stderr));
    assert!(written.starts_with(b"SQLite format 3\0"));
}

// Raw CreateFileW paths are limited to MAX_PATH unless they are in `\\?\` form.
#[cfg(windows)]
#[test]
fn export_beyond_max_path_works_with_and_without_force() {
    let base = export_dir("maxpath");
    let mut dir = base.clone();
    while dir.as_os_str().len() < 300 {
        dir = dir.join("d".repeat(40));
    }
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("export.sqlite");
    let fresh = run_on_fixture(&["export", out.to_str().unwrap()]);
    let forced = run_on_fixture(&["export", "--force", out.to_str().unwrap()]);
    let written = std::fs::read(&out).unwrap_or_default();
    let _ = std::fs::remove_file(&out);
    while dir != base {
        let _ = std::fs::remove_dir(&dir);
        dir.pop();
    }
    remove_export_dir(&base);
    assert!(fresh.status.success(), "fresh: {}", String::from_utf8_lossy(&fresh.stderr));
    assert!(forced.status.success(), "force: {}", String::from_utf8_lossy(&forced.stderr));
    assert!(written.starts_with(b"SQLite format 3\0"));
}

// --- WAL: the CLI picks up the `-wal` sidecar and replays it -----------------

#[test]
fn wal_sidecar_is_replayed_through_the_cli() {
    // desktop_wal.sqlite holds alpha+beta; gamma and the `wal_only` table were
    // committed to desktop_wal.sqlite-wal (whose first frame is page 1).
    let db = testdata("desktop_wal.sqlite");
    let out = Command::new(BIN)
        .args(["-d", db.to_str().unwrap(), "-k", FIXTURE_KEY])
        .args(["query", "SELECT name FROM items UNION ALL SELECT name FROM sqlite_schema WHERE name = 'wal_only'"])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for name in ["alpha", "beta", "gamma", "wal_only"] {
        assert!(stdout.contains(name), "missing '{name}':\n{stdout}");
    }
}

// --- Opening from places SQLite treats specially -----------------------------

/// Makes a directory unwritable for this user while alive. `None` when that
/// does not stop this user from creating files there (root, for one).
struct ReadOnlyDir(PathBuf);

impl ReadOnlyDir {
    fn new(dir: &std::path::Path) -> Option<Self> {
        set_dir_writable(dir, false);
        let guard = ReadOnlyDir(dir.to_path_buf());
        let probe = dir.join("probe");
        if std::fs::write(&probe, b"").is_ok() {
            let _ = std::fs::remove_file(&probe);
            return None;
        }
        Some(guard)
    }
}

impl Drop for ReadOnlyDir {
    fn drop(&mut self) {
        set_dir_writable(&self.0, true);
    }
}

#[cfg(unix)]
fn set_dir_writable(dir: &std::path::Path, writable: bool) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(if writable { 0o755 } else { 0o555 })).unwrap();
}

#[cfg(windows)]
fn set_dir_writable(dir: &std::path::Path, writable: bool) {
    // Deny Everyone (S-1-1-0) creating files and folders in it; the owner can
    // still change the ACL back.
    let change: &[&str] = if writable { &["/remove:d", "*S-1-1-0"] } else { &["/deny", "*S-1-1-0:(WD,AD)"] };
    let out = Command::new("icacls").arg(dir).args(change).output().expect("spawn icacls");
    assert!(out.status.success(), "icacls: {}", String::from_utf8_lossy(&out.stdout));
}

// A read-only mount or a forensic image: SQLite cannot create the `-shm` index
// beside a WAL database there, which must not hide the rows in the WAL.
#[test]
fn wal_database_in_a_read_only_directory_is_readable() {
    let db = fixture_copy("desktop_wal.sqlite");
    let dir = db.parent().unwrap().to_path_buf();
    let Some(read_only) = ReadOnlyDir::new(&dir) else {
        eprintln!("skipped: this user can write to a read-only directory");
        return;
    };
    let out = Command::new(BIN)
        .args(["-d", db.to_str().unwrap(), "-k", FIXTURE_KEY])
        .args(["query", "--csv", "SELECT name FROM items"])
        .output()
        .expect("spawn");
    let shm_created = dir.join("desktop_wal.sqlite-shm").exists();
    drop(read_only);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for name in ["alpha", "beta", "gamma"] {
        assert!(stdout.lines().any(|l| l == name), "missing '{name}':\n{stdout}");
    }
    assert!(!shm_created, "nothing may be created in a read-only directory");
}

// Win32 file APIs stop at MAX_PATH unless the path is in `\\?\` form, and
// SQLite's own file opens are no exception.
#[cfg(windows)]
#[test]
fn database_beyond_max_path_is_readable() {
    let db = fixture_copy("desktop_wal.sqlite");
    let base = db.parent().unwrap().to_path_buf();
    let mut dir = base.clone();
    while dir.as_os_str().len() < 300 {
        dir = dir.join("d".repeat(40));
    }
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["desktop_wal.sqlite", "desktop_wal.sqlite-wal"] {
        std::fs::copy(base.join(name), dir.join(name)).unwrap();
    }
    let out = Command::new(BIN)
        .args(["-d", dir.join("desktop_wal.sqlite").to_str().unwrap(), "-k", FIXTURE_KEY])
        .args(["query", "--csv", "SELECT count(*) AS n FROM items"])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).lines().last(), Some("3"));
}

// --- JSON output stays valid JSON for every SQLite value ---------------------

#[test]
fn json_output_maps_non_finite_reals_to_null() {
    let out = run_on_fixture(&["query", "--json", "SELECT 1e999 AS pinf, -1e999 AS ninf, 1.5 AS x"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), r#"[{"pinf":null,"ninf":null,"x":1.5}]"#);
}

// --- mobile cipher profiles (iOS / Android) against their fixtures ----------

/// iOS 96-hex keyspec and Android 64-hex passphrase for the committed fixtures
/// (`KEY32` and `SALT16` in `src/testdata/gen_wal_fixtures.sh`).
const IOS_FIXTURE_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";
const ANDROID_FIXTURE_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn testdata(name: &str) -> PathBuf {
    fixture_copy(name)
}

// --- the database engine reads exactly what Signal wrote ---------------------

/// The 96-hex keyspec the iOS WAL fixture was made with (key then salt).
const IOS_WAL_KEY: &str = IOS_FIXTURE_KEY;

#[test]
fn mobile_wal_sidecars_are_replayed_through_the_cli() {
    for (name, key, cipher) in [("ios_wal.sqlite", IOS_WAL_KEY, "ios"), ("android_wal.sqlite", ANDROID_FIXTURE_KEY, "android")] {
        let db = testdata(name);
        let out = Command::new(BIN)
            .args(["-d", db.to_str().unwrap(), "-k", key, "--cipher", cipher])
            .args(["query", "SELECT name FROM items UNION ALL SELECT name FROM sqlite_schema WHERE name = 'wal_only'"])
            .output()
            .expect("spawn");
        assert!(out.status.success(), "{cipher}: {}", String::from_utf8_lossy(&out.stderr));
        let stdout = String::from_utf8_lossy(&out.stdout);
        for row in ["alpha", "beta", "gamma", "wal_only"] {
            assert!(stdout.contains(row), "{cipher}: missing '{row}':\n{stdout}");
        }
    }
}

#[test]
fn wrong_key_is_reported_as_such() {
    let out = Command::new(BIN)
        .args(["-d", fixture_db().to_str().unwrap(), "-k", &"ff".repeat(32), "tables"])
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("wrong key"), "{stderr}");
    // SQLCipher's default log (stderr off Apple) stays off; see .cargo/config.toml.
    assert!(!stderr.contains("ERROR CORE"), "SQLCipher logged on its own:\n{stderr}");
}

#[test]
fn a_key_that_is_not_hex_is_rejected_before_use() {
    // The key ends up in a PRAGMA; anything but hex digits must never get there.
    let out = Command::new(BIN)
        .args(["-d", fixture_db().to_str().unwrap(), "-k", "00'; ATTACH DATABASE 'x' AS y; --", "tables"])
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("hex"), "{stderr}");
}

#[test]
fn reading_never_changes_the_database_or_its_wal() {
    let db = testdata("desktop_wal.sqlite");
    let digest = |p: &PathBuf| std::fs::read(p).unwrap();
    let wal = PathBuf::from(format!("{}-wal", db.display()));
    let (before_db, before_wal) = (digest(&db), digest(&wal));
    let out = Command::new(BIN)
        .args(["-d", db.to_str().unwrap(), "-k", FIXTURE_KEY, "query", "SELECT count(*) FROM items"])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(digest(&db) == before_db && digest(&wal) == before_wal, "the database or its WAL changed");
}

#[test]
fn ios_profile_queries_through_the_cli() {
    let db = testdata("ios_enc.sqlite");
    let out = Command::new(BIN)
        .args(["-d", db.to_str().unwrap(), "-k", IOS_FIXTURE_KEY, "--cipher", "ios"])
        .args(["query", "SELECT name FROM items ORDER BY id"])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for name in ["alpha", "beta", "gamma"] {
        assert!(stdout.contains(name), "missing '{name}':\n{stdout}");
    }
}

#[test]
fn android_profile_queries_through_the_cli() {
    let db = testdata("android_enc.sqlite");
    let out = Command::new(BIN)
        .args(["-d", db.to_str().unwrap(), "-k", ANDROID_FIXTURE_KEY, "--cipher", "android"])
        .args(["query", "SELECT name FROM items ORDER BY id"])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for name in ["alpha", "beta", "gamma"] {
        assert!(stdout.contains(name), "missing '{name}':\n{stdout}");
    }
}

#[test]
fn mobile_cipher_without_key_is_an_error() {
    // A mobile profile has nothing to auto-recover, so a missing --key must fail
    // cleanly rather than trying the desktop keychain path.
    let db = testdata("ios_enc.sqlite");
    let out = Command::new(BIN)
        .args(["-d", db.to_str().unwrap(), "--cipher", "ios", "tables"])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "mobile cipher without --key should fail");
    assert!(String::from_utf8_lossy(&out.stderr).to_lowercase().contains("key"));
}
