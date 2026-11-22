//! End-to-end test of `signal-sqlite mcp`: spawn the real binary, speak
//! JSON-RPC over its stdin/stdout, and assert the handshake plus a tool call.
//!
//! This covers the whole process path — key via `-k`, SQLCipher decrypt, serve
//! loop — that the in-process `mcp.rs` unit tests (which call `handle_line`
//! directly) cannot. No new dependency; only `std::process`.

#![cfg(feature = "sqlite")]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_signal-sqlite");

/// `KEY32` in `src/testdata/gen_wal_fixtures.sh`; decrypts the `items` fixture.
const FIXTURE_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn fixture_db() -> PathBuf {
    // A private copy: SQLite may create sidecar files beside what it opens.
    let dir = std::env::temp_dir().join(format!("mcp_fixture_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let copy = dir.join("enc.sqlite");
    std::fs::copy(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/testdata/enc.sqlite"), &copy).unwrap();
    copy
}

#[test]
fn mcp_handshake_and_tool_call_over_stdio() {
    let mut child = Command::new(BIN)
        .args(["-d", fixture_db().to_str().unwrap(), "-k", FIXTURE_KEY, "mcp"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mcp server");

    // A full session: initialize, the initialized notification (no reply),
    // tools/list, then a list_tables call. Closing stdin drives the server to
    // EOF so it exits; the total output is a few KB, well under the pipe buffer,
    // so writing everything before reading cannot deadlock.
    let requests = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_tables","arguments":{}}}"#,
    ];
    {
        let mut stdin = child.stdin.take().expect("child stdin");
        for req in requests {
            writeln!(stdin, "{req}").expect("write request");
        }
        // `stdin` is dropped here, signalling EOF to the server.
    }

    let output = child.wait_with_output().expect("wait for mcp server");
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let responses: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    // The notification is answered with nothing, so 3 requests with an id → 3 lines.
    assert_eq!(responses.len(), 3, "expected 3 responses, got:\n{stdout}");

    // initialize: protocol echoed, server identified.
    assert!(responses[0].contains(r#""protocolVersion":"2024-11-05""#), "init: {}", responses[0]);
    assert!(responses[0].contains(r#""name":"signal-sqlite""#), "init: {}", responses[0]);

    // tools/list: the read-only tool set.
    for tool in ["list_tables", "describe_schema", "search_messages", "query"] {
        assert!(responses[1].contains(tool), "tools/list missing {tool}: {}", responses[1]);
    }

    // tools/call list_tables: the fixture's `items` table in the JSON envelope.
    assert!(responses[2].contains("items"), "list_tables should see the fixture table: {}", responses[2]);
}
