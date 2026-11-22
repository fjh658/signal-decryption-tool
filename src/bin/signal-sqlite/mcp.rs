//! Minimal MCP (Model Context Protocol) stdio server for `signal-sqlite`.
//!
//! Exposes Signal's decrypted database to an AI agent as a handful of
//! **read-only** tools over JSON-RPC 2.0 on stdin/stdout (the MCP stdio
//! transport: one JSON message per line). The server holds a single decrypted
//! connection for its whole lifetime, so the SQLCipher key is recovered **once**
//! — unlike the one-shot CLI, an agent can issue many queries without
//! re-prompting the OS keychain.
//!
//! Hardening: the connection is already opened `SQLITE_OPEN_READONLY`; on top of
//! that this server forbids `ATTACH` and only accepts `SELECT`/`WITH` queries,
//! and every result is capped. This keeps a crafted query from reaching other
//! files or returning an unbounded dump.
//!
//! Privacy: the tools return real message content. Point this at a **local**
//! model; wiring it to a cloud agent sends private messages off the machine.
//!
//! The protocol is implemented by hand on top of `serde_json` (already a
//! dependency) to avoid pulling in an async MCP SDK.

use std::io::{BufRead, Write};

use rusqlite::Connection;
use serde_json::{json, Value};
use signal_core::Result;

use crate::output;

/// MCP protocol version we implement (echoed back to the client on request).
const PROTOCOL_VERSION: &str = "2024-11-05";
/// Server identity reported in `initialize`.
const SERVER_NAME: &str = "signal-sqlite";

/// Default rows returned by `query` when the caller gives no limit.
const DEFAULT_QUERY_ROWS: usize = 200;
/// Default rows returned by `search_messages`.
const DEFAULT_SEARCH_ROWS: usize = 50;
/// Hard ceiling on rows any single tool call may return, regardless of request.
const MAX_ROWS: usize = 2000;

/// A JSON-RPC protocol-level error (distinct from a tool execution error, which
/// is reported inside a successful `tools/call` result with `isError: true`).
struct RpcError {
    code: i64,
    message: String,
}

/// Serves the MCP protocol over stdin/stdout until the client closes stdin.
pub fn serve(conn: &Connection) -> Result<()> {
    harden(conn);

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break; // EOF: the client went away.
        }
        let message = line.trim();
        if message.is_empty() {
            continue;
        }
        if let Some(response) = handle_line(conn, message) {
            writeln!(out, "{response}")?;
            out.flush()?;
        }
    }
    Ok(())
}

/// Defense in depth on top of the read-only connection: forbid `ATTACH` so a
/// crafted query cannot open or reach another database file.
fn harden(conn: &Connection) {
    // SAFETY: `conn` is a live connection owned by the caller for the duration
    // of `serve`; `sqlite3_limit` only mutates a per-connection limit.
    unsafe {
        rusqlite::ffi::sqlite3_limit(conn.handle(), rusqlite::ffi::SQLITE_LIMIT_ATTACHED, 0);
    }
}

/// Parses one JSON-RPC message and returns the serialized response, or `None`
/// for a notification (a message with no `id`, which must not be answered).
fn handle_line(conn: &Connection, message: &str) -> Option<String> {
    let request: Value = match serde_json::from_str(message) {
        Ok(value) => value,
        Err(err) => {
            let response = error_response(&Value::Null, -32700, &format!("parse error: {err}"));
            return Some(response.to_string());
        }
    };

    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params");

    match request.get("id") {
        // Notification (e.g. `notifications/initialized`): act on nothing, answer nothing.
        None => None,
        Some(id) => {
            let response = match route(conn, method, params) {
                Ok(result) => success_response(id, result),
                Err(err) => error_response(id, err.code, &err.message),
            };
            Some(response.to_string())
        }
    }
}

/// Routes a request method to its handler.
fn route(conn: &Connection, method: &str, params: Option<&Value>) -> std::result::Result<Value, RpcError> {
    match method {
        "initialize" => Ok(initialize_result(params)),
        "tools/list" => Ok(tools_list_result()),
        "tools/call" => Ok(tools_call_result(conn, params)),
        "ping" => Ok(json!({})),
        other => Err(RpcError {
            code: -32601,
            message: format!("method not found: {other}"),
        }),
    }
}

/// `initialize` result: advertise the tools capability and echo the client's
/// requested protocol version when present.
fn initialize_result(params: Option<&Value>) -> Value {
    let version = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSION);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") },
    })
}

/// `tools/list` result: the four read-only tools and their input schemas.
fn tools_list_result() -> Value {
    json!({
        "tools": [
            {
                "name": "list_tables",
                "description": "List the user tables in Signal's database.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "describe_schema",
                "description": "Show CREATE statements for all objects, or just one named table.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "table": { "type": "string", "description": "Optional table name; omit for the whole schema." }
                    }
                }
            },
            {
                "name": "search_messages",
                "description": "Full-text search message bodies (FTS5 MATCH). Returns id, conversationId, sent_at and a snippet, newest first.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "description": "FTS5 MATCH expression, e.g. a word or \"a phrase\"." },
                        "limit": { "type": "integer", "description": "Max rows (default 50)." }
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "query",
                "description": "Run a read-only SQL query (SELECT/WITH only) and return bounded JSON rows.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "sql": { "type": "string", "description": "A single read-only SELECT (or WITH) statement." },
                        "limit": { "type": "integer", "description": "Max rows (default 200, hard cap 2000)." },
                        "blob": { "type": "string", "enum": ["summary", "hex"], "description": "How to render BLOB columns (default summary; hex emits raw bytes)." }
                    },
                    "required": ["sql"]
                }
            }
        ]
    })
}

/// `tools/call` result. A tool's own failure (bad arguments, SQL error) is
/// reported as a successful result with `isError: true`, per MCP convention.
fn tools_call_result(conn: &Connection, params: Option<&Value>) -> Value {
    let Some(params) = params else {
        return tool_error("missing params");
    };
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let empty = json!({});
    let args = params.get("arguments").unwrap_or(&empty);

    let outcome = match name {
        "list_tables" => tool_list_tables(conn),
        "describe_schema" => tool_describe_schema(conn, args),
        "search_messages" => tool_search_messages(conn, args),
        "query" => tool_query(conn, args),
        other => return tool_error(&format!("unknown tool: {other}")),
    };

    match outcome {
        Ok(text) => json!({ "content": [{ "type": "text", "text": text }] }),
        Err(err) => tool_error(&err.to_string()),
    }
}

/// Lists user tables as a JSON envelope.
fn tool_list_tables(conn: &Connection) -> Result<String> {
    let envelope = output::query_json(
        conn,
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        [],
        MAX_ROWS,
        output::BlobFormat::Summary,
    )?;
    stringify(&envelope)
}

/// Shows CREATE statements for one table or the whole schema.
fn tool_describe_schema(conn: &Connection, args: &Value) -> Result<String> {
    let envelope = match args.get("table").and_then(Value::as_str) {
        Some(table) => output::query_json(
            conn,
            "SELECT type, name, sql FROM sqlite_master WHERE name = ?1 AND sql IS NOT NULL",
            rusqlite::params![table],
            MAX_ROWS,
            output::BlobFormat::Summary,
        )?,
        None => output::query_json(
            conn,
            "SELECT type, name, sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type, name",
            [],
            MAX_ROWS,
            output::BlobFormat::Summary,
        )?,
    };
    stringify(&envelope)
}

/// Full-text search over `messages_fts`, joined back to `messages` for context.
fn tool_search_messages(conn: &Connection, args: &Value) -> Result<String> {
    let query = args
        .get("query")
        .and_then(Value::as_str)
        .ok_or("missing 'query' argument")?;
    let limit = row_limit(args, DEFAULT_SEARCH_ROWS);
    let limit_sql = limit as i64;

    let envelope = output::query_json(
        conn,
        "SELECT m.id AS id, m.conversationId AS conversationId, m.sent_at AS sent_at, \
                snippet(messages_fts, 0, '\u{00ab}', '\u{00bb}', '\u{2026}', 16) AS snippet \
         FROM messages_fts JOIN messages m ON m.rowid = messages_fts.rowid \
         WHERE messages_fts MATCH ?1 \
         ORDER BY m.sent_at DESC \
         LIMIT ?2",
        rusqlite::params![query, limit_sql],
        limit,
        output::BlobFormat::Summary,
    )?;
    stringify(&envelope)
}

/// Runs a caller-supplied read-only SQL query.
fn tool_query(conn: &Connection, args: &Value) -> Result<String> {
    let sql = args
        .get("sql")
        .and_then(Value::as_str)
        .ok_or("missing 'sql' argument")?;
    ensure_read_only(sql)?;
    // An agent must send exactly one statement. `prepare` would refuse the
    // string with rusqlite's generic error, so a trailing statement past the
    // SELECT/WITH guard is rejected here first, with a message that says why.
    if output::has_multiple_statements(conn, sql) {
        return Err("only a single SQL statement is allowed".into());
    }
    let limit = row_limit(args, DEFAULT_QUERY_ROWS);
    let envelope = output::query_json(conn, sql, [], limit, blob_format(args))?;
    stringify(&envelope)
}

/// Resolves the optional `blob` argument. Summary (never dumps bytes) is the
/// default; a caller must opt in to `hex` to receive raw blob bytes.
fn blob_format(args: &Value) -> output::BlobFormat {
    match args.get("blob").and_then(Value::as_str) {
        Some("hex") => output::BlobFormat::Hex,
        _ => output::BlobFormat::Summary,
    }
}

/// Clamps the caller's requested `limit` to `[1, MAX_ROWS]`, defaulting when absent.
fn row_limit(args: &Value, default: usize) -> usize {
    args.get("limit")
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(default)
        .clamp(1, MAX_ROWS)
}

/// Rejects anything that is not a single read-only statement. Belt-and-suspenders
/// on top of the read-only connection and the disabled `ATTACH` limit.
fn ensure_read_only(sql: &str) -> Result<()> {
    let keyword = sql
        .trim_start()
        .split(|c: char| c.is_whitespace() || c == '(')
        .find(|token| !token.is_empty())
        .unwrap_or("")
        .to_ascii_uppercase();
    match keyword.as_str() {
        "SELECT" | "WITH" | "VALUES" | "EXPLAIN" => Ok(()),
        "" => Err("empty SQL".into()),
        other => Err(format!("only read-only SELECT/WITH queries are allowed (got '{other}')").into()),
    }
}

/// Pretty-prints a JSON envelope for the tool's text content.
fn stringify(value: &Value) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(Into::into)
}

/// Builds a `tools/call` error result (not a JSON-RPC error).
fn tool_error(message: &str) -> Value {
    json!({
        "content": [{ "type": "text", "text": format!("Error: {message}") }],
        "isError": true,
    })
}

/// Builds a JSON-RPC success response.
fn success_response(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// Builds a JSON-RPC error response.
fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn fixture() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE items(id INTEGER, name TEXT);\
             INSERT INTO items VALUES (1, 'alpha'), (2, 'beta');",
        )
        .unwrap();
        conn
    }

    fn call(conn: &Connection, message: &str) -> Value {
        let response = handle_line(conn, message).expect("request must get a response");
        serde_json::from_str(&response).unwrap()
    }

    #[test]
    fn initialize_reports_server_and_echoes_version() {
        let conn = fixture();
        let v = call(
            &conn,
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        );
        assert_eq!(v["result"]["serverInfo"]["name"], "signal-sqlite");
        assert_eq!(v["result"]["protocolVersion"], "2025-06-18");
        assert!(v["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn tools_list_advertises_all_tools() {
        let conn = fixture();
        let v = call(&conn, r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let names: Vec<&str> = v["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for expected in ["list_tables", "describe_schema", "search_messages", "query"] {
            assert!(names.contains(&expected), "missing tool {expected}");
        }
    }

    #[test]
    fn query_tool_returns_typed_rows() {
        let conn = fixture();
        let v = call(
            &conn,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT id, name FROM items ORDER BY id"}}}"#,
        );
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        let envelope: Value = serde_json::from_str(text).unwrap();
        assert_eq!(envelope["row_count"], 2);
        assert_eq!(envelope["truncated"], false);
        assert_eq!(envelope["rows"][0]["name"], "alpha");
        assert_eq!(envelope["rows"][1]["id"], 2);
    }

    #[test]
    fn query_limit_truncates() {
        let conn = fixture();
        let v = call(
            &conn,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT * FROM items","limit":1}}}"#,
        );
        let envelope: Value =
            serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(envelope["row_count"], 1);
        assert_eq!(envelope["truncated"], true);
    }

    #[test]
    fn non_select_is_rejected() {
        let conn = fixture();
        let v = call(
            &conn,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"query","arguments":{"sql":"DELETE FROM items"}}}"#,
        );
        assert_eq!(v["result"]["isError"], true);
    }

    #[test]
    fn query_tool_renders_blob_as_hex_when_requested() {
        // Default summarizes; `blob: "hex"` opts in to the raw bytes.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE b(x BLOB); INSERT INTO b VALUES (x'0a1b2c');")
            .unwrap();

        let summarized = call(
            &conn,
            r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT x FROM b"}}}"#,
        );
        let env: Value =
            serde_json::from_str(summarized["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(env["rows"][0]["x"], "<3 bytes>");

        let hex = call(
            &conn,
            r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT x FROM b","blob":"hex"}}}"#,
        );
        let env: Value =
            serde_json::from_str(hex["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(env["rows"][0]["x"], "0a1b2c");
    }

    #[test]
    fn multiple_statements_are_rejected() {
        // A second statement smuggled past the SELECT guard must be refused, not
        // silently dropped (the trailing DROP never runs either way, but the
        // caller is told rather than left guessing).
        let conn = fixture();
        let v = call(
            &conn,
            r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"query","arguments":{"sql":"SELECT 1; DROP TABLE items"}}}"#,
        );
        assert_eq!(v["result"]["isError"], true);
    }

    #[test]
    fn unknown_tool_is_an_error_result() {
        let conn = fixture();
        let v = call(
            &conn,
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#,
        );
        assert_eq!(v["result"]["isError"], true);
    }

    #[test]
    fn unknown_method_is_rpc_error() {
        let conn = fixture();
        let v = call(&conn, r#"{"jsonrpc":"2.0","id":7,"method":"frobnicate"}"#);
        assert_eq!(v["error"]["code"], -32601);
    }

    #[test]
    fn notification_gets_no_response() {
        let conn = fixture();
        assert!(handle_line(&conn, r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).is_none());
    }

    // Validates the Signal-shaped SQL behind `search_messages` (the join on
    // rowid, the `snippet()` call, and newest-first ordering) without needing
    // the real database or the keychain. unicode61 stands in for Signal's
    // tokenizer here; the alias itself is covered by fts.rs tests.
    #[test]
    fn search_messages_joins_snippets_and_orders() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE messages(rowid INTEGER PRIMARY KEY, id TEXT, conversationId TEXT, sent_at INTEGER, body TEXT);\
             INSERT INTO messages(rowid, id, conversationId, sent_at, body) VALUES\
                (1, 'm1', 'c1', 1000, 'hello world'),\
                (2, 'm2', 'c1', 2000, 'goodbye world');\
             CREATE VIRTUAL TABLE messages_fts USING fts5(body, tokenize='unicode61');\
             INSERT INTO messages_fts(rowid, body) SELECT rowid, body FROM messages;",
        )
        .unwrap();

        let text = tool_search_messages(&conn, &json!({ "query": "world", "limit": 10 })).unwrap();
        let envelope: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(envelope["row_count"], 2);
        // Newest first (sent_at DESC).
        assert_eq!(envelope["rows"][0]["id"], "m2");
        assert_eq!(envelope["rows"][1]["id"], "m1");
        assert!(envelope["rows"][0]["snippet"].as_str().unwrap().contains("world"));
    }
}
