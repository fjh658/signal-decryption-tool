//! Command-line interface for `signal-sqlite`.
//!
//! Architecture (see `~/.claude/refs/cli-architecture.md`):
//! - **Subcommands are verbs** (mutually exclusive modes): `query`, `tables`,
//!   `schema`, `repl`, `mcp`. Each is one `Args` type with an `impl Command`,
//!   registered as one `Commands` variant — adding a command is a struct, an
//!   impl, and one line.
//! - **Flags are modifiers** (compose across commands): the database-opening
//!   options `-c/--config`, `-d/--db`, `-k/--key` are global; output format
//!   (`--json`/`--csv`) is local to the commands that render rows.
//! - Parsing is pure (clap derive); the work happens in [`Commands::run`], which
//!   receives the already-open connection — the shared "open the database" flow
//!   lives once, in `main`, not in each command.

use clap::{Args, Parser, Subcommand};
use rusqlite::Connection;
use signal_core::Result;

use crate::output::{self, BlobFormat, Format};
use crate::{mcp, repl};

/// Query Signal Desktop's database with the automatically recovered key.
///
/// With no subcommand, starts an interactive prompt. Signal is never modified.
#[derive(Parser, Debug)]
#[command(name = "signal-sqlite", version, about, long_about = None)]
pub struct Cli {
    /// Path to Signal's config.json (locates the database and key).
    #[arg(short = 'c', long, global = true, value_name = "PATH")]
    pub config: Option<String>,

    /// Path to db.sqlite (overrides the default location).
    #[arg(short = 'd', long, global = true, value_name = "PATH")]
    pub db: Option<String>,

    /// Use this 64-hex key directly, skipping automatic recovery.
    #[arg(short = 'k', long, global = true, value_name = "HEX")]
    pub key: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

/// The subcommand registry. One variant per mode.
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a single read-only SQL statement.
    Query(QueryArgs),
    /// List the user tables.
    Tables(TablesArgs),
    /// Show CREATE statements (all objects, or just one table).
    Schema(SchemaArgs),
    /// Start an interactive SQL prompt (the default with no subcommand).
    Repl(ReplArgs),
    /// Run as a read-only MCP server over stdio (for AI agents).
    Mcp(McpArgs),
    /// Export the decrypted database to a plaintext SQLite file.
    Export(ExportArgs),
}

impl Commands {
    /// Dispatches to the selected command, which runs against an open database.
    pub fn run(self, conn: &mut Connection) -> Result<()> {
        match self {
            Commands::Query(args) => args.run(conn),
            Commands::Tables(args) => args.run(conn),
            Commands::Schema(args) => args.run(conn),
            Commands::Repl(args) => args.run(conn),
            Commands::Mcp(args) => args.run(conn),
            Commands::Export(args) => args.run(conn),
        }
    }
}

/// A runnable subcommand: given an open connection, do its thing. Thin by
/// design — real work lives in `output` / `repl` / `mcp` / `signal_core`.
trait Command {
    fn run(self, conn: &mut Connection) -> Result<()>;
}

/// Output format shared by the row-rendering commands.
#[derive(Args, Debug, Default)]
pub struct FormatArgs {
    /// Output rows as JSON.
    #[arg(long, conflicts_with = "csv")]
    pub json: bool,
    /// Output rows as CSV.
    #[arg(long)]
    pub csv: bool,
    /// How to render BLOB columns: `summary` (`<N bytes>`, the default) or
    /// `hex` (lossless lowercase hex of the raw bytes).
    #[arg(long, value_enum, default_value_t = BlobFormat::Summary)]
    pub blob: BlobFormat,
}

impl FormatArgs {
    /// Resolves the chosen format (default is the aligned text table).
    fn format(&self) -> Format {
        if self.json {
            Format::Json
        } else if self.csv {
            Format::Csv
        } else {
            Format::Table
        }
    }
}

#[derive(Args, Debug)]
pub struct QueryArgs {
    /// The SQL to run (read-only).
    #[arg(value_name = "SQL")]
    pub sql: String,
    #[command(flatten)]
    pub format: FormatArgs,
}

#[derive(Args, Debug, Default)]
pub struct TablesArgs {
    #[command(flatten)]
    pub format: FormatArgs,
}

#[derive(Args, Debug)]
pub struct SchemaArgs {
    /// Optional table name; omit for the whole schema.
    #[arg(value_name = "TABLE")]
    pub table: Option<String>,
}

#[derive(Args, Debug, Default)]
pub struct ReplArgs {
    #[command(flatten)]
    pub format: FormatArgs,
}

#[derive(Args, Debug, Default)]
pub struct McpArgs {}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Destination path for the decrypted plaintext SQLite file.
    #[arg(value_name = "PATH")]
    pub path: String,
    /// Overwrite the destination if it already exists.
    #[arg(long)]
    pub force: bool,
}

impl Command for QueryArgs {
    fn run(self, conn: &mut Connection) -> Result<()> {
        output::run_query(conn, &self.sql, self.format.format(), self.format.blob)
    }
}

impl Command for TablesArgs {
    fn run(self, conn: &mut Connection) -> Result<()> {
        output::list_tables(conn, self.format.format())
    }
}

impl Command for SchemaArgs {
    fn run(self, conn: &mut Connection) -> Result<()> {
        output::show_schema(conn, self.table.as_deref())
    }
}

impl Command for ReplArgs {
    fn run(self, conn: &mut Connection) -> Result<()> {
        repl::run(conn, self.format.format(), self.format.blob)
    }
}

impl Command for McpArgs {
    fn run(self, conn: &mut Connection) -> Result<()> {
        mcp::serve(conn)
    }
}

impl Command for ExportArgs {
    fn run(self, conn: &mut Connection) -> Result<()> {
        output::export_db(conn, &self.path, self.force)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        let argv = std::iter::once("signal-sqlite").chain(args.iter().copied());
        Cli::try_parse_from(argv).unwrap()
    }

    #[test]
    fn no_subcommand_defaults_to_repl() {
        // `None` is mapped to the REPL by main; here we just confirm the parser
        // accepts a bare invocation.
        assert!(parse(&[]).command.is_none());
    }

    #[test]
    fn query_takes_sql_and_format() {
        let cli = parse(&["query", "SELECT 1"]);
        match cli.command {
            Some(Commands::Query(a)) => {
                assert_eq!(a.sql, "SELECT 1");
                assert_eq!(a.format.format(), Format::Table);
            }
            other => panic!("expected Query, got {other:?}"),
        }
        let cli = parse(&["query", "--json", "SELECT 1"]);
        match cli.command {
            Some(Commands::Query(a)) => assert_eq!(a.format.format(), Format::Json),
            other => panic!("expected Query, got {other:?}"),
        }
    }

    #[test]
    fn blob_flag_defaults_to_summary_and_parses_hex() {
        let cli = parse(&["query", "SELECT 1"]);
        match cli.command {
            Some(Commands::Query(a)) => assert_eq!(a.format.blob, BlobFormat::Summary),
            other => panic!("expected Query, got {other:?}"),
        }
        let cli = parse(&["query", "--blob", "hex", "SELECT 1"]);
        match cli.command {
            Some(Commands::Query(a)) => assert_eq!(a.format.blob, BlobFormat::Hex),
            other => panic!("expected Query, got {other:?}"),
        }
    }

    #[test]
    fn schema_optional_table() {
        match parse(&["schema"]).command {
            Some(Commands::Schema(a)) => assert_eq!(a.table, None),
            other => panic!("expected Schema, got {other:?}"),
        }
        match parse(&["schema", "items"]).command {
            Some(Commands::Schema(a)) => assert_eq!(a.table.as_deref(), Some("items")),
            other => panic!("expected Schema, got {other:?}"),
        }
    }

    #[test]
    fn mcp_and_tables_are_subcommands() {
        assert!(matches!(parse(&["mcp"]).command, Some(Commands::Mcp(_))));
        assert!(matches!(parse(&["tables"]).command, Some(Commands::Tables(_))));
    }

    #[test]
    fn export_takes_path_and_force() {
        match parse(&["export", "/tmp/out.sqlite"]).command {
            Some(Commands::Export(a)) => {
                assert_eq!(a.path, "/tmp/out.sqlite");
                assert!(!a.force, "force defaults off");
            }
            other => panic!("expected Export, got {other:?}"),
        }
        match parse(&["export", "--force", "/tmp/out.sqlite"]).command {
            Some(Commands::Export(a)) => assert!(a.force),
            other => panic!("expected Export, got {other:?}"),
        }
    }

    #[test]
    fn global_options_parse_before_or_after_subcommand() {
        let cli = parse(&["-c", "/c.json", "-d", "/db.sqlite", "tables"]);
        assert_eq!(cli.config.as_deref(), Some("/c.json"));
        assert_eq!(cli.db.as_deref(), Some("/db.sqlite"));
        // `global = true` lets them follow the subcommand too.
        let cli = parse(&["tables", "-k", "00"]);
        assert_eq!(cli.key.as_deref(), Some("00"));
    }

    #[test]
    fn json_and_csv_conflict() {
        let argv = ["signal-sqlite", "query", "--json", "--csv", "SELECT 1"];
        assert!(Cli::try_parse_from(argv).is_err());
    }

    #[test]
    fn legacy_flags_are_gone() {
        // Clean break: the old flag-style modes are no longer accepted.
        for flag in ["--tables", "--schema", "--mcp"] {
            assert!(
                Cli::try_parse_from(["signal-sqlite", flag]).is_err(),
                "{flag} should be rejected"
            );
        }
    }

    #[test]
    fn unknown_subcommand_errors() {
        assert!(Cli::try_parse_from(["signal-sqlite", "frobnicate"]).is_err());
    }

    #[test]
    fn commands_dispatch_against_an_open_connection() {
        // Flow/template test: `main` opens the database once and hands every
        // command the connection. Here an in-memory connection stands in for
        // that shared context, and each row-rendering command is dispatched
        // through `Commands::run` (the registry's match) to confirm the wiring
        // routes each variant to its handler and runs against the injected
        // connection without error. The interactive `Repl` and stdio `Mcp`
        // commands read stdin, so they are covered by the binary-level tests.
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t(id INTEGER, name TEXT); INSERT INTO t VALUES (1, 'a');")
            .unwrap();

        Commands::Query(QueryArgs {
            sql: "SELECT * FROM t".into(),
            format: FormatArgs::default(),
        })
        .run(&mut conn)
        .expect("query dispatch");

        Commands::Tables(TablesArgs::default())
            .run(&mut conn)
            .expect("tables dispatch");

        Commands::Schema(SchemaArgs { table: None })
            .run(&mut conn)
            .expect("schema (all) dispatch");
        Commands::Schema(SchemaArgs {
            table: Some("t".into()),
        })
        .run(&mut conn)
        .expect("schema (one table) dispatch");
    }
}
