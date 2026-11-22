//! `signal-sqlite` — query Signal Desktop's database without handling the key.
//!
//! Recovers the SQLCipher key via [`signal_core`], opens the database (and its
//! WAL) read-only with SQLCipher itself, and runs SQL against it — as a
//! one-shot query or an interactive prompt. Signal is never modified.

mod cli;
mod db;
mod fts;
mod mcp;
mod output;
mod repl;

use clap::Parser;
use cli::{Cli, Commands, ReplArgs};
use signal_core::android_backup::Passphrase;
use signal_core::Result;

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // The shared flow lives here, once: open the database before dispatching.
    // Two sources, same resulting connection — a live SQLCipher database
    // (desktop/iOS/Android) or an Android `.backup` file. Every command runs
    // against the open connection; no command opens its own.
    let passphrase = match (&cli.passphrase, &cli.passphrase_file) {
        (Some(code), _) => Some(Passphrase::parse(code)?),
        (None, Some(file)) => {
            let bytes = std::fs::read(file).map_err(|e| format!("cannot read passphrase file {file}: {e}"))?;
            Some(Passphrase::from_bytes(&bytes).map_err(|e| format!("passphrase file {file}: {e}"))?)
        }
        (None, None) => None,
    };
    // `mcp` speaks JSON-RPC on stdin, so the passphrase prompt (which reads
    // stdin) would swallow the client's first message. Require the flag.
    if cli.backup.is_some() && passphrase.is_none() && matches!(cli.command, Some(Commands::Mcp(_))) {
        return Err("--backup with mcp needs --passphrase-file (or --passphrase): stdin carries the MCP protocol, so the passphrase cannot be prompted for there".into());
    }
    let mut database = match cli.backup.as_deref() {
        Some(backup) => db::open_backup(backup, passphrase)?,
        None => db::open(
            cli.config.as_deref(),
            cli.db.as_deref(),
            cli.key.as_deref(),
            cli.cipher,
        )?,
    };

    // No subcommand drops into the interactive prompt (like `sqlite3`).
    let command = cli.command.unwrap_or_else(|| Commands::Repl(ReplArgs::default()));
    command.run(&mut database.conn)
}
