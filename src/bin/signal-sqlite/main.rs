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
use signal_core::Result;

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    // The shared flow lives here, once: open the database (recovering the key
    // and decrypting) before dispatching. Every command runs against the open
    // connection; no command opens its own.
    let mut database = db::open(
        cli.config.as_deref(),
        cli.db.as_deref(),
        cli.key.as_deref(),
        cli.cipher,
    )?;

    // No subcommand drops into the interactive prompt (like `sqlite3`).
    let command = cli.command.unwrap_or_else(|| Commands::Repl(ReplArgs::default()));
    command.run(&mut database.conn)
}
