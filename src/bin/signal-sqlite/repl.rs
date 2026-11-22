//! Interactive prompt: read SQL (terminated by `;`) and dot-commands, run them,
//! and keep going on errors.

use std::io::{self, BufRead, Write};

use rusqlite::Connection;
use signal_core::Result;

use crate::output::{BlobFormat, Format};
use crate::output;

const PROMPT: &str = "signal-sqlite> ";
const CONTINUATION: &str = "         ...> ";

/// Runs the interactive loop until EOF or `.quit`.
pub fn run(conn: &Connection, format: Format, blob: BlobFormat) -> Result<()> {
    println!("signal-sqlite — interactive mode. Type .help for commands, .quit to exit.");
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut buffer = String::new();

    loop {
        print!("{}", if buffer.is_empty() { PROMPT } else { CONTINUATION });
        io::stdout().flush()?;

        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            println!();
            break; // EOF (Ctrl-D)
        }

        // Dot-commands are only recognized at the start of a statement.
        if buffer.is_empty() {
            let trimmed = line.trim();
            match trimmed {
                "" => continue,
                ".quit" | ".exit" => break,
                ".help" => {
                    print_help();
                    continue;
                }
                ".tables" => {
                    report(output::list_tables(conn, format));
                    continue;
                }
                cmd if cmd.starts_with(".schema") => {
                    let table = cmd[".schema".len()..].trim();
                    report(output::show_schema(conn, (!table.is_empty()).then_some(table)));
                    continue;
                }
                cmd if cmd.starts_with('.') => {
                    eprintln!("Unknown command: {cmd} (.help for the command list)");
                    continue;
                }
                _ => {}
            }
        }

        buffer.push_str(&line);
        if buffer.trim_end().ends_with(';') {
            let sql = buffer.trim().trim_end_matches(';').trim();
            if !sql.is_empty() {
                report(output::run_query(conn, sql, format, blob));
            }
            buffer.clear();
        }
    }
    Ok(())
}

/// Prints an error without leaving the loop.
fn report(result: Result<()>) {
    if let Err(err) = result {
        eprintln!("Error: {err}");
    }
}

fn print_help() {
    println!("Commands:");
    println!("  .tables          list tables");
    println!("  .schema [TABLE]  show the schema (all, or one table)");
    println!("  .help            this help");
    println!("  .quit / .exit    leave");
    println!("Anything else is run as SQL (terminate statements with ';').");
}
