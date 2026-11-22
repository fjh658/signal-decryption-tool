//! `SignalDecryption` — print Signal Desktop's decrypted SQLCipher key.
//!
//! Thin CLI over [`signal_core`]: it parses arguments, resolves the config,
//! and prints the recovered key (and, with `-p`, the underlying key material).

mod cli;

use cli::{Command, Options};
use signal_core::config::{self, KeySource};
use signal_core::{platform, Decryptor, Result};

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

/// Parses the command line and dispatches to the matching action.
fn run() -> Result<()> {
    match Command::parse(std::env::args())? {
        Command::Help => {
            print!("{}", cli::HELP);
            Ok(())
        }
        Command::Version => {
            println!("{}", version_line());
            Ok(())
        }
        Command::Decrypt(options) => decrypt(options),
    }
}

/// Resolves the config, builds the platform decryptor, and prints the key.
fn decrypt(options: Options) -> Result<()> {
    // On Windows/Linux the config's directory is also where the backend finds
    // its sibling state (`Local State` on Windows), so resolve it even when the
    // encrypted key is supplied directly via `-k`.
    let config_path = match options.config_path {
        Some(path) => path,
        None => platform::default_config_path()?,
    };

    let source = match options.encrypted_key {
        Some(key) => KeySource::Encrypted(key),
        None => config::read_key_source(&config_path)?,
    };
    let encrypted_key = match source {
        KeySource::Encrypted(hex) => hex,
        // Nothing to decrypt, so no OS key store is involved.
        KeySource::Plaintext(key) => {
            if options.print_key {
                println!("Secure material: none (config.json keeps the key in plaintext)");
            }
            println!("Decrypted key: {key}");
            return Ok(());
        }
    };

    // The decryptor owns the platform key material (Keychain / DPAPI / keyring).
    let decryptor = platform::build(&config_path)?;

    if options.print_key {
        println!("Secure material: {}", decryptor.secret_material()?);
    }
    println!("Decrypted key: {}", decryptor.decrypt(&encrypted_key)?);
    Ok(())
}

/// Builds the `--version` line, taking the version from the crate metadata so it
/// never drifts from `Cargo.toml`.
fn version_line() -> String {
    let os = if cfg!(windows) {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "unsupported"
    };
    format!("SignalDecryption {} ({os})", env!("CARGO_PKG_VERSION"))
}
