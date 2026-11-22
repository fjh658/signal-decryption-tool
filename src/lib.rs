//! `signal_core` — recover Signal Desktop's SQLCipher database key.
//!
//! Signal (an Electron app) stores its SQLCipher key encrypted with Chromium's
//! `os_crypt` scheme, which differs per OS. This library is the shared core used
//! by both binaries (`SignalDecryption` and `signal-sqlite`); the layering is:
//!
//! - [`config`]       reads the `encryptedKey` field from Signal's `config.json`.
//! - [`decryptor`]    defines the [`Decryptor`] strategy contract (the port).
//! - [`oscrypt_cbc`]  shared PBKDF2 + AES-128-CBC primitive (macOS + Linux).
//! - [`platform`]     the per-OS backends (adapters), one implementing the
//!   contract, selected per target in `platform/mod.rs`.
//!
//! The one-call entry point is [`recover_key`].
//!
//! References:
//! - <https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_mac.mm>
//! - <https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_win.cc>
//! - <https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_linux.cc>

pub mod config;
pub mod error;
pub mod decryptor;

// Shared Chromium os_crypt CBC primitive (PBKDF2 + AES-128-CBC), used by the
// macOS and Linux backends, which differ only in iteration count, password
// source and accepted version prefixes.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod oscrypt_cbc;

pub mod platform;

// Long-path-safe paths for the few raw Win32 calls.
pub mod winpath;

pub use decryptor::Decryptor;

/// Crate-wide result type. A boxed error is enough here: errors are only ever
/// printed, never matched on by callers.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Recovers the plaintext SQLCipher key end to end: reads `encryptedKey` from
/// the Signal config (the platform default when `config_path` is `None`) and
/// decrypts it with the platform backend.
/// A plaintext `key` in the config is returned as is, without the OS key store
/// (see [`config::KeySource`]).
///
/// This is what `signal-sqlite` uses so the user never handles the key.
pub fn recover_key(config_path: Option<&str>) -> Result<String> {
    let path = match config_path {
        Some(path) => path.to_string(),
        None => platform::default_config_path()?,
    };
    match config::read_key_source(&path)? {
        config::KeySource::Plaintext(key) => Ok(key),
        config::KeySource::Encrypted(encrypted_key) => platform::build(&path)?.decrypt(&encrypted_key),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn recover_key_returns_a_plaintext_key_without_the_os_store() {
        let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let path = std::env::temp_dir().join(format!("signal_recover_plain_{}.json", std::process::id()));
        std::fs::write(&path, format!(r#"{{"key":"{key}"}}"#)).unwrap();
        let recovered = super::recover_key(path.to_str());
        std::fs::remove_file(&path).ok();
        assert_eq!(recovered.unwrap(), key);
    }
}
