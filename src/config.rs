//! Reading Signal's `config.json`.
//!
//! The only field this tool needs from the cross-platform config is the key:
//! the hex-encoded `encryptedKey`, or a plaintext `key` (see [`KeySource`],
//! which follows Signal's own `getSQLKey()`). Platform-specific state (Windows
//! `Local State`, Linux `safeStorageBackend`) is read by the respective
//! `platform_*` backend.

use serde_json::Value;
use std::fs;

use crate::error::Error;

/// Where Signal's SQLCipher key comes from, decided exactly as Signal Desktop's
/// `getSQLKey()` (app/main.main.ts) decides it.
pub enum KeySource {
    /// `key`: the key itself. Written by the Linux `basic_text` store and by
    /// older versions, and kept beside `encryptedKey` on Flatpak. When present
    /// Signal opens the database with it: either it equals the decrypted key,
    /// or Signal falls back to it after a decryption mismatch.
    Plaintext(String),
    /// `encryptedKey`: hex, encrypted by the OS key store (Keychain, DPAPI, or
    /// the Secret Service).
    Encrypted(String),
}

const CONFIG_HINT: &str =
    "start Signal Desktop once (it writes config.json and its key on first launch), or pass the right path with -c";
const KEY_HEX_LEN: usize = 64;

/// Reads where the key comes from in a Signal `config.json`: a plaintext `key`
/// (Linux `basic_text`, older versions, Flatpak), which takes precedence as in
/// Signal, or the hex-encoded `encryptedKey`.
///
/// # Errors
///
/// Typed errors that never contain key material: the file is missing (Signal
/// was never started) or unreadable, is not valid JSON, has a malformed `key`,
/// or has neither field.
pub fn read_key_source(path: &str) -> Result<KeySource, Error> {
    let invalid = |reason: &str| Error::Invalid { path: path.into(), reason: reason.into() };
    let contents = fs::read_to_string(path).map_err(|e| Error::from_io(e, "Signal config", path, CONFIG_HINT))?;
    let config: Value = serde_json::from_str(&contents).map_err(|e| invalid(&format!("not valid JSON ({e})")))?;
    if let Some(key) = config["key"].as_str() {
        if key.len() != KEY_HEX_LEN || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("`key` is not a 64-digit hex key"));
        }
        return Ok(KeySource::Plaintext(key.to_owned()));
    }
    match config["encryptedKey"].as_str() {
        Some(hex) => Ok(KeySource::Encrypted(hex.to_owned())),
        None => Err(invalid("has neither `encryptedKey` nor `key`; start Signal Desktop once so it writes its key")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn config(name: &str, json: &str) -> String {
        let path = std::env::temp_dir().join(format!("signal_config_{name}_{}.json", std::process::id()));
        std::fs::write(&path, json).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn source(name: &str, json: &str) -> std::result::Result<KeySource, Error> {
        let path = config(name, json);
        let result = read_key_source(&path);
        std::fs::remove_file(&path).ok();
        result
    }

    #[test]
    fn plaintext_key_is_used_as_is() {
        // Linux with the basic_text store: Signal never writes encryptedKey.
        assert!(matches!(source("plain", &format!(r#"{{"key":"{KEY}"}}"#)), Ok(KeySource::Plaintext(k)) if k == KEY));
    }

    #[test]
    fn legacy_key_wins_when_both_are_present() {
        // getSQLKey(): with both fields Signal ends up on the legacy key (equal
        // after a round trip, or chosen after a decryption mismatch).
        let json = format!(r#"{{"key":"{KEY}","encryptedKey":"763130deadbeef"}}"#);
        assert!(matches!(source("both", &json), Ok(KeySource::Plaintext(k)) if k == KEY));
    }

    #[test]
    fn encrypted_key_needs_the_os_store() {
        let json = r#"{"encryptedKey":"763130deadbeef","safeStorageBackend":"gnome_libsecret"}"#;
        assert!(matches!(source("enc", json), Ok(KeySource::Encrypted(hex)) if hex == "763130deadbeef"));
    }

    #[test]
    fn missing_config_says_signal_was_never_started() {
        let err = read_key_source("/nonexistent/Signal/config.json").err().expect("must fail");
        assert!(matches!(err, Error::Missing { .. }), "{err:?}");
        assert!(err.to_string().contains("/nonexistent/Signal/config.json") && err.to_string().contains("start Signal"), "{err}");
    }

    #[test]
    fn config_without_any_key_is_invalid() {
        let err = source("none", r#"{"mediaPermissions":true}"#).err().expect("must fail");
        assert!(matches!(err, Error::Invalid { .. }), "{err:?}");
        assert!(err.to_string().contains("start Signal"), "{err}");
    }

    #[test]
    fn malformed_plaintext_key_is_invalid_and_not_echoed() {
        let err = source("bad", r#"{"key":"not-a-key-zzzz"}"#).err().expect("must fail");
        assert!(matches!(err, Error::Invalid { .. }), "{err:?}");
        assert!(!err.to_string().contains("not-a-key-zzzz"), "a key must never be printed: {err}");
    }
}
