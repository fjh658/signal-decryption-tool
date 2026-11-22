//! Linux backend for Signal key decryption.
//!
//! Scheme (Chromium os_crypt, Linux variant):
//!   password := "peanuts"                 (v10, "basic_text" fallback store)
//!            or Secret Service secret      (v11, gnome-libsecret / kwallet-via-bridge)
//!   aes_key  := PBKDF2-HMAC-SHA1(password, salt="saltysalt", iters=1, dkLen=16)
//!   plaintext:= AES-128-CBC-PKCS7(aes_key, iv=16*' ')  over  config.json.encryptedKey[3..]
//!
//! The `encryptedKey` is hex-encoded and prefixed with "v10" or "v11". Signal
//! records the store it used in `config.json`'s `safeStorageBackend` field,
//! which we read as a hint; the actual routing is driven by the key's prefix.
//!
//! For v11, Chromium/Electron store the password in the Secret Service under the
//! attribute `application` = the app name ("Signal"). This needs a running D-Bus
//! session and an unlocked keyring, so it must run inside the desktop session.
//! KWallet without the `org.freedesktop.secrets` bridge is not reachable.
//!
//! Reference: <https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_linux.cc>

use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use secret_service::blocking::SecretService;
use secret_service::EncryptionType;

use crate::decryptor::Decryptor;
use crate::{oscrypt_cbc, Result};

/// PBKDF2 iteration count on Linux (vs 1003 on macOS).
const ITERATIONS: u32 = 1;
/// Hardcoded password for the v10 "basic" store.
const BASIC_PASSWORD: &str = "peanuts";
/// Secret Service `application` attribute value Signal stores its password under.
const KEYRING_APP: &str = "Signal";
/// Accepted version tags.
const VERSION_PREFIXES: [&str; 2] = ["v10", "v11"];

/// The Safe Storage backend Signal recorded in `config.json` (a routing hint).
enum Backend {
    /// `basic_text` → v10 / "peanuts".
    BasicText,
    /// `gnome_libsecret` | `kwallet*` → v11 / Secret Service.
    Keyring,
    /// Field absent (older Signal) → decide by the key's prefix.
    Unknown,
}

/// Decryptor that resolves the password from the key's version prefix (`v10`
/// uses "peanuts"; `v11` queries the Secret Service).
pub struct LinuxDecryptor {
    backend: Backend,
    app: String,
}

impl Decryptor for LinuxDecryptor {
    fn decrypt(&self, encrypted_hex: &str) -> Result<String> {
        let is_v11 = hex::decode(encrypted_hex)?.starts_with(b"v11");
        let password = self.password_for(is_v11)?;
        let aes_key = oscrypt_cbc::derive_key(&password, ITERATIONS);
        let (_prefix, plaintext) =
            oscrypt_cbc::decrypt(&aes_key, encrypted_hex, &VERSION_PREFIXES)?;
        Ok(plaintext)
    }

    fn secret_material(&self) -> Result<String> {
        // Resolve from the backend hint; `Unknown` prefers the keyring and falls
        // back to the basic password.
        match self.backend {
            Backend::BasicText => Ok(BASIC_PASSWORD.to_string()),
            Backend::Keyring => keyring_password(&self.app),
            Backend::Unknown => Ok(keyring_password(&self.app)
                .unwrap_or_else(|_| BASIC_PASSWORD.to_string())),
        }
    }
}

impl LinuxDecryptor {
    /// Resolves the os_crypt password for a given key version.
    fn password_for(&self, is_v11: bool) -> Result<String> {
        if is_v11 {
            keyring_password(&self.app)
        } else {
            Ok(BASIC_PASSWORD.to_string())
        }
    }
}

/// Returns the default `config.json` location for Signal on Linux
/// (honoring `XDG_CONFIG_HOME`, falling back to `~/.config`).
pub fn default_config_path() -> Result<String> {
    let base = match std::env::var("XDG_CONFIG_HOME") {
        Ok(dir) if !dir.is_empty() => dir,
        _ => format!("{}/.config", std::env::var("HOME")?),
    };
    Ok(format!("{base}/Signal/config.json"))
}

/// Builds a Linux decryptor, reading the backend hint from `config.json`.
pub fn build(config_path: &str) -> Result<impl Decryptor> {
    Ok(LinuxDecryptor {
        backend: read_backend(config_path),
        app: KEYRING_APP.to_string(),
    })
}

/// Looks up Signal's os_crypt password in the Secret Service by the
/// `application` attribute.
fn keyring_password(app: &str) -> Result<String> {
    let service = SecretService::connect(EncryptionType::Dh)?;
    let attributes = HashMap::from([("application", app)]);

    let found = service.search_items(attributes)?;
    let item = found
        .unlocked
        .into_iter()
        .next()
        .or_else(|| found.locked.into_iter().next())
        .ok_or_else(|| format!("no Secret Service item with application={app}"))?;

    item.unlock()?;
    Ok(String::from_utf8(item.get_secret()?)?)
}

/// Reads Signal's `safeStorageBackend` field from `config.json` (a routing hint,
/// not required: any read/parse failure maps to [`Backend::Unknown`]).
fn read_backend(config_path: &str) -> Backend {
    let Ok(contents) = fs::read_to_string(Path::new(config_path)) else {
        return Backend::Unknown;
    };
    let Ok(config) = serde_json::from_str::<Value>(&contents) else {
        return Backend::Unknown;
    };
    match config["safeStorageBackend"].as_str() {
        Some("basic_text") => Backend::BasicText,
        Some(_) => Backend::Keyring, // gnome_libsecret / kwallet* / other keyring
        None => Backend::Unknown,
    }
}
