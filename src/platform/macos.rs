//! macOS backend for Signal key decryption.
//!
//! Scheme (Chromium os_crypt, macOS variant):
//!   master password := Keychain item ("Signal Safe Storage", account "Signal Key"|"Signal")
//!   aes_key         := PBKDF2-HMAC-SHA1(password, salt="saltysalt", iters=1003, dkLen=16)
//!   plaintext       := AES-128-CBC-PKCS7(aes_key, iv=16*' ')  over  config.json.encryptedKey[3..]
//! where the stored key is hex-encoded and prefixed with the ASCII tag "v10".
//!
//! The PBKDF2 + CBC primitive is shared with the Linux backend ([`oscrypt_cbc`]);
//! only the iteration count, the password source and the version prefix differ.

use keyring::Entry;

use crate::decryptor::Decryptor;
use crate::{oscrypt_cbc, Result};

/// PBKDF2 iteration count on macOS.
const ITERATIONS: u32 = 1003;
/// Only the "v10" version tag is used on macOS.
const VERSION_PREFIX: &str = "v10";
/// Keychain service that holds the "Safe Storage" password.
const KEYCHAIN_SERVICE: &str = "Signal Safe Storage";
/// Keychain accounts to try, in order.
const KEYCHAIN_ACCOUNTS: [&str; 2] = ["Signal Key", "Signal"];

/// Decryptor holding the Keychain password and the AES key derived from it.
pub struct MacDecryptor {
    password: String,
    aes_key: [u8; oscrypt_cbc::KEY_LENGTH],
}

impl Decryptor for MacDecryptor {
    fn decrypt(&self, encrypted_hex: &str) -> Result<String> {
        let (_prefix, plaintext) =
            oscrypt_cbc::decrypt(&self.aes_key, encrypted_hex, &[VERSION_PREFIX])?;
        Ok(plaintext)
    }

    fn secret_material(&self) -> Result<String> {
        Ok(self.password.clone())
    }
}

/// Returns the default `config.json` location for Signal on macOS.
pub fn default_config_path() -> Result<String> {
    let home = std::env::var("HOME")?;
    Ok(format!("{home}/Library/Application Support/Signal/config.json"))
}

/// Builds a macOS decryptor from the Keychain "Safe Storage" password.
///
/// `config_path` is unused on macOS (the key material comes entirely from the
/// Keychain) but kept for a uniform backend signature.
pub fn build(_config_path: &str) -> Result<impl Decryptor> {
    let password = keychain_password()?;
    let aes_key = oscrypt_cbc::derive_key(&password, ITERATIONS);
    Ok(MacDecryptor { password, aes_key })
}

/// Reads the "Safe Storage" password, trying each known Keychain account.
fn keychain_password() -> Result<String> {
    let mut last_err: Option<Box<dyn std::error::Error>> = None;
    for account in KEYCHAIN_ACCOUNTS {
        match Entry::new(KEYCHAIN_SERVICE, account).get_password() {
            Ok(password) => return Ok(password),
            Err(err) => last_err = Some(err.into()),
        }
    }
    Err(last_err.unwrap_or_else(|| "No Keychain accounts configured".into()))
}
