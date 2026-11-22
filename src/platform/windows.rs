//! Windows backend for Signal key decryption.
//!
//! Scheme (Chromium os_crypt, Windows variant):
//!   1. `Local State` → `os_crypt.encrypted_key` is base64. Decoded it is
//!      "DPAPI" || DPAPI_blob. `CryptUnprotectData` (user scope) yields the
//!      32-byte AES-256 master key directly (no PBKDF2 on Windows).
//!   2. `config.json` → `encryptedKey` is hex. Decoded it is
//!      "v10" || nonce(12) || ciphertext || tag(16), decrypted with
//!      AES-256-GCM under the master key from step 1.
//!
//! DPAPI user-scope keys are bound to the logged-in user, so this must run as
//! the same Windows user that owns the Signal profile.
//!
//! Reference: <https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_win.cc>

use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::Value;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

use crate::decryptor::Decryptor;
use crate::error::Error;
use crate::Result;

const VERSION_PREFIX: &[u8] = b"v10"; // config.json encryptedKey tag
const DPAPI_PREFIX: &[u8] = b"DPAPI"; // Local State encrypted_key tag
const MASTER_KEY_LEN: usize = 32; // AES-256 key length
const NONCE_LEN: usize = 12; // GCM nonce length
const TAG_LEN: usize = 16; // GCM authentication tag length
const LOCAL_STATE_FILE: &str = "Local State"; // sibling of config.json
const LOCAL_STATE_HINT: &str = "start Signal Desktop once (it writes Local State next to config.json), or pass the right path with -c";

/// Decryptor holding the DPAPI-decrypted AES-256 master key.
pub struct WinDecryptor {
    master_key: Vec<u8>,
}

impl Decryptor for WinDecryptor {
    fn decrypt(&self, encrypted_hex: &str) -> Result<String> {
        let data = hex::decode(encrypted_hex)?;
        if !data.starts_with(VERSION_PREFIX) {
            return Err("Invalid encryption version prefix".into());
        }
        let body = &data[VERSION_PREFIX.len()..];
        if body.len() < NONCE_LEN + TAG_LEN {
            return Err("Ciphertext too short for AES-256-GCM".into());
        }

        // Layout: nonce(12) || ciphertext || tag(16). aes-gcm expects the tag
        // appended to the ciphertext, which `ct_and_tag` already is.
        let (nonce_bytes, ct_and_tag) = body.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.master_key));
        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ct_and_tag)
            .map_err(|_| "AES-256-GCM decryption/authentication failed")?;
        Ok(String::from_utf8(plaintext)?)
    }

    fn secret_material(&self) -> Result<String> {
        Ok(hex::encode(&self.master_key))
    }
}

/// Returns the default `config.json` location for Signal on Windows.
pub fn default_config_path() -> Result<String> {
    let appdata = std::env::var("APPDATA")?; // e.g. C:\Users\<user>\AppData\Roaming
    Ok(format!("{appdata}\\Signal\\config.json"))
}

/// Builds a Windows decryptor from the DPAPI master key in the sibling
/// `Local State` file (in the same directory as the resolved config path).
pub fn build(config_path: &str) -> Result<impl Decryptor> {
    let dir = Path::new(config_path)
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let master_key = master_key_from_local_state(&dir.join(LOCAL_STATE_FILE))?;
    Ok(WinDecryptor { master_key })
}

/// Reads and DPAPI-decrypts the AES-256 master key from a `Local State` file.
fn master_key_from_local_state(local_state_path: &Path) -> Result<Vec<u8>> {
    let contents = std::fs::read_to_string(local_state_path)
        .map_err(|e| Error::from_io(e, "Signal's Local State", local_state_path, LOCAL_STATE_HINT))?;
    let config: Value = serde_json::from_str(&contents)
        .map_err(|e| Error::Invalid { path: local_state_path.into(), reason: format!("not valid JSON ({e})") })?;
    let b64 = config["os_crypt"]["encrypted_key"]
        .as_str()
        .ok_or("Missing os_crypt.encrypted_key in Local State")?;

    let raw = BASE64.decode(b64)?;
    if !raw.starts_with(DPAPI_PREFIX) {
        return Err("Local State key is missing the 'DPAPI' prefix".into());
    }

    let key = dpapi_decrypt(&raw[DPAPI_PREFIX.len()..])?;
    if key.len() != MASTER_KEY_LEN {
        return Err(format!(
            "Unexpected master key length: got {}, expected {MASTER_KEY_LEN}",
            key.len()
        )
        .into());
    }
    Ok(key)
}

/// Decrypts a DPAPI blob (user scope) via `CryptUnprotectData`.
fn dpapi_decrypt(data: &[u8]) -> Result<Vec<u8>> {
    // SAFETY: we pass a valid input blob and a zeroed output blob. On success
    // Windows allocates `out_blob.pbData` with LocalAlloc; we copy out of it and
    // free it with LocalFree.
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: null_mut(),
        };

        // Flag 1 = CRYPTPROTECT_UI_FORBIDDEN: never prompt (this runs headless).
        let ok = CryptUnprotectData(
            &in_blob,
            null_mut(), // ppszDataDescr
            null(),     // pOptionalEntropy
            null(),     // pvReserved
            null(),     // pPromptStruct
            1,          // dwFlags
            &mut out_blob,
        );
        if ok == 0 {
            return Err(
                "CryptUnprotectData failed (run as the Windows user that owns the Signal profile)"
                    .into(),
            );
        }

        let out = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        LocalFree(out_blob.pbData as _);
        Ok(out)
    }
}
