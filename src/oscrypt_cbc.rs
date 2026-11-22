// Shared Chromium os_crypt CBC primitive, used by the macOS and Linux backends.
//
// Both platforms derive the AES key with PBKDF2-HMAC-SHA1 over the fixed salt
// "saltysalt" and decrypt with AES-128-CBC/PKCS7 under a fixed IV of 16 space
// bytes (0x20). They differ only in:
//   - the PBKDF2 iteration count: macOS = 1003, Linux = 1
//   - the password source: Keychain (macOS); "peanuts"/Secret Service (Linux)
//   - the accepted version prefixes: "v10" (macOS); "v10"/"v11" (Linux)
//
// References:
// - macOS:  https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_mac.mm
// - Linux:  https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_linux.cc
// - POSIX:  https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_posix.cc

use aes::Aes128; // AES-128 block cipher
use block_modes::block_padding::Pkcs7; // PKCS7 padding
use block_modes::{BlockMode, Cbc}; // CBC block mode
use hex::decode; // hex decode (encode is used only by the test-only `encrypt`)
use hmac::Hmac; // HMAC for PBKDF2
use pbkdf2::pbkdf2; // PBKDF2 key derivation
use sha1::Sha1; // SHA-1 (PBKDF2 PRF)

use crate::Result;

/// Type alias for AES-128 CBC mode with PKCS7 padding.
type Aes128Cbc = Cbc<Aes128, Pkcs7>;

/// Salt used for PBKDF2 key derivation (shared across all Chromium platforms).
const SALT: &[u8] = b"saltysalt";
/// Length of the derived AES key (AES-128).
pub const KEY_LENGTH: usize = 16;
/// Fixed IV: 16 space characters, per the Chromium os_crypt CBC logic.
const IV: [u8; KEY_LENGTH] = [b' '; KEY_LENGTH];

/// Derives an AES-128 key from a password via PBKDF2-HMAC-SHA1.
///
/// # Arguments
///
/// * `password` - The password (Keychain secret, "peanuts", or keyring secret).
/// * `iterations` - PBKDF2 iteration count (macOS = 1003, Linux = 1).
///
/// # Returns
///
/// The derived 16-byte AES key.
pub fn derive_key(password: &str, iterations: u32) -> [u8; KEY_LENGTH] {
    let mut key = [0u8; KEY_LENGTH];
    pbkdf2::<Hmac<Sha1>>(password.as_bytes(), SALT, iterations, &mut key);
    key
}

/// Decrypts a hex-encoded os_crypt value whose leading version tag is one of
/// `prefixes`, using the fixed space-filled IV.
///
/// # Arguments
///
/// * `aes_key` - The derived AES-128 key.
/// * `encrypted_hex` - The hex-encoded `encryptedKey` from `config.json`.
/// * `prefixes` - Accepted version tags, e.g. `&["v10"]` or `&["v10", "v11"]`.
///
/// # Returns
///
/// A tuple of (matched version prefix, decrypted UTF-8 plaintext).
pub fn decrypt(
    aes_key: &[u8; KEY_LENGTH],
    encrypted_hex: &str,
    prefixes: &[&str],
) -> Result<(String, String)> {
    let data = decode(encrypted_hex)?;
    let matched = prefixes
        .iter()
        .find(|p| data.starts_with(p.as_bytes()))
        .ok_or("Invalid or unsupported encryption version prefix")?;
    let body = &data[matched.len()..];
    let cipher = Aes128Cbc::new_from_slices(aes_key, &IV)?;
    let decrypted = cipher.decrypt_vec(body)?;
    Ok((matched.to_string(), String::from_utf8(decrypted)?))
}

/// Encrypts a plaintext string with the fixed space-filled IV and prepends the
/// given version prefix, returning a hex-encoded string.
///
/// Mirrors the Chromium os_crypt CBC encryption (used by the macOS backend for
/// parity and by the test vectors).
///
/// # Arguments
///
/// * `aes_key` - The derived AES-128 key.
/// * `plaintext` - The plaintext to encrypt.
/// * `prefix` - The version tag to prepend (e.g. "v10").
///
/// # Returns
///
/// The hex-encoded `prefix || AES-128-CBC(plaintext)`.
#[cfg(test)] // the inverse of `decrypt`, used only to build test vectors
pub fn encrypt(aes_key: &[u8; KEY_LENGTH], plaintext: &str, prefix: &str) -> Result<String> {
    let cipher = Aes128Cbc::new_from_slices(aes_key, &IV)?;
    let encrypted_data = cipher.encrypt_vec(plaintext.as_bytes());
    let mut result = prefix.as_bytes().to_vec();
    result.extend_from_slice(&encrypted_data);
    Ok(hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Round-trips the Linux "basic" path: password "peanuts", 1 iteration,
    // "v10" prefix. Proves the shared KDF+CBC primitive end to end without any
    // keyring. (Chromium's own unit tests use "not_peanuts" similarly.)
    #[test]
    fn roundtrip_v10_peanuts_one_iteration() {
        let key = derive_key("peanuts", 1);
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let enc = encrypt(&key, secret, "v10").unwrap();
        let (prefix, dec) = decrypt(&key, &enc, &["v10", "v11"]).unwrap();
        assert_eq!(prefix, "v10");
        assert_eq!(dec, secret);
    }

    // A wrong password must not authenticate to the same plaintext. CBC has no
    // MAC, so a wrong key yields either a padding error or garbage bytes; both
    // are acceptable "not equal" outcomes.
    #[test]
    fn wrong_password_does_not_recover_plaintext() {
        let good = derive_key("peanuts", 1);
        let bad = derive_key("not_peanuts", 1);
        let secret = "hello-signal";
        let enc = encrypt(&good, secret, "v10").unwrap();
        if let Ok((_, dec)) = decrypt(&bad, &enc, &["v10"]) {
            assert_ne!(dec, secret);
        }
        // an Err (padding/utf8 failure) is also a correct rejection
    }

    // macOS uses 1003 iterations; make sure the iteration count actually feeds
    // the derivation (different iters => different key => different ciphertext).
    #[test]
    fn iteration_count_changes_key() {
        assert_ne!(derive_key("peanuts", 1), derive_key("peanuts", 1003));
    }
}
