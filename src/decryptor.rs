//! The decryption strategy contract.

use crate::Result;

/// A platform-specific strategy for recovering Signal's database key.
///
/// Each OS backend (`platform_macos`, `platform_linux`, `platform_windows`)
/// provides a type implementing this trait via its `build()` constructor.
///
/// Dispatch is **static**: exactly one backend is compiled per target and
/// `platform::build` returns `impl Decryptor`, so every call is monomorphized
/// with no `dyn`/vtable indirection. The trait is here to name and enforce the
/// contract — the Strategy pattern — not to provide runtime polymorphism.
pub trait Decryptor {
    /// Decrypts the hex-encoded `encryptedKey` into the plaintext SQLCipher key.
    fn decrypt(&self, encrypted_hex: &str) -> Result<String>;

    /// Returns the underlying key material, for the `-p` flag: the Keychain
    /// "Safe Storage" password on macOS, the DPAPI master key (hex) on Windows,
    /// and the keyring / `peanuts` password on Linux.
    fn secret_material(&self) -> Result<String>;
}
