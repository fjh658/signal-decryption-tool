# vendor/

## libsqlite3-sys 0.40.0

Copied from the crates.io package `libsqlite3-sys-0.40.0.crate`
(SHA-256 `b06e69070b7e12262b0cd90832f0a7396f142a2b330181255562decf9f0c6215`,
rusqlite commit `812d63147ebea21c9c3de4db9e556f2e4e9f8161`), used through
`[patch.crates-io]` in the top-level `Cargo.toml`. Changes from the package:

- `Cargo.toml`: feature `bundled-sqlcipher-custom-crypto` and the optional
  dependency `sqlcipher-rustcrypto` (path `../../crates/sqlcipher-rustcrypto`).
- `build.rs`: with that feature, SQLCipher is compiled with
  `-DSQLCIPHER_CRYPTO_CUSTOM=sqlcipher_custom_crypto_setup` and the OpenSSL /
  CommonCrypto detection is skipped.
- `src/lib.rs`: `extern crate sqlcipher_rustcrypto;` under that feature, so
  every binary that links SQLCipher also links its crypto provider (as the
  package already does for `openssl-sys`).
- `sqlite3/sqlite3.c` removed (9.6 MB): it is the plain SQLite amalgamation,
  unused here because `bundled-sqlcipher` compiles the sources of the
  `sqlcipher-src` crate.

To upgrade, unpack the new package over this directory, delete
`sqlite3/sqlite3.c` again and reapply the three edits (search for
`custom-crypto` / `custom_crypto` / `sqlcipher_rustcrypto`).
