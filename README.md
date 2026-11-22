# Signal Decryption Tool for macOS 🔐

English | [中文](README_zh.md)

## Overview 🌟

`SignalDecryption` is a Rust command-line tool for **macOS, Windows and Linux** that recovers Signal Desktop's SQLCipher database key from its encrypted configuration. It implements Chromium's `os_crypt` scheme, which differs per platform:

- **macOS**: the "Safe Storage" password is read from the Keychain, run through PBKDF2-HMAC-SHA1 (1003 iterations), and used to AES-128-CBC-decrypt `config.json`'s `encryptedKey` (prefix `v10`).
- **Windows**: the master key is read from `Local State` (`os_crypt.encrypted_key`), unwrapped via **DPAPI** (`CryptUnprotectData`, user scope), and used to AES-256-GCM-decrypt `config.json`'s `encryptedKey` (prefix `v10`). Because DPAPI user-scope keys are bound to the logged-in user, the tool must run **as the Windows user that owns the Signal profile**.
- **Linux**: the password is either the hardcoded `"peanuts"` (prefix `v10`, the `basic_text` fallback store) or read from the **Secret Service** (prefix `v11`, `gnome_libsecret` — attribute `application=Signal`), then run through PBKDF2-HMAC-SHA1 (**1 iteration**) and used to AES-128-CBC-decrypt `encryptedKey`. v11 requires a running D-Bus session with an unlocked keyring, so the tool must run **inside the user's desktop session**.

## Features ✨

- 🔓 Recover Signal's SQLCipher key on macOS (Keychain), Windows (DPAPI) and Linux (Secret Service)
- 📁 Support for custom configuration file paths
- 🔑 Option to directly input encrypted keys
- 🛡️ Secure handling of sensitive information
- 💻 Command-line interface for easy integration into scripts or manual use
- 🍎 Universal binary support for both Intel and Apple Silicon Macs
- 🪟 Windows binaries for both ARM64 and x64 (built on Windows, MSVC ABI, no Visual C++ runtime needed)
- 🐧 Static musl Linux binary for x64 (runs on any distro, no glibc coupling; Signal Desktop on Linux is x64-only)
- 🛠️ macOS and Linux artifacts build from macOS (Linux by cross-compilation); Windows builds on Windows

## Prerequisites 📋

- 🖥️ macOS operating system
- 🦀 Rust programming language (latest stable version)
- 📦 Cargo package manager

## Installation 🛠️

1. Clone this repository:
   
   ```
   git clone https://github.com/fjh658/signal-decryption-tool.git
   cd signal-decryption-tool
   ```

2. Build the project using Cargo:
   
   ```
   cargo build --release
   ```

3. The compiled binary will be available in `target/release/signal_decryption`

### Building a Universal Binary 🏗️

To create a universal binary that runs on both Intel and Apple Silicon Macs:

1. Ensure you have the necessary Rust targets installed:
   
   ```
   rustup target add x86_64-apple-darwin aarch64-apple-darwin
   ```

2. Run the provided build script:
   
   ```
   ./build_universal_mac.sh
   ```

3. The universal binary will be created at `target/universal/SignalDecryption`

This script performs the following actions:

- Builds the project for both x86_64 and aarch64 architectures
- Strips debug symbols to reduce binary size
- Uses `lipo` to combine the binaries into a universal binary

### Building for Windows (cross-compile) 🪟

Windows binaries use the MSVC ABI and are cross-compiled from macOS/Linux with [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) (no Windows host required). SQLCipher's crypto is pure Rust (`crates/sqlcipher-rustcrypto`), so there is no OpenSSL to build for MSVC.

1. Install the toolchain:

   ```
   cargo install cargo-xwin
   rustup target add aarch64-pc-windows-msvc x86_64-pc-windows-msvc
   ```

2. Run the build script:

   ```
   ./build_windows.sh
   ```

3. The binaries are written to `target/windows/<tool>-arm64.exe` and `<tool>-x64.exe`, with `built-from.txt` naming the commit; `package.sh` refuses binaries built from any other commit.

The first run downloads the MSVC CRT and Windows SDK import libraries into cargo-xwin's cache; subsequent runs are offline.

On Windows itself, `build_windows.ps1` builds the same binaries natively with Visual Studio 2022 Build Tools (C++ workload, ARM64 and x64 tools): `powershell -NoProfile -ExecutionPolicy Bypass -File build_windows.ps1`.

The C runtime is linked statically (see `.cargo/config.toml`), so the executables run on a clean Windows without the Visual C++ Redistributable.

### Building for Linux (static musl) 🐧

Linux binaries are built against **musl** so they are fully static and run on any distro (Debian/Ubuntu, Alpine, bare hosts, containers) regardless of the host glibc version:

1. Install the toolchain (cross-compiling from macOS/Linux uses [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild); a native Linux host can use plain `cargo` with `musl-gcc`):

   ```
   cargo install cargo-zigbuild        # and have `zig` on PATH
   rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
   ```

2. Run the build script:

   ```
   ./build_linux.sh
   ```

3. The binary is written to `target/linux/SignalDecryption-x64`. (Only x64 is built: Signal Desktop for Linux is distributed as x86_64 exclusively, so there is no arm64 Signal profile to decrypt.)

### Building everything at once 🛠️

`build_all.sh` builds every artifact this host can build: the macOS universal binary on macOS, Linux from macOS or Linux, Windows on Windows (it skips the others and says so). `package.sh` then packages them, taking the Windows binaries from `target/windows/` as `build_windows.ps1` left them:

```
./build_all.sh              # everything applicable to this host
./build_all.sh windows linux   # only these
```

## Usage 📝

Run the tool from the command line with the following options:

```
SignalDecryption [options]

Options:
  -h, --help         Show this help message
  -c, --config PATH  Specify the path to the config.json file
  -k, --key KEY      Provide an encrypted key directly
  -p, --print-key    Print the secure storage key (use with caution)
  --version          Show the tool version
```

### Examples 🌈

1. Decrypt using the default configuration:
   
   ```
   ./SignalDecryption
   ```

2. Use a custom configuration file:
   
   ```
   ./SignalDecryption -c /path/to/custom/config.json
   ```

3. Provide an encrypted key directly:
   
   ```
   ./SignalDecryption -k "your_encrypted_key_here"
   ```

4. Print the secure storage key (use with caution):
   
   ```
   ./SignalDecryption -p
   ```

## Security Considerations 🔒

- ⚠️ This tool handles sensitive encryption keys. Use it in a secure environment.
- 🚨 The `-p` option prints sensitive information (the Keychain password on macOS, the DPAPI master key on Windows). Use it only when necessary and in a secure setting.
- 🔐 Ensure you have the necessary permissions to access Signal's configuration on your system.
- 🪟 On Windows the tool must run **as the user that owns the Signal profile** (DPAPI user-scope keys are user-bound); running as a different account or as `SYSTEM` will fail at `CryptUnprotectData`.
- 🍎 On macOS the first run triggers a Keychain access prompt for the "Signal Safe Storage" item; click Allow (or Always Allow) to proceed.
- 🐧 On Linux, `v11` keys require a running D-Bus session with an **unlocked** keyring (run inside the desktop session). When Signal uses the `basic_text` store it keeps the key as **plaintext** (`config.json`'s `key` field) rather than `encryptedKey`, so there is nothing to decrypt: both tools then use that key directly, as Signal itself does (it also wins when both fields are present). KWallet without the `org.freedesktop.secrets` bridge is not reachable.
- 📁 Default config path: `~/Library/Application Support/Signal/config.json` (macOS), `%APPDATA%\Signal\config.json` (Windows), `~/.config/Signal/config.json` (Linux). On Windows the sibling `Local State` file in the same directory is read for the master key.

## Limitations and Future Development 🚀

* 📱 This tool supports macOS, Windows and Linux. On Linux the `v10` (`peanuts`) and `v11` (Secret Service / `gnome_libsecret`) schemes are implemented; **KWallet** accessed natively (without the `org.freedesktop.secrets` bridge) is the remaining gap. The references below cover the relevant schemes:

  - For Windows implementation: [Chromium OS Crypt for Windows](https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_win.cc)
  - For cross-platform implementation in Electron: [Electron Safe Storage API](https://github.com/electron/electron/blob/41b8fdca5c53a41eabdad9a6a75b45bda4a6f37b/shell/browser/api/electron_api_safe_storage.cc)
  - For macOS specific implementation (current approach): [Chromium OS Crypt for macOS](https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_mac.mm)
  - Additional resource: [Electron macOS Keychain Patch](https://github.dev/electron/electron/blob/41b8fdca5c53a41eabdad9a6a75b45bda4a6f37b/patches/chromium/mas_avoid_private_macos_api_usage.patch.patch)

* 👨‍💻 While this tool is primarily intended for advanced users familiar with encryption key handling, we encourage developers of all levels to explore and contribute to cross-platform solutions.

* 🌍 If you develop a version for another operating system, please consider contributing it back to the community or linking it here as a related project.

## Contributing 🤝

Contributions to improve the tool or extend its functionality to other operating systems are welcome. Please feel free to submit pull requests or create issues for bugs and feature requests. If you're working on a version for another OS, you can open an issue to discuss your approach or seek guidance.

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer ⚖️

This tool is not officially associated with Signal. Use at your own risk. Always ensure you comply with relevant laws and Signal's terms of service when using this tool.
