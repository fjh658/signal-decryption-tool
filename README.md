# Signal Decryption Tool for macOS 🔐

English | [中文](README_zh.md)

## Overview 🌟

This Signal Decryption Tool is a Rust-based command-line utility designed specifically for macOS to handle the encryption and decryption of Signal keys. It provides a secure way to manage Signal's encrypted configuration on macOS systems.

## Features ✨

- 🔓 Decrypt Signal's encrypted keys stored in the macOS keychain
- 📁 Support for custom configuration file paths
- 🔑 Option to directly input encrypted keys
- 🛡️ Secure handling of sensitive information
- 💻 Command-line interface for easy integration into scripts or manual use
- 🍎 Universal binary support for both Intel and Apple Silicon Macs

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
- 🚨 The `-p` option prints sensitive information. Use it only when necessary and in a secure setting.
- 🔐 Ensure you have the necessary permissions to access Signal's configuration on your system.

## Limitations and Future Development 🚀

* 📱 This tool is currently designed for macOS. However, users can develop similar tools for other operating systems based on the following resources:
  
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
