# macOS Signal 解密工具 🔐

[English](README.md) | 中文

## 概述 🌟

这个 Signal 解密工具是一个专为 macOS 设计的基于 Rust 的命令行工具,用于处理 Signal 密钥的加密和解密。它提供了一种安全的方式来管理 macOS 系统上 Signal 的加密配置。

## 特性 ✨

- 🔓 解密存储在 macOS 钥匙串中的 Signal 加密密钥
- 📁 支持自定义配置文件路径
- 🔑 可以直接输入加密密钥
- 🛡️ 安全处理敏感信息
- 💻 命令行界面,易于集成到脚本或手动使用
- 🍎 支持 Intel 和 Apple Silicon Mac 的通用二进制文件

## 前提条件 📋

- 🖥️ macOS 操作系统
- 🦀 Rust 编程语言(最新稳定版)
- 📦 Cargo 包管理器

## 安装 🛠️

1. 克隆此仓库:
   
   ```
   git clone https://github.com/fjh658/signal-decryption-tool.git
   cd signal-decryption-tool
   ```

2. 使用 Cargo 构建项目:
   
   ```
   cargo build --release
   ```

3. 编译后的二进制文件将位于 `target/release/signal_decryption`

### 构建通用二进制文件 🏗️

要创建同时适用于 Intel 和 Apple Silicon Mac 的通用二进制文件:

1. 确保已安装必要的 Rust 目标:
   
   ```
   rustup target add x86_64-apple-darwin aarch64-apple-darwin
   ```

2. 运行提供的构建脚本:
   
   ```
   ./build_universal_mac.sh
   ```

3. 通用二进制文件将创建在 `target/universal/SignalDecryption`

此脚本执行以下操作:

- 为 x86_64 和 aarch64 架构构建项目
- 剥离调试符号以减小二进制文件大小
- 使用 `lipo` 将二进制文件合并为通用二进制文件

## 使用方法 📝

从命令行运行工具,使用以下选项:

```
SignalDecryption [选项]

选项:
  -h, --help         显示帮助信息
  -c, --config PATH  指定 config.json 文件的路径
  -k, --key KEY      直接提供加密密钥
  -p, --print-key    打印安全存储密钥(谨慎使用)
  --version          显示工具版本
```

### 示例 🌈

1. 使用默认配置进行解密:
   
   ```
   ./SignalDecryption
   ```

2. 使用自定义配置文件:
   
   ```
   ./SignalDecryption -c /path/to/custom/config.json
   ```

3. 直接提供加密密钥:
   
   ```
   ./SignalDecryption -k "your_encrypted_key_here"
   ```

4. 打印安全存储密钥(谨慎使用):
   
   ```
   ./SignalDecryption -p
   ```

## 安全考虑 🔒

- ⚠️ 此工具处理敏感的加密密钥。请在安全的环境中使用。
- 🚨 `-p` 选项会打印敏感信息。仅在必要时在安全的环境中使用。
- 🔐 确保您有必要的权限来访问系统上的 Signal 配置。

## 局限性和未来发展 🚀

* 📱 此工具目前专为 macOS 设计。然而,用户可以基于以下资源为其他操作系统开发类似的工具:
  
  - Windows 实现: [Chromium OS Crypt for Windows](https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_win.cc)
  - Electron 中的跨平台实现: [Electron Safe Storage API](https://github.com/electron/electron/blob/41b8fdca5c53a41eabdad9a6a75b45bda4a6f37b/shell/browser/api/electron_api_safe_storage.cc)
  - macOS 特定实现(当前方法): [Chromium OS Crypt for macOS](https://chromium.googlesource.com/chromium/src/+/refs/tags/130.0.6686.2/components/os_crypt/sync/os_crypt_mac.mm)
  - 额外资源: [Electron macOS Keychain Patch](https://github.dev/electron/electron/blob/41b8fdca5c53a41eabdad9a6a75b45bda4a6f37b/patches/chromium/mas_avoid_private_macos_api_usage.patch.patch)

* 👨‍💻 虽然此工具主要面向熟悉加密密钥处理的高级用户,但我们鼓励各级开发者探索并贡献跨平台解决方案。

* 🌍 如果您为其他操作系统开发了版本,请考虑将其贡献回社区或在此处链接作为相关项目。

## 贡献 🤝

欢迎贡献以改进工具或扩展其功能到其他操作系统。请随时提交拉取请求或创建问题以报告错误和功能请求。如果您正在为其他操作系统开发版本,可以开启一个问题来讨论您的方法或寻求指导。

## 许可证 📄

本项目采用 MIT 许可证 - 有关详细信息,请查看 [LICENSE](LICENSE) 文件。

## 免责声明 ⚖️

此工具与 Signal 官方无关。使用风险自负。使用此工具时,请始终确保遵守相关法律和 Signal 的服务条款。
