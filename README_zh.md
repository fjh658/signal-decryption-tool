# Signal 解密工具 🔐

[English](README.md) | 中文

## 概述 🌟

`SignalDecryption` 是一个支持 **macOS、Windows 和 Linux** 的 Rust 命令行工具,从 Signal Desktop 的加密配置中恢复其 SQLCipher 数据库密钥。它通过实现 Chromium 的 `os_crypt` 方案恢复密钥——该方案在不同平台上完全不同:

- **macOS**:从钥匙串读取 "Safe Storage" 口令,经 PBKDF2-HMAC-SHA1(1003 次迭代)派生,再用 AES-128-CBC 解密 `config.json` 的 `encryptedKey`(前缀 `v10`)。
- **Windows**:从 `Local State`(`os_crypt.encrypted_key`)读取主密钥,通过 **DPAPI**(`CryptUnprotectData`,用户作用域)解包,再用 AES-256-GCM 解密 `config.json` 的 `encryptedKey`(前缀 `v10`)。由于 DPAPI 用户作用域密钥绑定登录用户,本工具必须**以拥有该 Signal 配置的 Windows 用户身份运行**。
- **Linux**:口令来自硬编码的 `"peanuts"`(前缀 `v10`,即 `basic_text` 回退存储),或从 **Secret Service** 读取(前缀 `v11`,`gnome_libsecret`——属性 `application=Signal`),再经 PBKDF2-HMAC-SHA1(**1 次迭代**)派生,用 AES-128-CBC 解密 `encryptedKey`。v11 需要运行中的 D-Bus 会话与已解锁的 keyring,故必须**在用户的桌面会话内运行**。

## 特性 ✨

- 🔓 在 macOS(钥匙串)、Windows(DPAPI)和 Linux(Secret Service)上恢复 Signal 的 SQLCipher 密钥
- 📁 支持自定义配置文件路径
- 🔑 可以直接输入加密密钥
- 🛡️ 安全处理敏感信息
- 💻 命令行界面,易于集成到脚本或手动使用
- 🍎 支持 Intel 和 Apple Silicon Mac 的通用二进制文件
- 🪟 支持 Windows ARM64 与 x64 二进制(在 Windows 上构建,MSVC ABI,无需 Visual C++ 运行库)
- 🐧 静态 musl Linux 二进制(x64,任意发行版可跑,不与 glibc 耦合;Signal Desktop 在 Linux 上仅发行 x64)
- 🛠️ macOS 与 Linux 产物在 macOS 上构建(Linux 为交叉编译);Windows 产物在 Windows 上构建

## 前提条件 📋

- 🖥️ macOS、Windows 或 Linux 操作系统
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

### 构建 Windows 版本(交叉编译) 🪟

Windows 二进制使用 MSVC ABI,通过 [`cargo-xwin`](https://github.com/rust-cross/cargo-xwin) 从 macOS/Linux 交叉编译(无需 Windows 主机)。SQLCipher 的加密实现是纯 Rust(`crates/sqlcipher-rustcrypto`),所以不需要为 MSVC 编 OpenSSL。

1. 安装工具链:

   ```
   cargo install cargo-xwin
   rustup target add aarch64-pc-windows-msvc x86_64-pc-windows-msvc
   ```

2. 运行构建脚本:

   ```
   ./build_windows.sh
   ```

3. 二进制输出到 `target/windows/<工具>-arm64.exe` 和 `<工具>-x64.exe`,并附 `built-from.txt` 记录源码 commit;`package.sh` 会拒绝其他 commit 编出的二进制。

首次运行会把 MSVC CRT 与 Windows SDK 导入库下载到 cargo-xwin 的缓存;之后运行均为离线。

在 Windows 本机上,`build_windows.ps1` 用 Visual Studio 2022 Build Tools(C++ 工作负载,含 ARM64 和 x64 工具)原生编出同样的二进制:`powershell -NoProfile -ExecutionPolicy Bypass -File build_windows.ps1`。

C 运行库是静态链接的(见 `.cargo/config.toml`),所以 exe 在没有装 Visual C++ 运行库的干净 Windows 上也能运行。

### 构建 Linux 版本(静态 musl) 🐧

Linux 二进制针对 **musl** 构建,完全静态,可在任意发行版(Debian/Ubuntu、Alpine、裸机、容器)运行,不受宿主 glibc 版本限制:

1. 安装工具链(从 macOS/Linux 交叉编译用 [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild);原生 Linux 主机可用自带 `musl-gcc` 的 `cargo`):

   ```
   cargo install cargo-zigbuild        # 并确保 PATH 中有 `zig`
   rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
   ```

2. 运行构建脚本:

   ```
   ./build_linux.sh
   ```

3. 二进制输出到 `target/linux/SignalDecryption-x64`。(仅构建 x64:Signal Desktop 在 Linux 上只发行 x86_64,不存在 arm64 的 Signal 配置可解密。)

### 一键构建全部产物 🛠️

`build_all.sh` 构建当前主机能构建的全部产物:macOS 通用二进制在 macOS 上,Linux 在 macOS 或 Linux 上,Windows 在 Windows 上(其他的会跳过并说明)。然后由 `package.sh` 打包,Windows 二进制取自 `build_windows.ps1` 留在 `target/windows/` 里的那份:

```
./build_all.sh              # 构建当前主机适用的全部目标
./build_all.sh windows linux   # 仅构建指定目标
```

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
- 🚨 `-p` 选项会打印敏感信息(macOS 上是钥匙串口令,Windows 上是 DPAPI 主密钥)。仅在必要时在安全的环境中使用。
- 🔐 确保您有必要的权限来访问系统上的 Signal 配置。
- 🪟 在 Windows 上必须**以拥有该 Signal 配置的用户身份运行**(DPAPI 用户作用域密钥绑定用户);以其他账户或 `SYSTEM` 身份运行会在 `CryptUnprotectData` 处失败。
- 🍎 在 macOS 上首次运行会弹出 "Signal Safe Storage" 项的钥匙串访问提示;点击"允许"(或"始终允许")以继续。
- 🐧 在 Linux 上,`v11` 密钥需要运行中的 D-Bus 会话与**已解锁**的 keyring(在桌面会话内运行)。当 Signal 使用 `basic_text` 存储时,它把密钥以**明文**存在 `config.json` 的 `key` 字段(而非 `encryptedKey`),因此无需解密:两个工具都直接用这个 key,与 Signal 自己的做法一致(两个字段并存时也以它为准)。未经 `org.freedesktop.secrets` 桥接的 KWallet 无法访问。
- 📁 默认配置路径:`~/Library/Application Support/Signal/config.json`(macOS)、`%APPDATA%\Signal\config.json`(Windows)、`~/.config/Signal/config.json`(Linux)。Windows 上还会读取同目录下的 `Local State` 文件以获取主密钥。

## 局限性和未来发展 🚀

* 📱 此工具支持 macOS、Windows 和 Linux。Linux 上已实现 `v10`(`peanuts`)与 `v11`(Secret Service / `gnome_libsecret`)方案;**未经 `org.freedesktop.secrets` 桥接直连 KWallet** 仍是缺口。以下资源涵盖了相关方案:

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
