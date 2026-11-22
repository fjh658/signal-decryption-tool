#!/bin/bash
#
# Build the Windows binaries of SignalDecryption (MSVC ABI, so DPAPI and
# windows-sys link cleanly), one .exe per architecture.
#
# From macOS/Linux this cross-compiles with `cargo-xwin` (it supplies the MSVC
# CRT and Windows SDK import libraries and links with lld-link). SQLCipher's
# crypto is RustCrypto (crates/sqlcipher-rustcrypto), so no OpenSSL has to be
# built for MSVC. In Git Bash on Windows it runs build_windows.ps1, the native
# MSVC build, instead. Either way target/windows/built-from.txt records the
# commit, which package.sh checks before it ships the binaries.
#
# Prerequisites (cross-compile):
#   cargo install cargo-xwin              # and clang + lld (brew install llvm)
#   rustup target add aarch64-pc-windows-msvc x86_64-pc-windows-msvc
#
# The first run downloads the MSVC CRT/SDK into cargo-xwin's cache (needs
# network); subsequent runs are offline.

set -euo pipefail
cd "$(dirname "$0")"

# ---- Configuration (named constants) ----------------------------------------

readonly OUTPUT_DIR="target/windows"
readonly PROFILE="release"
# Table of "<rust-target>:<output-suffix>" to build.
readonly TARGETS=(
    "aarch64-pc-windows-msvc:arm64"
    "x86_64-pc-windows-msvc:x64"
)
# Both binaries; signal-sqlite needs the `sqlite` feature (bundled SQLCipher).
readonly BINARIES=("SignalDecryption" "signal-sqlite")

# ---- Pure helpers -----------------------------------------------------------

host_is_windows() { case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) return 0 ;; *) return 1 ;; esac; }

# ---- Guarded actions (I/O at the edges) -------------------------------------

require_tools() {
    command -v cargo >/dev/null || { echo "error: cargo not found" >&2; exit 1; }
    command -v git >/dev/null || { echo "error: git not found" >&2; exit 1; }
    cargo xwin --help >/dev/null 2>&1 || {
        echo "error: cargo-xwin not installed (run: cargo install cargo-xwin)" >&2
        exit 1
    }
}

build_target() {
    local target="$1"
    echo "Building for ${target}..."
    XWIN_ACCEPT_LICENSE=1 cargo xwin build --${PROFILE} --features sqlite --target "${target}"
}

# Copy every binary built for a target to its suffixed output name.
collect_output() {
    local target="$1" suffix="$2" bin src dst
    for bin in "${BINARIES[@]}"; do
        src="target/${target}/${PROFILE}/${bin}.exe"
        dst="${OUTPUT_DIR}/${bin}-${suffix}.exe"
        [ -f "${src}" ] || { echo "error: expected binary not found: ${src}" >&2; exit 1; }
        cp "${src}" "${dst}"
        echo "  -> ${dst}"
    done
}

# The commit the binaries come from, and whether the tree had local changes
# (the same record build_windows.ps1 writes).
write_built_from() {
    local rev state=clean
    rev="$(git rev-parse HEAD)"
    [ -z "$(git status --porcelain --untracked-files=no)" ] || state=dirty
    printf '%s %s\n' "${rev}" "${state}" > "${OUTPUT_DIR}/built-from.txt"
}

# ---- Composition ------------------------------------------------------------

main() {
    if host_is_windows; then
        exec powershell -NoProfile -ExecutionPolicy Bypass -File build_windows.ps1 "$@"
    fi
    require_tools
    mkdir -p "${OUTPUT_DIR}"

    for entry in "${TARGETS[@]}"; do
        local target="${entry%%:*}"
        local suffix="${entry##*:}"
        build_target "${target}"
        collect_output "${target}" "${suffix}"
    done
    write_built_from

    echo "Windows binaries created in ${OUTPUT_DIR}/"
}

main "$@"
