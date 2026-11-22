#!/bin/bash
#
# Build static Linux binaries of SignalDecryption.
#
# We target musl (not glibc) so the result is a fully static, dependency-free
# binary that runs on any Linux distro (Debian/Ubuntu, Alpine, bare hosts,
# containers) regardless of the host's glibc version. The Secret Service client
# (zbus) is pure Rust and talks D-Bus over a Unix socket; signal-sqlite's
# SQLCipher is C, built from source by cargo and linked statically (its crypto
# is RustCrypto, crates/sqlcipher-rustcrypto).
#
# Cross-compiling from macOS/Linux uses cargo-zigbuild (zig supplies the musl
# toolchain); on a native Linux host plain `cargo build` with musl-gcc also
# works, so we prefer zigbuild when present and fall back to cargo.
#
# Prerequisites (cross-compile):
#   cargo install cargo-zigbuild      # and have `zig` on PATH
#   rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl

set -euo pipefail

# ---- Configuration (named constants) ----------------------------------------

readonly OUTPUT_DIR="target/linux"
readonly PROFILE="release"
# Table of "<rust-target>:<output-suffix>" to build.
#
# x86_64 only: Signal Desktop for Linux is distributed as x86_64 exclusively
# (the official apt repo has no arm64 package), so there is no arm64 Signal
# profile to decrypt. Add an arm64 row here if you ever need a cross-host build.
readonly TARGETS=(
    "x86_64-unknown-linux-musl:x64"
)

# Both binaries; signal-sqlite needs the `sqlite` feature (SQLCipher).
readonly BINARIES=("SignalDecryption" "signal-sqlite")

# ---- Pure helpers (compute paths / commands, no side effects) ---------------

# Choose the build driver: zigbuild for cross, cargo for native musl.
build_driver() {
    if command -v cargo-zigbuild >/dev/null 2>&1; then
        echo "zigbuild"
    else
        echo "cargo"
    fi
}

# ---- Guarded actions (I/O at the edges) -------------------------------------

require_tools() {
    command -v cargo >/dev/null || { echo "error: cargo not found" >&2; exit 1; }
}

build_target() {
    local target="$1" driver="$2"
    echo "Building for ${target} (${driver})..."
    if [ "${driver}" = "zigbuild" ]; then
        cargo zigbuild --${PROFILE} --features sqlite --target "${target}"
    else
        cargo build --${PROFILE} --features sqlite --target "${target}"
    fi
}

# Copy every binary built for a target to its suffixed output name.
collect_output() {
    local target="$1" suffix="$2" bin src dst
    for bin in "${BINARIES[@]}"; do
        src="target/${target}/${PROFILE}/${bin}"
        dst="${OUTPUT_DIR}/${bin}-${suffix}"
        [ -f "${src}" ] || { echo "error: expected binary not found: ${src}" >&2; exit 1; }
        cp "${src}" "${dst}"
        echo "  -> ${dst}"
    done
}

# ---- Composition ------------------------------------------------------------

main() {
    require_tools
    mkdir -p "${OUTPUT_DIR}"
    local driver
    driver="$(build_driver)"

    for entry in "${TARGETS[@]}"; do
        local target="${entry%%:*}"
        local suffix="${entry##*:}"
        build_target "${target}" "${driver}"
        collect_output "${target}" "${suffix}"
    done

    echo "Linux static binaries created in ${OUTPUT_DIR}/"
}

main "$@"
