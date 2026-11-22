#!/bin/bash
#
# Build macOS universal binaries (x86_64 + arm64) for both tools.
#
# `signal-sqlite` needs the `sqlite` feature (SQLCipher); it is built
# alongside `SignalDecryption` and lipo'd into a universal binary each.

set -euo pipefail

# ---- Configuration (named constants) ----------------------------------------

readonly OUTPUT_DIR="target/universal"
readonly PROFILE="release"
readonly ARCHES=("x86_64-apple-darwin" "aarch64-apple-darwin")
readonly BINARIES=("SignalDecryption" "signal-sqlite")

# ---- Pure helpers -----------------------------------------------------------

arch_bin_path() {
    local arch="$1" bin="$2"
    echo "target/${arch}/${PROFILE}/${bin}"
}

# ---- Guarded actions --------------------------------------------------------

require_targets() {
    echo "Adding required Rust targets..."
    rustup target add "${ARCHES[@]}"
}

build_arch() {
    local arch="$1"
    echo "Building for ${arch}..."
    cargo build --${PROFILE} --features sqlite --target "${arch}"
}

# Lipo one binary across all arches into a universal output.
lipo_binary() {
    local bin="$1" inputs=() arch src
    for arch in "${ARCHES[@]}"; do
        src="$(arch_bin_path "${arch}" "${bin}")"
        [ -f "${src}" ] || { echo "error: expected binary not found: ${src}" >&2; exit 1; }
        strip -S -x "${src}"
        inputs+=("${src}")
    done
    lipo -create -output "${OUTPUT_DIR}/${bin}" "${inputs[@]}"
    echo "  -> ${OUTPUT_DIR}/${bin}"
}

# ---- Composition ------------------------------------------------------------

main() {
    require_targets
    mkdir -p "${OUTPUT_DIR}"
    for arch in "${ARCHES[@]}"; do
        build_arch "${arch}"
    done
    echo "Creating universal binaries..."
    for bin in "${BINARIES[@]}"; do
        lipo_binary "${bin}"
    done
    echo "Universal binaries created in ${OUTPUT_DIR}/"
}

main "$@"
