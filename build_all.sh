#!/bin/bash
#
# Build every distributable artifact this host can build:
#
#   macOS   universal (x86_64 + arm64)         build_universal_mac.sh   [macOS host]
#   Windows arm64 + x64 (MSVC ABI, cargo-xwin)  build_windows.sh         [any host]
#   Linux   x64 (static musl, zigbuild)         build_linux.sh           [any host]
#
# Only macOS needs its own host; elsewhere it is skipped with a note. Pass a
# subset to build only those, e.g.:
#   ./build_all.sh windows linux

set -euo pipefail
cd "$(dirname "$0")"

# ---- Targets: "<name>:<script>:<host it needs: macos or any>" ---------------

readonly TARGETS=(
    "macos:build_universal_mac.sh:macos"
    "windows:build_windows.sh:any"
    "linux:build_linux.sh:any"
)

# ---- Pure helpers -----------------------------------------------------------

host_is_macos() { [ "$(uname -s)" = "Darwin" ]; }

# Whether a target should run given the host and the requested set.
should_build() {
    local name="$1" needs_macos="$2"
    if [ "${needs_macos}" = "macos" ] && ! host_is_macos; then
        echo "skip: ${name} (needs a macOS host)" >&2
        return 1
    fi
    if [ ${#REQUESTED[@]} -gt 0 ] && [[ ! " ${REQUESTED[*]} " == *" ${name} "* ]]; then
        return 1
    fi
    return 0
}

# ---- Guarded actions --------------------------------------------------------

run_build() {
    local name="$1" script="$2"
    echo "==> Building ${name} (${script})"
    "./${script}"
}

list_artifacts() {
    echo "==> Artifacts:"
    ls -la \
        target/universal/SignalDecryption target/universal/signal-sqlite \
        target/windows/*.exe \
        target/linux/SignalDecryption-* target/linux/signal-sqlite-* 2>/dev/null || true
}

# ---- Composition ------------------------------------------------------------

main() {
    REQUESTED=("$@") # empty = build all applicable
    for entry in "${TARGETS[@]}"; do
        IFS=':' read -r name script needs_macos <<<"${entry}"
        if should_build "${name}" "${needs_macos}"; then
            run_build "${name}" "${script}"
        fi
    done
    list_artifacts
}

main "$@"
