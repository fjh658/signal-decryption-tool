#!/bin/bash
#
# Package the per-OS release artifacts (already built into target/ by
# build_all.sh) into one compressed archive per platform under dist/.
#
#   macos-universal   target/universal/{SignalDecryption,signal-sqlite}   -> .tar.gz
#   linux-x64         target/linux/*-x64                                   -> .tar.gz
#   windows-x64       target/windows/*-x64.exe                             -> .zip
#   windows-arm64     target/windows/*-arm64.exe                           -> .zip
#
# Each archive holds a single top-level folder
# "SignalDecryption-<version>-<label>/" containing both tools (renamed to their
# plain names, with .exe on Windows) plus README.md, README_zh.md and LICENSE.
# Everything goes to dist/<version>/, with a SHA256SUMS file covering exactly
# the archives this run wrote, so a stale archive can never slip in.
#
# The archives are reproducible: owners are dropped, every timestamp is
# SOURCE_DATE_EPOCH (default: the last commit's time), entries are sorted, and
# gzip stores no name or time. The packaged READMEs link the diagrams by the
# release tag, since docs/ is not packaged. A Windows exe that imports anything
# but system DLLs (e.g. the VC++ runtime) is refused.
#
# By default this builds every platform first (via ./build_all.sh) and then
# packages, so one command produces dist/. Pass --no-build to skip the build and
# just package whatever artifacts already exist in target/. The version defaults
# to the Cargo.toml package version; override it with:
#   ./package.sh [--no-build] [<version>]
#
# No `rm -rf`: staging lives in a mktemp dir cleaned with `find -delete`, and
# only the exact output files are removed before they are rewritten.

set -euo pipefail
cd "$(dirname "$0")"

# ---- Configuration (named constants) ----------------------------------------

readonly PRODUCT="SignalDecryption"
readonly DIST_DIR="dist"
readonly BUILD_SCRIPT="build_all.sh"   # produces target/{universal,windows,linux}
readonly BINARIES=("SignalDecryption" "signal-sqlite")
readonly DOC_FILES=("README.md" "README_zh.md" "LICENSE")
readonly README_FILES=("README.md" "README_zh.md")
# Public repository; packaged READMEs link docs/ there, pinned to the release tag.
readonly REPO_URL="https://github.com/fjh658/signal-decryption-tool"
# DLLs that ship with every Windows install; anything else must be linked in.
# bcryptprimitives (ProcessPrng, Windows 10+) is SQLCipher's random source,
# through getrandom in crates/sqlcipher-rustcrypto.
readonly WINDOWS_SYSTEM_DLLS=("kernel32.dll" "ntdll.dll" "advapi32.dll" "crypt32.dll" "bcryptprimitives.dll" "api-ms-win-core-synch-l1-2-0.dll")

# Platform table: "<label>|<format>|<src-dir>|<src-suffix>|<ext>".
#   src file  = <src-dir>/<bin><src-suffix><ext>
#   dest file = <bin><ext>   (inside the archive's top-level folder)
readonly PLATFORMS=(
    "macos-universal|tar.gz|target/universal||"
    "linux-x64|tar.gz|target/linux|-x64|"
    "windows-x64|zip|target/windows|-x64|.exe"
    "windows-arm64|zip|target/windows|-arm64|.exe"
)

# ---- Pure helpers (compute values / paths, no side effects) -----------------

# Read the package version from Cargo.toml (first `version = "..."`).
cargo_version() {
    sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -1
}

stage_folder_name() {
    local version="$1" label="$2"
    echo "${PRODUCT}-${version}-${label}"
}

archive_file_name() {
    local version="$1" label="$2" format="$3"
    echo "${PRODUCT}-${version}-${label}.${format}"
}

# One output folder per version.
version_dir() {
    echo "${DIST_DIR}/$1"
}

# The archive timestamp: SOURCE_DATE_EPOCH, else the last commit's time.
source_date_epoch() {
    if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
        echo "${SOURCE_DATE_EPOCH}"
    else
        git log -1 --format=%ct 2>/dev/null
    fi
}

# `touch -t` stamp (UTC) for an epoch, with BSD or GNU date.
touch_stamp() {
    date -u -r "$1" +%Y%m%d%H%M.%S 2>/dev/null || date -u -d "@$1" +%Y%m%d%H%M.%S
}

# sed program that pins relative docs/ links to the release tag: images to raw
# files, everything else to the repository view.
pin_links_program() {
    local version="$1"
    echo "s#\]\(docs/([^)]*\.png)\)#](${REPO_URL}/raw/${version}/docs/\1)#g; s#\]\(docs/([^)]*)\)#](${REPO_URL}/blob/${version}/docs/\1)#g"
}

# ---- Guarded actions (I/O at the edges) -------------------------------------

require_tools() {
    local t
    for t in tar gzip zip shasum; do
        command -v "${t}" >/dev/null || { echo "error: ${t} not found" >&2; exit 1; }
    done
}

# Build every platform's artifacts into target/ (what build_all.sh produces).
run_build() {
    [ -x "./${BUILD_SCRIPT}" ] || { echo "error: ./${BUILD_SCRIPT} not found or not executable" >&2; exit 1; }
    echo "==> Building artifacts (./${BUILD_SCRIPT})"
    "./${BUILD_SCRIPT}"
}

# Remove a mktemp staging tree without `rm -rf` (find -delete is depth-first).
cleanup_stage() {
    local dir="$1"
    [ -n "${dir}" ] && [ -d "${dir}" ] || return 0
    find "${dir}" -mindepth 1 -delete
    rmdir "${dir}"
}

# Copy both binaries (renamed to plain names) + docs into a fresh staged folder.
stage_platform() {
    local stage_root="$1" version="$2" label="$3" src_dir="$4" suffix="$5" ext="$6"
    local dest="${stage_root}/$(stage_folder_name "${version}" "${label}")"
    mkdir -p "${dest}"

    local bin src dst
    for bin in "${BINARIES[@]}"; do
        src="${src_dir}/${bin}${suffix}${ext}"
        dst="${dest}/${bin}${ext}"
        [ -f "${src}" ] || { echo "error: missing artifact: ${src} -- ${BUILD_SCRIPT} did not produce it (this host may not be able to build ${label}; or drop --no-build)" >&2; exit 1; }
        cp "${src}" "${dst}"
        chmod +x "${dst}"
    done

    local doc
    for doc in "${DOC_FILES[@]}"; do
        [ -f "${doc}" ] && cp "${doc}" "${dest}/"
    done

    pin_readme_links "${dest}" "${version}"
    check_readme_links "${dest}"
    if [ "${ext}" = ".exe" ]; then
        check_built_from "${src_dir}"
        for bin in "${BINARIES[@]}"; do
            check_windows_imports "${dest}/${bin}${ext}"
        done
    fi
}

pin_readme_links() {
    local dest="$1" version="$2" readme
    for readme in "${README_FILES[@]}"; do
        [ -f "${dest}/${readme}" ] || continue
        sed -E "$(pin_links_program "${version}")" "${dest}/${readme}" > "${dest}/${readme}.pinned"
        mv "${dest}/${readme}.pinned" "${dest}/${readme}"
    done
}

# Every relative link in a packaged README must point into the archive.
check_readme_links() {
    local dest="$1" readme link links
    for readme in "${README_FILES[@]}"; do
        [ -f "${dest}/${readme}" ] || continue
        # Captured first, for the same reason as in check_windows_imports; no
        # match is fine.
        links="$(grep -oE '\]\([^) ]+\)' "${dest}/${readme}" | sed -E 's/^\]\((.*)\)$/\1/' || true)"
        while IFS= read -r link; do
            [ -n "${link}" ] || continue
            case "${link}" in http://*|https://*|mailto:*|\#*) continue ;; esac
            [ -e "${dest}/${link%%#*}" ] || { echo "error: ${readme} links to ${link}, which is not in the archive" >&2; exit 1; }
        done <<< "${links}"
    done
}

# Windows binaries come from build_windows.sh (cargo-xwin) or build_windows.ps1
# (on Windows), which record the commit in built-from.txt; refuse ones built
# from any other state.
check_built_from() {
    local dir="$1" recorded head
    [ -f "${dir}/built-from.txt" ] || { echo "error: ${dir}/built-from.txt missing: build them with build_windows.sh" >&2; exit 1; }
    recorded="$(cat "${dir}/built-from.txt" | tr -d '\r')"
    head="$(git rev-parse HEAD)"
    [ "${recorded}" = "${head} clean" ] || {
        echo "error: Windows binaries were built from '${recorded}', not from a clean ${head}: rebuild them" >&2
        exit 1
    }
}

# The DLLs an exe imports, lower-cased, from its PE import table.
windows_imports() {
    local tool
    tool="$(command -v llvm-objdump || command -v objdump)" || { echo "error: objdump not found (needed to check Windows imports)" >&2; exit 1; }
    "${tool}" -p "$1" | sed -n 's/^[[:space:]]*DLL Name:[[:space:]]*//p' | tr '[:upper:]' '[:lower:]'
}

check_windows_imports() {
    local exe="$1" dll allowed found imports
    # Captured first: inside `< <(...)` a failure (say, objdump missing) would
    # not stop the script, and the check would silently pass.
    imports="$(windows_imports "${exe}")"
    [ -n "${imports}" ] || { echo "error: no imports read from $(basename "${exe}") (can this objdump read PE files?)" >&2; exit 1; }
    while IFS= read -r dll; do
        found=0
        for allowed in "${WINDOWS_SYSTEM_DLLS[@]}"; do
            [ "${dll}" = "${allowed}" ] && found=1
        done
        [ "${found}" -eq 1 ] || {
            echo "error: $(basename "${exe}") imports ${dll}, which a clean Windows may lack (is the static CRT in .cargo/config.toml in effect?)" >&2
            exit 1
        }
    done <<< "${imports}"
}

# Fixed modes and timestamps for everything staged, so archives are reproducible.
normalize_stage() {
    local stage_root="$1" epoch="$2" stamp
    stamp="$(touch_stamp "${epoch}")"
    find "${stage_root}" -mindepth 1 -type d -exec chmod 755 {} +
    find "${stage_root}" -mindepth 1 -type f -exec chmod 644 {} +
    find "${stage_root}" -mindepth 1 -type f \( -name '*.exe' -o -name "${BINARIES[0]}" -o -name "${BINARIES[1]}" \) -exec chmod 755 {} +
    find "${stage_root}" -mindepth 1 -exec env TZ=UTC touch -h -t "${stamp}" {} +
}

# Sorted entry list of a staged folder (archive order must not depend on the filesystem).
sorted_entries() {
    ( cd "$1" && find "$2" -print | LC_ALL=C sort )
}

write_tar_gz() {
    local stage_root="$1" folder="$2" out="$3"
    if tar --version 2>/dev/null | grep -q 'GNU tar'; then
        sorted_entries "${stage_root}" "${folder}" | tar -C "${stage_root}" --format=ustar --owner=0 --group=0 \
            --numeric-owner --no-recursion -T - -cf - | gzip -n -9 > "${out}"
    else
        sorted_entries "${stage_root}" "${folder}" | COPYFILE_DISABLE=1 tar -C "${stage_root}" --format ustar \
            --uid 0 --gid 0 --uname '' --gname '' --no-xattrs --no-mac-metadata -n -T - -cf - | gzip -n -9 > "${out}"
    fi
}

write_zip() {
    local stage_root="$1" folder="$2" out="$3"
    # -X drops owner ids and extra timestamps; TZ=UTC fixes the DOS local time.
    sorted_entries "${stage_root}" "${folder}" | ( cd "${stage_root}" && TZ=UTC zip -q -X "${out}" -@ )
}

# Archive a staged folder into dist/ in the requested format.
archive_platform() {
    local stage_root="$1" version="$2" label="$3" format="$4"
    local folder; folder="$(stage_folder_name "${version}" "${label}")"
    local out; out="$(archive_file_name "${version}" "${label}" "${format}")"
    local dist_abs; dist_abs="$(cd "$(version_dir "${version}")" && pwd)"  # zip needs an absolute path once we cd away
    rm -f "${dist_abs}/${out}"   # zip would append to an existing archive
    case "${format}" in
        tar.gz) write_tar_gz "${stage_root}" "${folder}" "${dist_abs}/${out}" ;;
        zip)    write_zip "${stage_root}" "${folder}" "${dist_abs}/${out}" ;;
        *)      echo "error: unknown format: ${format}" >&2; exit 1 ;;
    esac
    echo "  -> $(version_dir "${version}")/${out}"
}

# Checksums of exactly the given archives, then verified as a self-check.
write_checksums() {
    local dir="$1"; shift
    ( cd "${dir}" && shasum -a 256 "$@" > SHA256SUMS && shasum -a 256 -c SHA256SUMS >/dev/null )
    echo "  -> ${dir}/SHA256SUMS"
}

# ---- Composition ------------------------------------------------------------

main() {
    require_tools

    # Args: [--no-build] [<version>]. Default is to build then package.
    local do_build=1 version="" arg
    for arg in "$@"; do
        case "${arg}" in
            --no-build) do_build=0 ;;
            --build)    do_build=1 ;;
            -*)         echo "error: unknown option: ${arg}" >&2; exit 1 ;;
            *)          version="${arg}" ;;
        esac
    done
    version="${version:-$(cargo_version)}"
    [ -n "${version}" ] || { echo "error: could not determine version" >&2; exit 1; }

    if [ "${do_build}" -eq 1 ]; then
        run_build
    fi

    local epoch; epoch="$(source_date_epoch)"
    [ -n "${epoch}" ] || { echo "error: set SOURCE_DATE_EPOCH (no git history to take it from)" >&2; exit 1; }
    local out_dir; out_dir="$(version_dir "${version}")"

    echo "Packaging ${PRODUCT} ${version} -> ${out_dir}/"
    mkdir -p "${out_dir}"
    # stage_root is global (not local): the EXIT trap fires after main returns,
    # when a local would already be out of scope under `set -u`.
    stage_root=""
    trap 'cleanup_stage "${stage_root:-}"' EXIT
    stage_root="$(mktemp -d "${TMPDIR:-/tmp}/signaldecryption-pkg.XXXXXX")"

    local entry label format src_dir suffix ext produced=()
    for entry in "${PLATFORMS[@]}"; do
        IFS='|' read -r label format src_dir suffix ext <<<"${entry}"
        stage_platform "${stage_root}" "${version}" "${label}" "${src_dir}" "${suffix}" "${ext}"
        normalize_stage "${stage_root}" "${epoch}"
        archive_platform "${stage_root}" "${version}" "${label}" "${format}"
        produced+=("$(archive_file_name "${version}" "${label}" "${format}")")
    done

    write_checksums "${out_dir}" "${produced[@]}"
    echo "Done."
    ls -la "${out_dir}"
}

main "$@"
