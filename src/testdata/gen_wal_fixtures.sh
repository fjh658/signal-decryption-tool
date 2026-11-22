#!/usr/bin/env bash
# Regenerates the encrypted WAL fixtures in this directory with the real
# sqlcipher CLI (verified with SQLCipher 4.20.0), one per Signal cipher profile:
#
#   <profile>_wal.sqlite      main database: table `items` with alpha, beta
#   <profile>_wal.sqlite-wal  WAL holding a committed CREATE TABLE + INSERT gamma
#
# The CREATE TABLE rewrites sqlite_schema, so every WAL is guaranteed to carry a
# page-1 frame — the shape a live Signal database has whenever the file grows.
# The snapshot is copied while the writer connection is still open: closing it
# would checkpoint the WAL into the main file and delete it.
#
# Usage: src/testdata/gen_wal_fixtures.sh   (from the repository root)
set -euo pipefail

readonly OUT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly KEY32="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
readonly SALT16="202122232425262728292a2b2c2d2e2f"

# Profile table: "<name>|<key + cipher PRAGMAs, run right after opening>".
# These mirror the PRAGMAs each Signal client issues (see key_pragmas in
# src/bin/signal-sqlite/db.rs, which signal-sqlite uses to open them).
readonly PROFILES=(
  "desktop|PRAGMA key = \"x'${KEY32}'\";"
  "ios|PRAGMA key = \"x'${KEY32}${SALT16}'\"; PRAGMA cipher_plaintext_header_size = 32;"
  "android|PRAGMA key = '${KEY32}'; PRAGMA cipher_compatibility = 3; PRAGMA kdf_iter = 1; PRAGMA cipher_page_size = 4096;"
)

# Creates the main database in rollback mode, then switches it to WAL.
seed_main() {
  local db="$1" keying="$2"
  sqlcipher "$db" >/dev/null <<SQL
${keying}
CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT);
INSERT INTO items(name) VALUES ('alpha'), ('beta');
PRAGMA journal_mode = WAL;
SQL
}

# Writes into the WAL and copies db + -wal out before the connection closes.
write_wal_and_snapshot() {
  local db="$1" keying="$2" dest="$3"
  sqlcipher "$db" >/dev/null <<SQL
${keying}
PRAGMA wal_autocheckpoint = 0;
CREATE TABLE wal_only(x);
INSERT INTO items(name) VALUES ('gamma');
.shell cp '${db}' '${dest}' && cp '${db}-wal' '${dest}-wal'
SQL
}

generate_profile() {
  local name="$1" keying="$2" work="$3"
  local db="${work}/${name}.db" dest="${OUT_DIR}/${name}_wal.sqlite"
  seed_main "$db" "$keying"
  write_wal_and_snapshot "$db" "$keying" "$dest"
  echo "wrote ${dest} (+ -wal)"
}

main() {
  command -v sqlcipher >/dev/null || { echo "error: sqlcipher CLI not found" >&2; exit 1; }
  local work
  work="$(mktemp -d "${TMPDIR:-/tmp}/walfix.XXXXXX")"
  trap 'find "'"$work"'" -mindepth 1 -delete; rmdir "'"$work"'"' EXIT
  local entry
  for entry in "${PROFILES[@]}"; do
    generate_profile "${entry%%|*}" "${entry#*|}" "$work"
  done
}

main "$@"
