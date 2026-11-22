//! Offline decryption of Signal **Android** encrypted `.backup` files.
//!
//! This is the no-root path to Android support: the user enables local backups
//! in Signal, which writes a `signal-YYYY-MM-DD-...backup` file protected by a
//! 30-digit passphrase. Unlike the live on-device database (whose key is sealed
//! by the Android Keystore and cannot be unwrapped off-device), the `.backup`
//! file is self-contained — passphrase + file is everything needed.
//!
//! Everything here was verified byte-for-byte against the Signal-Android source
//! (tag 8.36.2); the relevant files are cited inline:
//!
//! * `backup/FullBackupBase.java`          — passphrase -> 32-byte backup key
//! * `backup/BackupFrameOutputStream.java` — the writer (authoritative format)
//! * `backup/BackupRecordInputStream.java` — the reader (what we re-implement)
//! * `backup/FullBackupImporter.java`      — how SqlStatement frames rebuild the DB
//! * `backup/BackupVersions.kt`            — version gate + length-encryption flag
//! * `protowire/Backups.proto`             — the proto2 `BackupFrame` schema
//!
//! ## File layout
//!
//! ```text
//! [4B BE length][plaintext Header frame]          <- Header carries iv, salt, version
//! repeated:
//!   [4B length][frame ciphertext][10B MAC]         <- length is CTR-encrypted for version >= 1
//!   (if the frame is an attachment/avatar/sticker:)
//!   [blob ciphertext (length bytes)][10B MAC]      <- a SECOND encrypted unit, its own counter
//! ...terminated by an encrypted BackupFrame{ end = true }.
//! ```
//!
//! ## Crypto
//!
//! * **passphrase -> key**: strip spaces, then SHA-512 iterated 250,000 times
//!   (round 0 hashes `salt || pass || pass`, later rounds `prev || pass`), trim
//!   to 32 bytes. (`FullBackupBase.java:18-35`.)
//! * **key split**: `HKDF-SHA256(key, salt = none, info = "Backup Export", L = 64)`
//!   -> `cipherKey (32) || macKey (32)`. libsignal's HKDF uses a zero salt, which
//!   is the RFC-5869 default, so `Hkdf::new(None, key)` matches it exactly.
//! * **frames**: AES-256-CTR. The 16-byte IV comes from the header; before every
//!   encrypted unit its first 4 bytes are overwritten with a big-endian counter,
//!   which starts at `BE32(iv[0..4])` and **increments once per frame AND once per
//!   attachment/avatar/sticker blob**. Getting that increment wrong corrupts
//!   everything after the first attachment — the format's single sharpest edge.
//! * **MAC**: HMAC-SHA256 truncated to its first 10 bytes. A frame MAC covers
//!   `encrypted_length(4) || ciphertext`; a blob MAC covers `iv(16) || ciphertext`.
//!
//! ## What we produce
//!
//! We only need `statement` and `version` frames to rebuild a queryable database;
//! attachment/avatar/sticker blobs are still *consumed* (to keep the stream and
//! the counter aligned) but their bytes are discarded. The SqlStatement frames are
//! replayed into a fresh in-memory SQLite database exactly the way Signal's own
//! importer does (same skip predicates, foreign keys off), and that database is
//! serialized to a plaintext image the rest of `signal-sqlite` can mount and query.

use std::io::{self, Read};

use aes::Aes256;
use ctr::cipher::{NewCipher, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rusqlite::{Connection, MAIN_DB};
use sha2::{Digest, Sha256, Sha512};

/// AES-256 in 128-bit big-endian counter mode — matches Java `AES/CTR/NoPadding`,
/// whose counter is the full 128-bit IV incremented big-endian.
type Aes256Ctr = Ctr128BE<Aes256>;
use ctr::Ctr128BE;
type HmacSha256 = Hmac<Sha256>;

/// SHA-512 rounds for the passphrase KDF (`FullBackupBase.DIGEST_ROUNDS`).
const DIGEST_ROUNDS: usize = 250_000;
/// HKDF `info` string (`BackupFrameOutputStream.java:59`).
const HKDF_INFO: &[u8] = b"Backup Export";
/// Truncated-HMAC tag length appended to every encrypted unit.
const MAC_LEN: usize = 10;
/// Symmetric key length (both cipherKey and macKey).
const KEY_LEN: usize = 32;
/// AES-CTR IV / nonce length.
const IV_LEN: usize = 16;
/// Supported backup versions (`BackupVersions.kt`): MINIMUM_VERSION..=CURRENT_VERSION.
const MINIMUM_VERSION: u32 = 0;
const CURRENT_VERSION: u32 = 1;
/// Sanity caps: a wrong passphrase decrypts the length field to a uniformly random
/// 32-bit value, so an implausible length is the first wrong-passphrase signal (the
/// MAC is the second). Headers are tiny; frames hold one row's worth of values.
const MAX_HEADER_LEN: usize = 64 * 1024;
const MAX_FRAME_LEN: usize = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can go wrong decrypting or rebuilding a backup.
#[derive(Debug)]
pub enum BackupError {
    /// Underlying I/O failure (short read, unreadable file, ...).
    Io(io::Error),
    /// The byte stream did not match the documented format.
    Format(String),
    /// A frame's MAC did not verify — wrong passphrase or a corrupt file.
    WrongPassphrase,
    /// The header declared a version outside `MINIMUM_VERSION..=CURRENT_VERSION`.
    UnsupportedVersion(u32),
    /// Building the reconstructed SQLite database failed.
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for BackupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupError::Io(e) => write!(f, "backup I/O error: {e}"),
            BackupError::Format(m) => write!(f, "malformed backup: {m}"),
            BackupError::WrongPassphrase => write!(
                f,
                "could not decrypt the backup — the passphrase is wrong or the file is corrupt"
            ),
            BackupError::UnsupportedVersion(v) => {
                write!(f, "unsupported backup version {v} (this tool handles {MINIMUM_VERSION}..={CURRENT_VERSION})")
            }
            BackupError::Sqlite(e) => write!(f, "rebuilding the database failed: {e}"),
        }
    }
}

impl std::error::Error for BackupError {}

impl From<io::Error> for BackupError {
    fn from(e: io::Error) -> Self {
        BackupError::Io(e)
    }
}

impl From<rusqlite::Error> for BackupError {
    fn from(e: rusqlite::Error) -> Self {
        BackupError::Sqlite(e)
    }
}

/// Short constructor for a format error.
fn format_err(msg: impl Into<String>) -> BackupError {
    BackupError::Format(msg.into())
}

/// The result of rebuilding a backup into a plaintext SQLite image.
#[derive(Debug)]
pub struct RebuildOutcome {
    /// Serialized plaintext SQLite database (ready to mount read-only in memory).
    pub image: Vec<u8>,
    /// Total frames read from the stream (excludes the plaintext header).
    pub frames: usize,
    /// `statement` frames executed against the rebuilt database.
    pub statements_run: usize,
    /// `statement` frames deliberately skipped (FTS shadow tables, `sqlite_*`, ...).
    pub statements_skipped: usize,
    /// Non-fatal problems (a statement that failed to execute, for example). The
    /// rebuild keeps going so one odd statement never loses the whole database.
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Passphrase
// ---------------------------------------------------------------------------

/// Digits in a Signal backup passphrase (shown as six groups of five).
const PASSPHRASE_DIGITS: usize = 30;

/// A backup passphrase: exactly the 30 digits Signal shows, from whatever the
/// user typed or saved (UTF-8 or UTF-16, with or without a BOM, any whitespace
/// between the groups). Never printed, not even in errors.
pub struct Passphrase(String);

/// Why a passphrase was rejected (without its content).
#[derive(Debug)]
pub struct PassphraseError(String);

impl std::fmt::Display for PassphraseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid backup passphrase ({}): expected the 30 digits Signal showed when backups were enabled", self.0)
    }
}

impl std::error::Error for PassphraseError {}

impl Passphrase {
    /// Validates typed text: whitespace is dropped, anything else must be an
    /// ASCII digit, and there must be exactly [`PASSPHRASE_DIGITS`].
    pub fn parse(text: &str) -> Result<Self, PassphraseError> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        if !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(PassphraseError("only digits and spaces are allowed".into()));
        }
        if digits.len() != PASSPHRASE_DIGITS {
            return Err(PassphraseError(format!("got {} digits", digits.len())));
        }
        Ok(Passphrase(digits))
    }

    /// Decodes a file's or stdin's bytes, then validates them like [`Self::parse`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PassphraseError> {
        Self::parse(&decode_text(bytes)?)
    }

    /// The 30 digits, without separators.
    pub fn digits(&self) -> &str {
        &self.0
    }
}

/// UTF-8 or UTF-16 text, told apart by a BOM or, without one, by the NUL
/// bytes UTF-16 puts next to every ASCII digit.
fn decode_text(bytes: &[u8]) -> Result<String, PassphraseError> {
    match bytes {
        [0xEF, 0xBB, 0xBF, rest @ ..] => decode_utf8(rest),
        [0xFF, 0xFE, rest @ ..] => decode_utf16(rest, u16::from_le_bytes),
        [0xFE, 0xFF, rest @ ..] => decode_utf16(rest, u16::from_be_bytes),
        [first, 0, ..] if *first != 0 => decode_utf16(bytes, u16::from_le_bytes),
        [0, second, ..] if *second != 0 => decode_utf16(bytes, u16::from_be_bytes),
        _ => decode_utf8(bytes),
    }
}

fn decode_utf8(bytes: &[u8]) -> Result<String, PassphraseError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| PassphraseError("not valid UTF-8 or UTF-16 text".into()))
}

fn decode_utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Result<String, PassphraseError> {
    // A line read up to b'\n' from UTF-16 stops before the newline's NUL byte.
    let bytes = match bytes {
        [head @ .., b'\n'] if bytes.len() % 2 == 1 => head,
        _ => bytes,
    };
    let (pairs, odd) = bytes.as_chunks::<2>();
    if !odd.is_empty() {
        return Err(PassphraseError("not valid UTF-16 text".into()));
    }
    char::decode_utf16(pairs.iter().map(|pair| unit(*pair)))
        .collect::<Result<String, _>>()
        .map_err(|_| PassphraseError("not valid UTF-16 text".into()))
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// `passphrase -> 32-byte backup key` (`FullBackupBase.getBackupKey`).
///
/// Spaces are stripped (the UI shows the 30 digits in groups), then SHA-512 is
/// iterated `DIGEST_ROUNDS` times. Round 0 absorbs `salt || input || input`; every
/// later round absorbs `previous_hash || input`. The first 32 bytes are the key.
fn derive_backup_key(passphrase: &str, salt: Option<&[u8]>) -> [u8; KEY_LEN] {
    let input: Vec<u8> = passphrase.bytes().filter(|&b| b != b' ').collect();
    let mut hash: Vec<u8> = input.clone();

    for round in 0..DIGEST_ROUNDS {
        let mut digest = Sha512::new();
        if round == 0 {
            if let Some(s) = salt {
                digest.update(s);
            }
        }
        digest.update(&hash);
        digest.update(&input);
        hash = digest.finalize().to_vec();
    }

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&hash[..KEY_LEN]);
    key
}

/// `backup key -> (cipherKey, macKey)` via `HKDF-SHA256(salt = none, info)`.
fn split_keys(backup_key: &[u8]) -> Result<([u8; KEY_LEN], [u8; KEY_LEN]), BackupError> {
    let hkdf = Hkdf::<Sha256>::new(None, backup_key);
    let mut okm = [0u8; KEY_LEN * 2];
    hkdf.expand(HKDF_INFO, &mut okm)
        .map_err(|_| format_err("HKDF expand failed"))?;

    let mut cipher_key = [0u8; KEY_LEN];
    let mut mac_key = [0u8; KEY_LEN];
    cipher_key.copy_from_slice(&okm[..KEY_LEN]);
    mac_key.copy_from_slice(&okm[KEY_LEN..]);
    Ok((cipher_key, mac_key))
}

/// Fresh AES-256-CTR instance for one encrypted unit.
fn new_cipher(cipher_key: &[u8; KEY_LEN], iv: &[u8; IV_LEN]) -> Aes256Ctr {
    Aes256Ctr::new(cipher_key.into(), iv.into())
}

/// Fresh HMAC-SHA256 instance (the key length is always valid for HMAC).
fn new_mac(mac_key: &[u8; KEY_LEN]) -> HmacSha256 {
    HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key length")
}

/// Whether the 4-byte frame length is itself CTR-encrypted (version >= 1).
fn frame_length_encrypted(version: u32) -> bool {
    version >= 1
}

// ---------------------------------------------------------------------------
// Minimal proto2 reader (only the wire types BackupFrame actually uses)
// ---------------------------------------------------------------------------

mod proto {
    use super::{format_err, BackupError};

    /// A single protobuf field value, borrowed from the frame buffer.
    #[derive(Clone, Copy)]
    pub enum Wire<'a> {
        /// Wire type 0 (varint): used for uint32/uint64/bool.
        Varint(u64),
        /// Wire type 1 (64-bit): used for `double`.
        Fixed64(u64),
        /// Wire type 5 (32-bit): used for `float`. No field we read is a float, but
        /// the 4 bytes must still be consumed to stay aligned, so the value is dropped.
        Fixed32,
        /// Wire type 2 (length-delimited): string/bytes/embedded message.
        Len(&'a [u8]),
    }

    /// Decodes a base-128 varint, returning `(value, bytes_consumed)`.
    pub fn read_varint(buf: &[u8], start: usize) -> Option<(u64, usize)> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        let mut pos = start;
        loop {
            let byte = *buf.get(pos)?;
            pos += 1;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some((result, pos - start));
            }
            shift += 7;
            if shift >= 64 {
                return None; // malformed / overlong varint
            }
        }
    }

    /// Walks the fields of one protobuf message in wire order.
    pub struct FieldReader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> FieldReader<'a> {
        pub fn new(buf: &'a [u8]) -> Self {
            FieldReader { buf, pos: 0 }
        }

        /// Returns the next `(field_number, value)` or `None` at end of message.
        pub fn next_field(&mut self) -> Result<Option<(u32, Wire<'a>)>, BackupError> {
            if self.pos >= self.buf.len() {
                return Ok(None);
            }

            let (tag, used) =
                read_varint(self.buf, self.pos).ok_or_else(|| format_err("bad field tag"))?;
            self.pos += used;

            let field = (tag >> 3) as u32;
            let wire_type = (tag & 0x7) as u8;

            let value = match wire_type {
                0 => {
                    let (v, used) = read_varint(self.buf, self.pos)
                        .ok_or_else(|| format_err("bad varint value"))?;
                    self.pos += used;
                    Wire::Varint(v)
                }
                1 => {
                    let b = self.take(8)?;
                    Wire::Fixed64(u64::from_le_bytes(b.try_into().unwrap()))
                }
                5 => {
                    let _ = self.take(4)?; // consume the 4 bytes; the value is unused
                    Wire::Fixed32
                }
                2 => {
                    let (len, used) = read_varint(self.buf, self.pos)
                        .ok_or_else(|| format_err("bad length prefix"))?;
                    self.pos += used;
                    Wire::Len(self.take(len as usize)?)
                }
                other => {
                    return Err(format_err(format!("unsupported wire type {other}")));
                }
            };

            Ok(Some((field, value)))
        }

        /// Borrows the next `n` bytes, erroring if the message is truncated.
        fn take(&mut self, n: usize) -> Result<&'a [u8], BackupError> {
            let end = self
                .pos
                .checked_add(n)
                .ok_or_else(|| format_err("field length overflow"))?;
            let slice = self
                .buf
                .get(self.pos..end)
                .ok_or_else(|| format_err("truncated field"))?;
            self.pos = end;
            Ok(slice)
        }
    }
}

use proto::{FieldReader, Wire};

// ---------------------------------------------------------------------------
// Decoded frame model (only what we need; other frames collapse to `Other`)
// ---------------------------------------------------------------------------

/// The plaintext header carried by the first (unencrypted) frame.
struct Header {
    iv: [u8; IV_LEN],
    salt: Vec<u8>,
    version: u32,
}

/// One bound parameter of a `SqlStatement`.
enum Param {
    Str(String),
    Int(i64),
    Double(f64),
    Blob(Vec<u8>),
    Null,
}

/// A `SqlStatement` frame: SQL text plus its bound parameters.
struct Statement {
    sql: Option<String>,
    params: Vec<Param>,
}

/// A decoded `BackupFrame`, reduced to the cases that drive the rebuild.
enum Frame {
    /// The header frame (only expected once, at the very start).
    Header(Header),
    /// A SQL statement to replay.
    Statement(Statement),
    /// A `DatabaseVersion` frame (schema version).
    DatabaseVersion(u32),
    /// An attachment/avatar/sticker frame — a binary blob of `length` bytes
    /// follows it in the stream and must be consumed.
    Blob { length: u32 },
    /// The terminating `end = true` frame.
    End,
    /// A frame we do not act on (preference, keyValue, unknown).
    Other,
}

/// Decodes a `Header` message body (`Backups.proto:56-60`).
fn decode_header(buf: &[u8]) -> Result<Header, BackupError> {
    let mut iv: Option<Vec<u8>> = None;
    let mut salt: Vec<u8> = Vec::new();
    let mut version = 0u32;

    let mut reader = FieldReader::new(buf);
    while let Some((field, value)) = reader.next_field()? {
        match (field, value) {
            (1, Wire::Len(b)) => iv = Some(b.to_vec()),
            (2, Wire::Len(b)) => salt = b.to_vec(),
            (3, Wire::Varint(v)) => version = v as u32,
            _ => {}
        }
    }

    let iv = iv.ok_or_else(|| format_err("header is missing the IV"))?;
    let iv: [u8; IV_LEN] = iv
        .as_slice()
        .try_into()
        .map_err(|_| format_err("header IV is not 16 bytes"))?;
    Ok(Header { iv, salt, version })
}

/// Decodes one `SqlStatement.SqlParameter` (`Backups.proto:14-20`). The first set
/// field wins, mirroring the exporter, which sets exactly one per parameter.
fn decode_param(buf: &[u8]) -> Result<Param, BackupError> {
    let mut reader = FieldReader::new(buf);
    while let Some((field, value)) = reader.next_field()? {
        match (field, value) {
            (1, Wire::Len(b)) => return Ok(Param::Str(String::from_utf8_lossy(b).into_owned())),
            (2, Wire::Varint(v)) => return Ok(Param::Int(v as i64)),
            (3, Wire::Fixed64(v)) => return Ok(Param::Double(f64::from_bits(v))),
            (4, Wire::Len(b)) => return Ok(Param::Blob(b.to_vec())),
            (5, Wire::Varint(_)) => return Ok(Param::Null),
            _ => {}
        }
    }
    Ok(Param::Null)
}

/// Decodes a `SqlStatement` message body (`Backups.proto:13-24`).
fn decode_statement(buf: &[u8]) -> Result<Statement, BackupError> {
    let mut sql = None;
    let mut params = Vec::new();

    let mut reader = FieldReader::new(buf);
    while let Some((field, value)) = reader.next_field()? {
        match (field, value) {
            (1, Wire::Len(b)) => sql = Some(String::from_utf8_lossy(b).into_owned()),
            (2, Wire::Len(b)) => params.push(decode_param(b)?),
            _ => {}
        }
    }

    Ok(Statement { sql, params })
}

/// Reads a single `uint32` field (`target`) out of an embedded message, used to
/// pull the `length` out of an Attachment/Avatar/Sticker frame.
fn message_u32_field(buf: &[u8], target: u32) -> Result<u32, BackupError> {
    let mut reader = FieldReader::new(buf);
    while let Some((field, value)) = reader.next_field()? {
        if field == target {
            if let Wire::Varint(v) = value {
                return Ok(v as u32);
            }
        }
    }
    Ok(0) // a missing length means a zero-byte blob
}

/// Decodes a top-level `BackupFrame` (`Backups.proto:72-82`). Exactly one field is
/// set, so the first recognized one determines the frame kind.
fn decode_frame(buf: &[u8]) -> Result<Frame, BackupError> {
    let mut reader = FieldReader::new(buf);
    while let Some((field, value)) = reader.next_field()? {
        match (field, value) {
            (1, Wire::Len(b)) => return Ok(Frame::Header(decode_header(b)?)),
            (2, Wire::Len(b)) => return Ok(Frame::Statement(decode_statement(b)?)),
            // Attachment.length is field 3; a blob follows the frame.
            (4, Wire::Len(b)) => {
                return Ok(Frame::Blob {
                    length: message_u32_field(b, 3)?,
                })
            }
            // DatabaseVersion.version is field 1.
            (5, Wire::Len(b)) => return Ok(Frame::DatabaseVersion(message_u32_field(b, 1)?)),
            (6, Wire::Varint(v)) => {
                return Ok(if v != 0 { Frame::End } else { Frame::Other });
            }
            // Avatar.length and Sticker.length are both field 2; a blob follows.
            (7, Wire::Len(b)) | (8, Wire::Len(b)) => {
                return Ok(Frame::Blob {
                    length: message_u32_field(b, 2)?,
                })
            }
            // preference (3) and keyValue (9): no trailing blob, nothing to do.
            (3, _) | (9, _) => return Ok(Frame::Other),
            _ => {}
        }
    }
    Ok(Frame::Other)
}

// ---------------------------------------------------------------------------
// Streaming frame decryptor
// ---------------------------------------------------------------------------

/// Reads and decrypts frames from a backup stream one at a time, mirroring
/// `BackupRecordInputStream`. Attachments are streamed past (never buffered), so
/// a multi-gigabyte backup rebuilds its database without loading the blobs.
struct FrameStream<R: Read> {
    reader: R,
    cipher_key: [u8; KEY_LEN],
    mac_key: [u8; KEY_LEN],
    /// The header IV; bytes 0..4 are replaced per unit with the running counter.
    base_iv: [u8; IV_LEN],
    version: u32,
    counter: u32,
}

impl<R: Read> FrameStream<R> {
    /// Reads the plaintext header, derives the keys, and primes the counter.
    fn open(mut reader: R, passphrase: &str) -> Result<Self, BackupError> {
        let header_len = read_u32_be(&mut reader)? as usize;
        if header_len == 0 || header_len > MAX_HEADER_LEN {
            return Err(format_err(format!("implausible header length {header_len}")));
        }
        let header_buf = read_exact_vec(&mut reader, header_len)?;

        let header = match decode_frame(&header_buf)? {
            Frame::Header(h) => h,
            _ => return Err(format_err("backup does not start with a header frame")),
        };

        if !(MINIMUM_VERSION..=CURRENT_VERSION).contains(&header.version) {
            return Err(BackupError::UnsupportedVersion(header.version));
        }

        let salt = if header.salt.is_empty() {
            None
        } else {
            Some(header.salt.as_slice())
        };
        let backup_key = derive_backup_key(passphrase, salt);
        let (cipher_key, mac_key) = split_keys(&backup_key)?;
        let counter = u32::from_be_bytes(header.iv[..4].try_into().unwrap());

        Ok(FrameStream {
            reader,
            cipher_key,
            mac_key,
            base_iv: header.iv,
            version: header.version,
            counter,
        })
    }

    /// Builds the IV for the next encrypted unit and advances the counter. The
    /// counter overwrites the high 4 IV bytes big-endian and wraps like a Java int.
    fn next_iv(&mut self) -> [u8; IV_LEN] {
        let mut iv = self.base_iv;
        iv[..4].copy_from_slice(&self.counter.to_be_bytes());
        self.counter = self.counter.wrapping_add(1);
        iv
    }

    /// Reads, verifies, and decrypts the next frame. Returns `None` once the
    /// stream is cleanly exhausted. Attachment blobs are consumed here so the
    /// caller only ever sees frames.
    fn next_frame(&mut self) -> Result<Option<Frame>, BackupError> {
        let mut length_bytes = [0u8; 4];
        match self.reader.read_exact(&mut length_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let iv = self.next_iv();
        let mut cipher = new_cipher(&self.cipher_key, &iv);
        let mut mac = new_mac(&self.mac_key);

        let frame_len = if frame_length_encrypted(self.version) {
            mac.update(&length_bytes);
            let mut decrypted = length_bytes;
            cipher.apply_keystream(&mut decrypted);
            u32::from_be_bytes(decrypted) as usize
        } else {
            u32::from_be_bytes(length_bytes) as usize
        };

        if !(MAC_LEN..=MAX_FRAME_LEN).contains(&frame_len) {
            // Garbage length is the first sign of a wrong passphrase.
            return Err(BackupError::WrongPassphrase);
        }

        let mut frame = read_exact_vec(&mut self.reader, frame_len)?;
        let body_len = frame_len - MAC_LEN;

        mac.update(&frame[..body_len]);
        let computed = mac.finalize().into_bytes();
        if computed[..MAC_LEN] != frame[body_len..] {
            return Err(BackupError::WrongPassphrase);
        }

        cipher.apply_keystream(&mut frame[..body_len]);
        let decoded = decode_frame(&frame[..body_len])?;

        if let Frame::Blob { length } = decoded {
            self.skip_blob(length as usize)?;
        }

        Ok(Some(decoded))
    }

    /// Consumes an attachment/avatar/sticker blob: advance the counter (the writer
    /// does `counter++` before each blob) and discard `length + 10` bytes. We do
    /// not decrypt or MAC-check discarded blobs, but the counter bump is mandatory
    /// — without it every frame after the first attachment would fail to decrypt.
    fn skip_blob(&mut self, length: usize) -> Result<(), BackupError> {
        let _iv = self.next_iv();
        let total = length as u64 + MAC_LEN as u64;
        let discarded = io::copy(&mut (&mut self.reader).take(total), &mut io::sink())?;
        if discarded != total {
            return Err(format_err("attachment blob ended early"));
        }
        Ok(())
    }
}

/// Reads a big-endian `u32` from the stream.
fn read_u32_be<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Reads exactly `n` bytes into a fresh buffer.
fn read_exact_vec<R: Read>(reader: &mut R, n: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Database rebuild
// ---------------------------------------------------------------------------

/// Statements the Signal importer deliberately does not replay
/// (`FullBackupImporter.processStatement`): FTS5 shadow tables (which the virtual
/// table recreates itself), the internal `sqlite_*` tables, and volatile rows.
fn should_skip(sql: &str) -> bool {
    let lower = sql.to_ascii_lowercase();
    sql.contains("message_fts_")
        || sql.contains("emoji_search_")
        || lower.starts_with("create table sqlite_")
        || lower.starts_with("insert into remote_megaphone")
}

/// Executes one statement with its bound parameters against the rebuilt database.
fn run_statement(conn: &Connection, sql: &str, params: &[Param]) -> rusqlite::Result<()> {
    use rusqlite::types::Value;

    let values: Vec<Value> = params
        .iter()
        .map(|p| match p {
            Param::Str(s) => Value::Text(s.clone()),
            Param::Int(i) => Value::Integer(*i),
            Param::Double(d) => Value::Real(*d),
            Param::Blob(b) => Value::Blob(b.clone()),
            Param::Null => Value::Null,
        })
        .collect();

    conn.execute(sql, rusqlite::params_from_iter(values.iter()))?;
    Ok(())
}

/// Truncates a statement for a warning message so a huge INSERT does not flood logs.
fn truncate_sql(sql: &str) -> String {
    const MAX: usize = 120;
    if sql.len() <= MAX {
        sql.to_string()
    } else {
        format!("{}...", &sql[..MAX])
    }
}

/// Decrypts a Signal Android `.backup` from `reader` and rebuilds its database
/// into a plaintext SQLite image, replaying statements the way Signal's importer
/// does. Nothing is written to disk; the image lives only in the returned `Vec`.
pub fn rebuild_to_image<R: Read>(
    reader: R,
    passphrase: &Passphrase,
) -> Result<RebuildOutcome, BackupError> {
    let mut stream = FrameStream::open(reader, passphrase.digits())?;

    let mut conn = Connection::open_in_memory()?;
    // Foreign keys off while we recreate the schema out of dependency order, and
    // non-durable pragmas since this database never touches disk.
    conn.execute_batch(
        "PRAGMA foreign_keys = OFF; PRAGMA journal_mode = MEMORY; PRAGMA synchronous = OFF;",
    )?;
    conn.execute_batch("BEGIN")?;

    let mut outcome = RebuildOutcome {
        image: Vec::new(),
        frames: 0,
        statements_run: 0,
        statements_skipped: 0,
        warnings: Vec::new(),
    };

    let mut first = true;
    loop {
        let frame = match stream.next_frame() {
            Ok(Some(frame)) => frame,
            Ok(None) => break, // stream ended (tolerated even without an End frame)
            // The very first encrypted frame failing is the wrong-passphrase case.
            Err(BackupError::WrongPassphrase) => return Err(BackupError::WrongPassphrase),
            Err(e) if first => return Err(e),
            Err(e) => return Err(e),
        };
        first = false;
        outcome.frames += 1;

        match frame {
            Frame::Statement(stmt) => {
                let Some(sql) = stmt.sql.as_deref() else {
                    continue;
                };
                if should_skip(sql) {
                    outcome.statements_skipped += 1;
                } else if let Err(e) = run_statement(&conn, sql, &stmt.params) {
                    outcome
                        .warnings
                        .push(format!("statement failed ({e}): {}", truncate_sql(sql)));
                } else {
                    outcome.statements_run += 1;
                }
            }
            Frame::DatabaseVersion(v) => {
                let _ = conn.pragma_update(None, "user_version", v as i64);
            }
            Frame::End => break,
            Frame::Blob { .. } | Frame::Other | Frame::Header(_) => {}
        }
    }

    conn.execute_batch("COMMIT")?;
    outcome.image = conn.serialize(MAIN_DB)?.to_vec();
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Golden key-derivation vectors, generated by an INDEPENDENT Python reference
    // (stdlib hashlib/hmac) — not by this code — so a bug symmetric in both our
    // writer and reader cannot hide behind a round-trip test. Passphrase is a
    // 30-digit code grouped like Signal's UI; salt is 0x00..0x1f.
    const GOLDEN_PASSPHRASE: &str = "12345 67890 12345 67890 12345 67890";
    const GOLDEN_SALT: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const GOLDEN_BACKUP_KEY: &str =
        "b8bf308eddb216d1c606fe0192b5d91f93b4bbd76e3b4954d72de8f443e76f10";
    const GOLDEN_CIPHER_KEY: &str =
        "bca8e1dc9cc9f2d7bd1dc3fe1018633019cabf7bb810bbcecb0b4a92018d4ec7";
    const GOLDEN_MAC_KEY: &str =
        "e5943bd4bb63eb518263b841a5a86f68cec871093ff4055773345934a8cb5f4c";

    #[test]
    fn key_derivation_matches_independent_golden_vectors() {
        let key = derive_backup_key(GOLDEN_PASSPHRASE, Some(&GOLDEN_SALT));
        assert_eq!(hex::encode(key), GOLDEN_BACKUP_KEY, "backup key mismatch");

        let (cipher_key, mac_key) = split_keys(&key).unwrap();
        assert_eq!(hex::encode(cipher_key), GOLDEN_CIPHER_KEY, "cipherKey mismatch");
        assert_eq!(hex::encode(mac_key), GOLDEN_MAC_KEY, "macKey mismatch");
    }

    // --- the passphrase as users actually supply it ---------------------------

    const DIGITS: &str = "123456789012345678901234567890";

    fn utf16(text: &str, little_endian: bool, bom: bool) -> Vec<u8> {
        let mut out = Vec::new();
        if bom {
            out.extend_from_slice(if little_endian { &[0xFF, 0xFE] } else { &[0xFE, 0xFF] });
        }
        for unit in text.encode_utf16() {
            out.extend_from_slice(&if little_endian { unit.to_le_bytes() } else { unit.to_be_bytes() });
        }
        out
    }

    #[test]
    fn passphrase_accepts_the_forms_signal_shows_and_editors_write() {
        for text in [GOLDEN_PASSPHRASE, DIGITS, "12345\t67890 12345\n67890 12345 67890\r\n"] {
            assert_eq!(Passphrase::parse(text).unwrap().digits(), DIGITS, "{text:?}");
        }
        let spaced = format!("{GOLDEN_PASSPHRASE}\r\n");
        let encodings: [(&str, Vec<u8>); 5] = [
            ("utf-8", spaced.as_bytes().to_vec()),
            ("utf-8 with BOM", [&[0xEF, 0xBB, 0xBF][..], spaced.as_bytes()].concat()),
            ("utf-16le with BOM (PowerShell 5.1 `>`)", utf16(&spaced, true, true)),
            ("utf-16be with BOM", utf16(&spaced, false, true)),
            ("utf-16le without BOM", utf16(&spaced, true, false)),
        ];
        for (label, bytes) in encodings {
            assert_eq!(Passphrase::from_bytes(&bytes).unwrap().digits(), DIGITS, "{label}");
        }
        // A line read from UTF-16 stdin stops at the 0x0A byte, before its 0x00.
        let mut line = utf16(&spaced, true, true);
        line.pop();
        assert_eq!(Passphrase::from_bytes(&line).unwrap().digits(), DIGITS, "utf-16le line");
    }

    #[test]
    fn passphrase_rejects_anything_but_thirty_ascii_digits() {
        let full_width: String = DIGITS.chars().map(|c| char::from_u32(c as u32 - '0' as u32 + 0xFF10).unwrap()).collect();
        for bad in ["12345 67890", &format!("{DIGITS}1"), "12345-67890-12345-67890-12345-67890", "", full_width.as_str()] {
            let err = Passphrase::parse(bad).err().unwrap_or_else(|| panic!("{bad:?} must be rejected"));
            assert!(err.to_string().contains("30 digits"), "{err}");
            assert!(bad.len() < 5 || !err.to_string().contains(bad), "the passphrase must never be printed: {err}");
        }
        assert!(Passphrase::from_bytes(&[0xC3, 0x28]).is_err(), "invalid UTF-8");
    }

    #[test]
    fn spaces_in_the_passphrase_are_ignored() {
        let spaced = derive_backup_key(GOLDEN_PASSPHRASE, Some(&GOLDEN_SALT));
        let packed = derive_backup_key("123456789012345678901234567890", Some(&GOLDEN_SALT));
        assert_eq!(spaced, packed);
    }

    // --- A faithful in-test backup writer (mirrors BackupFrameOutputStream) -----

    /// Minimal proto2 encoder helpers (only the wire types we emit).
    mod encode {
        fn varint(out: &mut Vec<u8>, mut v: u64) {
            loop {
                let mut byte = (v & 0x7f) as u8;
                v >>= 7;
                if v != 0 {
                    byte |= 0x80;
                }
                out.push(byte);
                if v == 0 {
                    break;
                }
            }
        }

        fn tag(out: &mut Vec<u8>, field: u32, wire: u8) {
            varint(out, ((field as u64) << 3) | wire as u64);
        }

        pub fn varint_field(out: &mut Vec<u8>, field: u32, v: u64) {
            tag(out, field, 0);
            varint(out, v);
        }

        pub fn fixed64_field(out: &mut Vec<u8>, field: u32, v: u64) {
            tag(out, field, 1);
            out.extend_from_slice(&v.to_le_bytes());
        }

        pub fn len_field(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
            tag(out, field, 2);
            varint(out, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }

        pub fn string_field(out: &mut Vec<u8>, field: u32, s: &str) {
            len_field(out, field, s.as_bytes());
        }
    }

    /// Mirror of `Param` used to drive the test writer.
    enum TestParam {
        Str(&'static str),
        Int(i64),
        Double(f64),
        Blob(Vec<u8>),
        Null,
    }

    /// Builds a byte-exact Signal Android backup in memory for round-trip tests.
    struct TestWriter {
        out: Vec<u8>,
        cipher_key: [u8; KEY_LEN],
        mac_key: [u8; KEY_LEN],
        base_iv: [u8; IV_LEN],
        counter: u32,
    }

    impl TestWriter {
        fn new(passphrase: &str) -> Self {
            // Deterministic IV/salt so tests are reproducible.
            let base_iv: [u8; IV_LEN] = [
                0x00, 0x00, 0x00, 0x05, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                0x07, 0x08,
            ];
            let backup_key = derive_backup_key(passphrase, Some(&GOLDEN_SALT));
            let (cipher_key, mac_key) = split_keys(&backup_key).unwrap();
            let counter = u32::from_be_bytes(base_iv[..4].try_into().unwrap());

            // Header frame: BackupFrame { header { iv, salt, version = 1 } }, plaintext.
            let mut header_msg = Vec::new();
            encode::len_field(&mut header_msg, 1, &base_iv);
            encode::len_field(&mut header_msg, 2, &GOLDEN_SALT);
            encode::varint_field(&mut header_msg, 3, CURRENT_VERSION as u64);
            let mut header_frame = Vec::new();
            encode::len_field(&mut header_frame, 1, &header_msg);

            let mut out = Vec::new();
            out.extend_from_slice(&(header_frame.len() as u32).to_be_bytes());
            out.extend_from_slice(&header_frame);

            TestWriter {
                out,
                cipher_key,
                mac_key,
                base_iv,
                counter,
            }
        }

        fn next_iv(&mut self) -> [u8; IV_LEN] {
            let mut iv = self.base_iv;
            iv[..4].copy_from_slice(&self.counter.to_be_bytes());
            self.counter = self.counter.wrapping_add(1);
            iv
        }

        /// Encrypts and appends one frame exactly as `BackupFrameOutputStream.write`.
        fn write_frame(&mut self, frame: &[u8]) {
            let iv = self.next_iv();
            let mut cipher = new_cipher(&self.cipher_key, &iv);
            let mut mac = new_mac(&self.mac_key);

            let mut length = ((frame.len() + MAC_LEN) as u32).to_be_bytes();
            cipher.apply_keystream(&mut length); // version 1: length is encrypted
            mac.update(&length);

            let mut ciphertext = frame.to_vec();
            cipher.apply_keystream(&mut ciphertext);
            mac.update(&ciphertext);

            let tag = mac.finalize().into_bytes();
            self.out.extend_from_slice(&length);
            self.out.extend_from_slice(&ciphertext);
            self.out.extend_from_slice(&tag[..MAC_LEN]);
        }

        /// Appends a raw attachment blob exactly as `writeStream`.
        fn write_blob(&mut self, data: &[u8]) {
            let iv = self.next_iv();
            let mut cipher = new_cipher(&self.cipher_key, &iv);
            let mut mac = new_mac(&self.mac_key);
            mac.update(&iv);

            let mut ciphertext = data.to_vec();
            cipher.apply_keystream(&mut ciphertext);
            mac.update(&ciphertext);

            let tag = mac.finalize().into_bytes();
            self.out.extend_from_slice(&ciphertext);
            self.out.extend_from_slice(&tag[..MAC_LEN]);
        }

        fn statement(&mut self, sql: &str, params: &[TestParam]) {
            let mut stmt = Vec::new();
            encode::string_field(&mut stmt, 1, sql);
            for p in params {
                let mut param = Vec::new();
                match p {
                    TestParam::Str(s) => encode::string_field(&mut param, 1, s),
                    TestParam::Int(i) => encode::varint_field(&mut param, 2, *i as u64),
                    TestParam::Double(d) => encode::fixed64_field(&mut param, 3, d.to_bits()),
                    TestParam::Blob(b) => encode::len_field(&mut param, 4, b),
                    TestParam::Null => encode::varint_field(&mut param, 5, 1),
                }
                encode::len_field(&mut stmt, 2, &param);
            }
            let mut frame = Vec::new();
            encode::len_field(&mut frame, 2, &stmt); // BackupFrame.statement = field 2
            self.write_frame(&frame);
        }

        /// Writes an Attachment frame followed by its blob (the counter footgun).
        fn attachment(&mut self, row_id: u64, data: &[u8]) {
            let mut attachment = Vec::new();
            encode::varint_field(&mut attachment, 1, row_id); // rowId
            encode::varint_field(&mut attachment, 3, data.len() as u64); // length
            let mut frame = Vec::new();
            encode::len_field(&mut frame, 4, &attachment); // BackupFrame.attachment = field 4
            self.write_frame(&frame);
            self.write_blob(data);
        }

        fn version(&mut self, v: u32) {
            let mut dbv = Vec::new();
            encode::varint_field(&mut dbv, 1, v as u64);
            let mut frame = Vec::new();
            encode::len_field(&mut frame, 5, &dbv); // BackupFrame.version = field 5
            self.write_frame(&frame);
        }

        fn end(&mut self) {
            let mut frame = Vec::new();
            encode::varint_field(&mut frame, 6, 1); // BackupFrame.end = true
            self.write_frame(&frame);
        }

        fn finish(self) -> Vec<u8> {
            self.out
        }
    }

    /// Opens a serialized SQLite image by writing it to a temp file (test only).
    fn open_image(image: &[u8]) -> Connection {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Tests run in parallel and their images can share a length: number each file.
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "android_backup_test_{}_{}.sqlite",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, image).unwrap();
        let conn = Connection::open(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        conn
    }

    #[test]
    fn roundtrip_rebuilds_a_queryable_database() {
        let mut w = TestWriter::new(GOLDEN_PASSPHRASE);
        w.statement(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, score REAL, data BLOB)",
            &[],
        );
        w.statement(
            "INSERT INTO items (id, name, score, data) VALUES (?, ?, ?, ?)",
            &[
                TestParam::Int(1),
                TestParam::Str("alpha"),
                TestParam::Double(1.5),
                TestParam::Blob(vec![0xde, 0xad, 0xbe, 0xef]),
            ],
        );
        // An attachment frame + blob in the MIDDLE: if the per-blob counter bump is
        // wrong, every frame after this fails to decrypt (the format's footgun).
        w.attachment(99, &[0xAB; 50]);
        w.statement(
            "INSERT INTO items (id, name, score, data) VALUES (?, ?, ?, ?)",
            &[
                TestParam::Int(2),
                TestParam::Str("beta"),
                TestParam::Null,
                TestParam::Null,
            ],
        );
        w.version(42);
        w.end();
        let bytes = w.finish();

        let outcome = rebuild_to_image(&bytes[..], &Passphrase::parse(GOLDEN_PASSPHRASE).unwrap()).unwrap();
        assert!(outcome.warnings.is_empty(), "warnings: {:?}", outcome.warnings);
        assert_eq!(outcome.statements_run, 3, "CREATE + two INSERTs should run");

        let conn = open_image(&outcome.image);
        let names: Vec<String> = conn
            .prepare("SELECT name FROM items ORDER BY id")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        // "beta" appearing proves the frame AFTER the attachment blob decrypted.
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);

        let score: f64 = conn
            .query_row("SELECT score FROM items WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(score, 1.5);
        let blob: Vec<u8> = conn
            .query_row("SELECT data FROM items WHERE id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(blob, vec![0xde, 0xad, 0xbe, 0xef]);
        let user_version: i64 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(user_version, 42);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let mut w = TestWriter::new(GOLDEN_PASSPHRASE);
        w.statement("CREATE TABLE t (x INTEGER)", &[]);
        w.end();
        let bytes = w.finish();

        let err = rebuild_to_image(&bytes[..], &Passphrase::parse("99999 99999 99999 99999 99999 99999").unwrap()).unwrap_err();
        assert!(
            matches!(err, BackupError::WrongPassphrase),
            "expected WrongPassphrase, got {err:?}"
        );
    }

    #[test]
    fn fts_shadow_and_sqlite_internal_statements_are_skipped() {
        let mut w = TestWriter::new(GOLDEN_PASSPHRASE);
        w.statement("CREATE TABLE message (id INTEGER PRIMARY KEY, body TEXT)", &[]);
        // These mirror what Signal's exporter emits and its importer skips.
        w.statement("CREATE TABLE 'message_fts_data'(id INTEGER PRIMARY KEY, block BLOB)", &[]);
        w.statement("CREATE TABLE sqlite_sequence(name, seq)", &[]);
        w.statement(
            "INSERT INTO remote_megaphone VALUES (1)",
            &[],
        );
        w.end();
        let bytes = w.finish();

        let outcome = rebuild_to_image(&bytes[..], &Passphrase::parse(GOLDEN_PASSPHRASE).unwrap()).unwrap();
        assert_eq!(outcome.statements_run, 1, "only the real CREATE should run");
        assert_eq!(outcome.statements_skipped, 3, "three statements should be skipped");
    }

    /// Writes a committed `.backup` fixture for the binary-level CLI tests. Run on
    /// demand (it is `#[ignore]`d) with:
    ///   `cargo test --features sqlite -p SignalDecryption --lib -- --ignored generate_cli_fixture`
    /// The fixture's passphrase and rows are mirrored in `tests/cli_e2e.rs`.
    #[test]
    #[ignore = "regenerates a committed fixture; run explicitly"]
    fn generate_cli_fixture() {
        const FIXTURE_PASSPHRASE: &str = "11111 22222 33333 44444 55555 66666";
        let mut w = TestWriter::new(FIXTURE_PASSPHRASE);
        w.statement(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)",
            &[],
        );
        for (id, name) in [(1, "alpha"), (2, "beta"), (3, "gamma")] {
            w.statement(
                "INSERT INTO items (id, name) VALUES (?, ?)",
                &[TestParam::Int(id), TestParam::Str(name)],
            );
        }
        // An attachment blob between rows exercises the counter footgun end to end.
        w.attachment(7, &[0xCD; 32]);
        w.statement(
            "INSERT INTO items (id, name) VALUES (?, ?)",
            &[TestParam::Int(4), TestParam::Str("delta")],
        );
        w.version(1);
        w.end();
        let bytes = w.finish();

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/testdata/android.backup");
        std::fs::write(path, &bytes).unwrap();
        eprintln!("wrote {} bytes to {path}", bytes.len());
    }

    #[test]
    fn a_failing_statement_warns_but_does_not_abort() {
        let mut w = TestWriter::new(GOLDEN_PASSPHRASE);
        w.statement("CREATE TABLE ok (x INTEGER)", &[]);
        w.statement("THIS IS NOT VALID SQL", &[]);
        w.statement("INSERT INTO ok (x) VALUES (?)", &[TestParam::Int(7)]);
        w.end();
        let bytes = w.finish();

        let outcome = rebuild_to_image(&bytes[..], &Passphrase::parse(GOLDEN_PASSPHRASE).unwrap()).unwrap();
        assert_eq!(outcome.warnings.len(), 1, "the bad statement should warn");
        assert_eq!(outcome.statements_run, 2, "the good statements still run");

        let conn = open_image(&outcome.image);
        let x: i64 = conn.query_row("SELECT x FROM ok", [], |r| r.get(0)).unwrap();
        assert_eq!(x, 7);
    }
}
