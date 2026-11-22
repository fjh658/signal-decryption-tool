//! SQLCipher crypto provider on RustCrypto, installed with
//! `SQLCIPHER_CRYPTO_CUSTOM=sqlcipher_custom_crypto_setup`: AES-256-CBC, HMAC
//! and PBKDF2 over SHA-1/256/512, and the OS random generator. `aes` and `sha2`
//! choose AES-NI / ARMv8 AES and AVX2 / ARMv8 SHA-512 at run time where the OS
//! lets them detect it (not on Windows on ARM, which falls back to software).
//!
//! The layout and contract follow `struct sqlcipher_provider` in SQLCipher
//! 4.20's sqlcipher.h and its CommonCrypto provider (crypto_cc.c). Nothing here
//! keeps state: SQLCipher passes the key with every call.

#![cfg_attr(not(test), no_std)]

use core::ffi::{c_char, c_int, c_uchar, c_void, CStr};
use core::{ptr, slice};

use aes::Aes256;
use cbc::cipher::array::Array;
use cbc::cipher::{Block, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

const SQLITE_OK: c_int = 0;
const SQLITE_ERROR: c_int = 1;
// sqlcipher.h; the PBKDF2 PRF ids are the same numbers.
const SQLCIPHER_HMAC_SHA1: c_int = 0;
const SQLCIPHER_HMAC_SHA256: c_int = 1;
const SQLCIPHER_HMAC_SHA512: c_int = 2;
const SQLCIPHER_ENCRYPT: c_int = 1;
const KEY_SZ: c_int = 32;
const BLOCK_SZ: usize = 16;

const PROVIDER_NAME: &CStr = c"rustcrypto";
const PROVIDER_VERSION: &CStr = c"aes 0.9, sha2 0.11, hmac 0.13, pbkdf2 0.13";
const CIPHER_NAME: &CStr = c"aes-256-cbc";

type Ctx = *mut c_void;

/// `struct sqlcipher_provider`, field for field.
#[repr(C)]
pub struct SqlcipherProvider {
    init: Option<unsafe extern "C" fn() -> c_int>,
    shutdown: Option<unsafe extern "C" fn()>,
    get_provider_name: unsafe extern "C" fn(Ctx) -> *const c_char,
    add_random: unsafe extern "C" fn(Ctx, *const c_void, c_int) -> c_int,
    random: unsafe extern "C" fn(Ctx, *mut c_void, c_int) -> c_int,
    hmac: unsafe extern "C" fn(Ctx, c_int, *const c_uchar, c_int, *const c_uchar, c_int, *const c_uchar, c_int, *mut c_uchar) -> c_int,
    kdf: unsafe extern "C" fn(Ctx, c_int, *const c_uchar, c_int, *const c_uchar, c_int, c_int, c_int, *mut c_uchar) -> c_int,
    cipher: unsafe extern "C" fn(Ctx, c_int, *const c_uchar, c_int, *const c_uchar, *const c_uchar, c_int, *mut c_uchar) -> c_int,
    get_cipher: unsafe extern "C" fn(Ctx) -> *const c_char,
    get_key_sz: unsafe extern "C" fn(Ctx) -> c_int,
    get_iv_sz: unsafe extern "C" fn(Ctx) -> c_int,
    get_block_sz: unsafe extern "C" fn(Ctx) -> c_int,
    get_hmac_sz: unsafe extern "C" fn(Ctx, c_int) -> c_int,
    ctx_init: unsafe extern "C" fn(*mut Ctx) -> c_int,
    ctx_free: unsafe extern "C" fn(*mut Ctx) -> c_int,
    fips_status: unsafe extern "C" fn(Ctx) -> c_int,
    get_provider_version: unsafe extern "C" fn(Ctx) -> *const c_char,
    next: *mut SqlcipherProvider,
}

// SQLCipher allocates sizeof(sqlcipher_provider): 17 function pointers and `next`.
const _: () = assert!(size_of::<SqlcipherProvider>() == 18 * size_of::<usize>());

/// `n` bytes at `p`; empty for `n == 0`, `None` for a negative size or a null buffer.
unsafe fn bytes<'a>(p: *const c_uchar, n: c_int) -> Option<&'a [u8]> {
    let n = usize::try_from(n).ok()?;
    match n {
        0 => Some(&[]),
        _ if p.is_null() => None,
        _ => Some(unsafe { slice::from_raw_parts(p, n) }),
    }
}

unsafe fn bytes_mut<'a>(p: *mut c_uchar, n: c_int) -> Option<&'a mut [u8]> {
    let n = usize::try_from(n).ok()?;
    match n {
        0 => Some(&mut []),
        _ if p.is_null() => None,
        _ => Some(unsafe { slice::from_raw_parts_mut(p, n) }),
    }
}

fn status(ok: bool) -> c_int {
    if ok {
        SQLITE_OK
    } else {
        SQLITE_ERROR
    }
}

fn hmac_sz(algorithm: c_int) -> c_int {
    match algorithm {
        SQLCIPHER_HMAC_SHA1 => 20,
        SQLCIPHER_HMAC_SHA256 => 32,
        SQLCIPHER_HMAC_SHA512 => 64,
        _ => 0,
    }
}

/// HMAC of `a || b`, written to `out` (which holds the algorithm's output size).
fn mac_into<M: Mac + KeyInit>(key: &[u8], a: &[u8], b: &[u8], out: &mut [u8]) -> bool {
    let Ok(mut mac) = <M as KeyInit>::new_from_slice(key) else { return false };
    mac.update(a);
    mac.update(b);
    let tag = mac.finalize().into_bytes();
    // Never panic across the FFI boundary: a size mismatch is an error.
    if tag.len() != out.len() {
        return false;
    }
    out.copy_from_slice(&tag);
    true
}

unsafe extern "C" fn get_provider_name(_: Ctx) -> *const c_char {
    PROVIDER_NAME.as_ptr()
}

unsafe extern "C" fn get_provider_version(_: Ctx) -> *const c_char {
    PROVIDER_VERSION.as_ptr()
}

unsafe extern "C" fn get_cipher(_: Ctx) -> *const c_char {
    CIPHER_NAME.as_ptr()
}

/// The OS generator needs no extra entropy.
unsafe extern "C" fn add_random(_: Ctx, _: *const c_void, _: c_int) -> c_int {
    SQLITE_OK
}

unsafe extern "C" fn random(_: Ctx, buffer: *mut c_void, length: c_int) -> c_int {
    match unsafe { bytes_mut(buffer.cast(), length) } {
        Some(buf) => status(getrandom::fill(buf).is_ok()),
        None => SQLITE_ERROR,
    }
}

#[allow(clippy::too_many_arguments)] // the C signature
unsafe extern "C" fn hmac(
    _: Ctx,
    algorithm: c_int,
    key: *const c_uchar,
    key_sz: c_int,
    in1: *const c_uchar,
    in1_sz: c_int,
    in2: *const c_uchar,
    in2_sz: c_int,
    out: *mut c_uchar,
) -> c_int {
    // As crypto_cc.c: `in` is required, `in2` is optional.
    if in1.is_null() {
        return SQLITE_ERROR;
    }
    let in2 = if in2.is_null() { Some(&[][..]) } else { unsafe { bytes(in2, in2_sz) } };
    let (Some(key), Some(in1), Some(in2), Some(out)) =
        (unsafe { bytes(key, key_sz) }, unsafe { bytes(in1, in1_sz) }, in2, unsafe { bytes_mut(out, hmac_sz(algorithm)) })
    else {
        return SQLITE_ERROR;
    };
    status(match algorithm {
        SQLCIPHER_HMAC_SHA1 => mac_into::<Hmac<Sha1>>(key, in1, in2, out),
        SQLCIPHER_HMAC_SHA256 => mac_into::<Hmac<Sha256>>(key, in1, in2, out),
        SQLCIPHER_HMAC_SHA512 => mac_into::<Hmac<Sha512>>(key, in1, in2, out),
        _ => false,
    })
}

#[allow(clippy::too_many_arguments)] // the C signature
unsafe extern "C" fn kdf(
    _: Ctx,
    algorithm: c_int,
    pass: *const c_uchar,
    pass_sz: c_int,
    salt: *const c_uchar,
    salt_sz: c_int,
    workfactor: c_int,
    key_sz: c_int,
    key: *mut c_uchar,
) -> c_int {
    let (Some(pass), Some(salt), Some(rounds), Some(out)) = (
        unsafe { bytes(pass, pass_sz) },
        unsafe { bytes(salt, salt_sz) },
        u32::try_from(workfactor).ok().filter(|&r| r > 0),
        unsafe { bytes_mut(key, key_sz) },
    ) else {
        return SQLITE_ERROR;
    };
    match algorithm {
        SQLCIPHER_HMAC_SHA1 => pbkdf2::pbkdf2_hmac::<Sha1>(pass, salt, rounds, out),
        SQLCIPHER_HMAC_SHA256 => pbkdf2::pbkdf2_hmac::<Sha256>(pass, salt, rounds, out),
        SQLCIPHER_HMAC_SHA512 => pbkdf2::pbkdf2_hmac::<Sha512>(pass, salt, rounds, out),
        _ => return SQLITE_ERROR,
    }
    SQLITE_OK
}

/// AES-256-CBC without padding: SQLCipher always passes whole blocks.
#[allow(clippy::too_many_arguments)] // the C signature
unsafe extern "C" fn cipher(
    _: Ctx,
    mode: c_int,
    key: *const c_uchar,
    key_sz: c_int,
    iv: *const c_uchar,
    input: *const c_uchar,
    in_sz: c_int,
    out: *mut c_uchar,
) -> c_int {
    let (Some(key), Some(iv), Ok(len)) =
        (unsafe { bytes(key, key_sz) }, unsafe { bytes(iv, BLOCK_SZ as c_int) }, usize::try_from(in_sz))
    else {
        return SQLITE_ERROR;
    };
    if len % BLOCK_SZ != 0 || (len > 0 && (input.is_null() || out.is_null())) {
        return SQLITE_ERROR;
    }
    if len == 0 {
        return SQLITE_OK;
    }
    // `input` and `out` may be the same buffer: copy, then work on `out` alone.
    let buf = unsafe {
        ptr::copy(input, out, len);
        slice::from_raw_parts_mut(out, len)
    };
    let (chunks, _) = buf.as_chunks_mut::<BLOCK_SZ>();
    let blocks: &mut [Block<Aes256>] = Array::cast_slice_from_core_mut(chunks);
    if mode == SQLCIPHER_ENCRYPT {
        let Ok(mut enc) = cbc::Encryptor::<Aes256>::new_from_slices(key, iv) else { return SQLITE_ERROR };
        enc.encrypt_blocks(blocks);
    } else {
        let Ok(mut dec) = cbc::Decryptor::<Aes256>::new_from_slices(key, iv) else { return SQLITE_ERROR };
        dec.decrypt_blocks(blocks);
    }
    SQLITE_OK
}

unsafe extern "C" fn get_key_sz(_: Ctx) -> c_int {
    KEY_SZ
}

/// The IV is one AES block, so this also serves `get_iv_sz`.
unsafe extern "C" fn get_block_sz(_: Ctx) -> c_int {
    BLOCK_SZ as c_int
}

unsafe extern "C" fn get_hmac_sz(_: Ctx, algorithm: c_int) -> c_int {
    hmac_sz(algorithm)
}

unsafe extern "C" fn ctx_init(_: *mut Ctx) -> c_int {
    SQLITE_OK
}

unsafe extern "C" fn ctx_free(_: *mut Ctx) -> c_int {
    SQLITE_OK
}

unsafe extern "C" fn fips_status(_: Ctx) -> c_int {
    0
}

/// Called by SQLCipher's `sqlcipher_extra_init` with a provider it allocated.
///
/// # Safety
/// `p` must point to writable memory of `sizeof(sqlcipher_provider)` bytes.
#[no_mangle]
pub unsafe extern "C" fn sqlcipher_custom_crypto_setup(p: *mut SqlcipherProvider) -> c_int {
    if p.is_null() {
        return SQLITE_ERROR;
    }
    unsafe {
        p.write(SqlcipherProvider {
            init: None,
            shutdown: None,
            get_provider_name,
            add_random,
            random,
            hmac,
            kdf,
            cipher,
            get_cipher,
            get_key_sz,
            get_iv_sz: get_block_sz,
            get_block_sz,
            get_hmac_sz,
            ctx_init,
            ctx_free,
            fips_status,
            get_provider_version,
            next: ptr::null_mut(),
        });
    }
    SQLITE_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    // Expected values come from independent implementations: Python's hmac and
    // hashlib, and LibreSSL's `openssl enc -aes-256-cbc -nopad`. PBKDF2-SHA1
    // with 2 rounds also matches RFC 6070.
    const KEY: &[u8] = b"key";
    const IN1: &[u8] = b"The quick brown fox ";
    const IN2: &[u8] = b"jumps over the lazy dog";
    const HMAC_BOTH: &[(c_int, &str)] = &[
        (SQLCIPHER_HMAC_SHA1, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"),
        (SQLCIPHER_HMAC_SHA256, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"),
        (
            SQLCIPHER_HMAC_SHA512,
            "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a",
        ),
    ];
    const HMAC_FIRST_ONLY: &[(c_int, &str)] = &[
        (SQLCIPHER_HMAC_SHA1, "2bf5b11ce66e92922b76d3afe48336445a7ea2e4"),
        (SQLCIPHER_HMAC_SHA256, "f20c67b56ce1a2503c6ab37f2932307fcee1c9e9b786cce7f76d55bdac12a73f"),
        (
            SQLCIPHER_HMAC_SHA512,
            "083dbbc13a8861cae759913f2b2c11d6267d13a3c0517ee6ed4c554219fdb18e681b07c3e1e338a12968de327f11fb769c42a0c5ec27165b0f0e5bd4814a7e18",
        ),
    ];
    // PBKDF2(password = "password", salt = "salt", 2 rounds, 32 bytes)
    const PBKDF2: &[(c_int, &str)] = &[
        (SQLCIPHER_HMAC_SHA1, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957cae93136266537a8d7bf4b76"),
        (SQLCIPHER_HMAC_SHA256, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
        (SQLCIPHER_HMAC_SHA512, "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c"),
    ];
    // AES-256-CBC, key 00..1f, IV 20..2f, plaintext 00..3f.
    const CBC_CIPHERTEXT: &str = "72d75c294159fac28a43f67c6e07ee4b9c6dcff1fb62d285ff59864ad9cf9411\
                                  9e175a14ca7d64d50979f9e08382257c6548205713ea4eaa5377a028b7c27537";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn len(bytes: &[u8]) -> c_int {
        bytes.len() as c_int
    }

    fn run_hmac(algorithm: c_int, in1: *const u8, in2: Option<&[u8]>) -> Option<String> {
        let mut out = vec![0u8; hmac_sz(algorithm) as usize];
        let (in2, in2_sz) = in2.map_or((ptr::null(), 0), |b| (b.as_ptr(), len(b)));
        let rc = unsafe { hmac(ptr::null_mut(), algorithm, KEY.as_ptr(), len(KEY), in1, len(IN1), in2, in2_sz, out.as_mut_ptr()) };
        (rc == SQLITE_OK).then(|| hex(&out))
    }

    fn run_kdf(algorithm: c_int, rounds: c_int) -> Option<String> {
        let mut key = [0u8; 32];
        let (pass, salt) = (b"password", b"salt");
        let rc = unsafe {
            kdf(ptr::null_mut(), algorithm, pass.as_ptr(), len(pass), salt.as_ptr(), len(salt), rounds, len(&key), key.as_mut_ptr())
        };
        (rc == SQLITE_OK).then(|| hex(&key))
    }

    fn run_cipher(mode: c_int, input: *const u8, in_sz: c_int, out: *mut u8) -> c_int {
        let key: Vec<u8> = (0..32).collect();
        let iv: Vec<u8> = (0x20..0x30).collect();
        unsafe { cipher(ptr::null_mut(), mode, key.as_ptr(), len(&key), iv.as_ptr(), input, in_sz, out) }
    }

    #[test]
    fn hmac_covers_both_inputs() {
        for &(algorithm, expected) in HMAC_BOTH {
            assert_eq!(run_hmac(algorithm, IN1.as_ptr(), Some(IN2)).as_deref(), Some(expected), "algorithm {algorithm}");
        }
    }

    #[test]
    fn hmac_second_input_is_optional() {
        for &(algorithm, expected) in HMAC_FIRST_ONLY {
            assert_eq!(run_hmac(algorithm, IN1.as_ptr(), None).as_deref(), Some(expected), "algorithm {algorithm}");
        }
    }

    #[test]
    fn hmac_needs_the_first_input_and_a_known_algorithm() {
        assert_eq!(run_hmac(SQLCIPHER_HMAC_SHA512, ptr::null(), Some(IN2)), None);
        assert_eq!(run_hmac(3, IN1.as_ptr(), Some(IN2)), None);
        assert_eq!(unsafe { get_hmac_sz(ptr::null_mut(), 3) }, 0);
    }

    #[test]
    fn kdf_matches_reference() {
        for &(algorithm, expected) in PBKDF2 {
            assert_eq!(run_kdf(algorithm, 2).as_deref(), Some(expected), "algorithm {algorithm}");
        }
    }

    #[test]
    fn kdf_rejects_zero_rounds_and_unknown_algorithms() {
        assert_eq!(run_kdf(SQLCIPHER_HMAC_SHA512, 0), None);
        assert_eq!(run_kdf(SQLCIPHER_HMAC_SHA512, -1), None);
        assert_eq!(run_kdf(3, 2), None);
    }

    #[test]
    fn cipher_matches_reference_and_decrypts_in_place() {
        let plaintext: Vec<u8> = (0..64).collect();
        let mut buf = vec![0u8; 64];
        assert_eq!(run_cipher(SQLCIPHER_ENCRYPT, plaintext.as_ptr(), 64, buf.as_mut_ptr()), SQLITE_OK);
        assert_eq!(hex(&buf), CBC_CIPHERTEXT);
        // SQLCipher may pass one buffer as both input and output.
        let p = buf.as_mut_ptr();
        assert_eq!(run_cipher(0, p, 64, p), SQLITE_OK);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn cipher_rejects_partial_blocks_and_null_buffers() {
        let mut buf = [0u8; 32];
        let p = buf.as_mut_ptr();
        assert_eq!(run_cipher(SQLCIPHER_ENCRYPT, p, 15, p), SQLITE_ERROR);
        assert_eq!(run_cipher(SQLCIPHER_ENCRYPT, p, -16, p), SQLITE_ERROR);
        assert_eq!(run_cipher(SQLCIPHER_ENCRYPT, ptr::null(), 16, p), SQLITE_ERROR);
        assert_eq!(run_cipher(SQLCIPHER_ENCRYPT, p, 16, ptr::null_mut()), SQLITE_ERROR);
    }

    #[test]
    fn random_fills_the_buffer() {
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        assert_eq!(unsafe { random(ptr::null_mut(), a.as_mut_ptr().cast(), 64) }, SQLITE_OK);
        assert_eq!(unsafe { random(ptr::null_mut(), b.as_mut_ptr().cast(), 64) }, SQLITE_OK);
        assert_ne!(a, [0u8; 64]);
        assert_ne!(a, b);
        assert_eq!(unsafe { random(ptr::null_mut(), ptr::null_mut(), 16) }, SQLITE_ERROR);
    }

    #[test]
    fn setup_installs_every_entry_point() {
        let mut p = MaybeUninit::<SqlcipherProvider>::uninit();
        assert_eq!(unsafe { sqlcipher_custom_crypto_setup(p.as_mut_ptr()) }, SQLITE_OK);
        let p = unsafe { p.assume_init() };
        let name = unsafe { CStr::from_ptr((p.get_provider_name)(ptr::null_mut())) };
        assert_eq!(name, PROVIDER_NAME);
        assert_eq!(unsafe { CStr::from_ptr((p.get_cipher)(ptr::null_mut())) }, CIPHER_NAME);
        assert_eq!(unsafe { ((p.get_key_sz)(ptr::null_mut()), (p.get_iv_sz)(ptr::null_mut())) }, (32, 16));
        assert_eq!(unsafe { (p.get_hmac_sz)(ptr::null_mut(), SQLCIPHER_HMAC_SHA512) }, 64);
        assert!(p.init.is_none() && p.shutdown.is_none() && p.next.is_null());
        assert_eq!(unsafe { sqlcipher_custom_crypto_setup(ptr::null_mut()) }, SQLITE_ERROR);
    }
}
