//! Paths for raw Win32 calls.
//!
//! `std::fs` already lifts MAX_PATH by itself. A raw `CreateFileW` call does
//! not: without long-path opt-in it fails beyond 259 characters. Every raw
//! call therefore takes its path from [`to_wide`], which makes it absolute (as
//! `GetFullPathNameW` would) and puts it in `\\?\` form.

/// The `\\?\` form of an absolute Windows path. Device and verbatim paths are
/// returned as they are; `\\server\share\...` becomes `\\?\UNC\server\share\...`.
pub fn verbatim(absolute: &str) -> String {
    if absolute.starts_with(r"\\?\") || absolute.starts_with(r"\\.\") {
        absolute.to_string()
    } else if let Some(unc) = absolute.strip_prefix(r"\\") {
        format!(r"\\?\UNC\{unc}")
    } else {
        format!(r"\\?\{absolute}")
    }
}

/// A NUL-terminated UTF-16 verbatim path for a raw Win32 call. A path with an
/// interior NUL is refused, since Win32 would silently cut it there.
#[cfg(windows)]
pub fn to_wide(path: &str) -> std::io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    if path.contains('\0') {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL character"));
    }
    let absolute = std::path::absolute(path)?;
    let absolute = absolute.to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path is not valid Unicode")
    })?;
    Ok(std::ffi::OsStr::new(&verbatim(absolute)).encode_wide().chain(Some(0)).collect())
}

#[cfg(test)]
mod tests {
    use super::verbatim;

    #[test]
    fn verbatim_forms() {
        assert_eq!(verbatim(r"C:\Users\me\export.sqlite"), r"\\?\C:\Users\me\export.sqlite");
        assert_eq!(verbatim(r"\\server\share\export.sqlite"), r"\\?\UNC\server\share\export.sqlite");
        assert_eq!(verbatim(r"\\?\C:\already"), r"\\?\C:\already");
        assert_eq!(verbatim(r"\\.\NUL"), r"\\.\NUL");
    }
}
