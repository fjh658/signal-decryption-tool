//! Errors a user can act on: each one names the file and what to do about it.
//!
//! They travel inside the crate-wide boxed [`crate::Result`], so callers that
//! only print errors are unaffected, and tests can still match on the kind.

use std::fmt;
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub enum Error {
    /// A file that Signal creates on its first launch does not exist yet.
    Missing { what: &'static str, path: PathBuf, hint: &'static str },
    /// A file exists but could not be read.
    Io { path: PathBuf, source: io::Error },
    /// A file was read but its content is not what Signal writes.
    Invalid { path: PathBuf, reason: String },
}

impl Error {
    /// Maps an I/O error on `path`: "not found" becomes [`Error::Missing`].
    pub fn from_io(source: io::Error, what: &'static str, path: impl Into<PathBuf>, hint: &'static str) -> Self {
        let path = path.into();
        if source.kind() == io::ErrorKind::NotFound {
            Error::Missing { what, path, hint }
        } else {
            Error::Io { path, source }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Missing { what, path, hint } => write!(f, "{what} not found at {}: {hint}", path.display()),
            Error::Io { path, source } => write!(f, "cannot read {}: {source}", path.display()),
            Error::Invalid { path, reason } => write!(f, "{}: {reason}", path.display()),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}
