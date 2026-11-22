//! Platform backends: the concrete [`Decryptor`](crate::decryptor::Decryptor)
//! strategies, one per operating system (the *adapters* behind the abstraction).
//!
//! Exactly one submodule is compiled per target. This module selects it by
//! `cfg` and re-exports its two entry points — `build` (the constructor) and
//! `default_config_path` — so the rest of the crate depends only on
//! `platform::…`, never on a specific OS module.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{build, default_config_path};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{build, default_config_path};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{build, default_config_path};
